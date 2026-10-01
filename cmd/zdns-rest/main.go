package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/zmap/dns"
	_ "github.com/zmap/zdns/v2/src/modules/alookup"
	_ "github.com/zmap/zdns/v2/src/modules/axfr"
	_ "github.com/zmap/zdns/v2/src/modules/bindversion"
	_ "github.com/zmap/zdns/v2/src/modules/dmarc"
	_ "github.com/zmap/zdns/v2/src/modules/mxlookup"
	_ "github.com/zmap/zdns/v2/src/modules/nslookup"
	_ "github.com/zmap/zdns/v2/src/modules/spf"
	"github.com/zmap/zdns/v2/src/zdns"
)

// GlobalConf holds the server configuration. It used to embed
// zdns.GlobalConf (v1); after the v2 migration the zdns-facing fields are
// declared here directly and translated into a zdns.ResolverConfig by
// buildResolverConfig.
type GlobalConf struct {
	ApiPort int
	ApiIP   string

	// Lookup behavior (previously zdns.GlobalConf fields)
	Threads              int
	GoMaxProcs           int
	NamePrefix           string
	NameOverride         string
	IterativeResolution  bool
	LookupAllNameServers bool
	LogFilePath          string
	ResultVerbosity      string
	IncludeInOutput      string
	Verbosity            int
	Retries              int
	MaxDepth             int
	CacheSize            int
	TCPOnly              bool
	UDPOnly              bool
	RecycleSockets       bool
	Timeout              time.Duration
	IterationTimeout     time.Duration
	NetworkTimeout       time.Duration
	TimeFormat           string
	Class                uint16
	NameServers          []string
	NameServersSpecified bool
	LocalAddrs           []net.IP
	LocalAddrSpecified   bool
	OutputGroups         []string
	OutputFormat         string // "v1" flat envelope or "v2" upstream-style envelope

	// Module flags (previously passed through factory.SetFlags)
	IPv4Lookup    bool
	IPv6Lookup    bool
	BlacklistFile string
	MXCacheSize   int // deprecated: no v2 equivalent, accepted for config compat

	// Rate limiting and validation
	RateLimitEnabled   bool
	RateLimitRequests  int
	RateLimitWindow    int // seconds
	MaxQueriesPerReq   int
	MaxRequestBodySize int64 // bytes

	// Security
	TLSEnabled     bool
	TLSCertFile    string
	TLSKeyFile     string
	TLSAutoHTTP    bool
	APIKey         string
	TrustedProxies string // comma-separated CIDRs whose X-Forwarded-For headers are trusted

	// CORS
	CORSOrigins string
	CORSMethods string
	CORSHeaders string

	// Operations
	EnablePprof            bool
	PprofPort              int
	RequestTimeout         int // seconds
	CircuitBreakerEnabled  bool
	CircuitBreakerFailures int
	CircuitBreakerTimeout  int // seconds

	// Cache
	CacheEnabled  bool
	CacheTTL      int // seconds
	CacheMaxSize  int
	CacheStaleTTL int // seconds
}

type ArgumentsConf struct {
	Servers_string   string
	Localaddr_string string
	Localif_string   string
	Config_file      string
	Timeout          int
	IterationTimeout int
	NetworkTimeout   int
	Class_string     string
	NanoSeconds      bool
}

var cfgFile string
var GC GlobalConf
var AC ArgumentsConf

// GCMu guards access to the global configuration GC. prepareConfig takes the
// write lock; request handlers take the read lock so GC is never read while
// it is being reconfigured.
var GCMu sync.RWMutex

const EnvPrefix = "ZDNS"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "server",
	Short:   "High-speed, low-drag DNS lookups",
	Version: buildVersion,
	Long: `ZDNS is a library and CLI tool for making very fast DNS requests. It's built upon
https://github.com/zmap/dns (and in turn https://github.com/miekg/dns) for constructing
and parsing raw DNS packets.

ZDNS also includes its own recursive resolution and a cache to further optimize performance.`,
	Run: func(cmd *cobra.Command, args []string) {
		prepareConfig()
		startServer()
	},
}

func prepareConfig() {
	GCMu.Lock()
	defer GCMu.Unlock()

	if GC.LogFilePath != "" {
		f, err := os.OpenFile(GC.LogFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			//nolint:gocritic // exits the process; deferred GCMu.Unlock is moot
			log.Fatalf("Unable to open log file (%s): %s", GC.LogFilePath, err.Error())
		}
		log.SetOutput(f)
	}

	// Translate the assigned verbosity level to a logrus log level.
	switch GC.Verbosity {
	case 1: // Fatal
		log.SetLevel(log.FatalLevel)
	case 2: // Error
		log.SetLevel(log.ErrorLevel)
	case 3: // Warnings  (default)
		log.SetLevel(log.WarnLevel)
	case 4: // Information
		log.SetLevel(log.InfoLevel)
	case 5: // Debugging
		log.SetLevel(log.DebugLevel)
	default:
		log.Fatal("Unknown verbosity level specified. Must be between 1 (lowest)--5 (highest)")
	}

	// complete post facto global initialization based on command line arguments
	GC.Timeout = time.Second * time.Duration(AC.Timeout)
	GC.IterationTimeout = time.Second * time.Duration(AC.IterationTimeout)
	GC.NetworkTimeout = time.Second * time.Duration(AC.NetworkTimeout)

	if GC.OutputFormat == "" {
		GC.OutputFormat = "v2"
	}
	switch GC.OutputFormat {
	case "v1", "v2":
	default:
		log.Fatal("Invalid argument for --output-format. Must be 'v1' or 'v2'.")
	}
	if GC.MXCacheSize != 1000 {
		log.Warn("--mx-cache-size has no equivalent in zdns v2 and is ignored")
	}

	// class initialization
	switch strings.ToUpper(AC.Class_string) {
	case "INET", "IN":
		GC.Class = dns.ClassINET
	case "CSNET", "CS":
		GC.Class = dns.ClassCSNET
	case "CHAOS", "CH":
		GC.Class = dns.ClassCHAOS
	case "HESIOD", "HS":
		GC.Class = dns.ClassHESIOD
	case "NONE":
		GC.Class = dns.ClassNONE
	case "ANY":
		GC.Class = dns.ClassANY
	default:
		log.Fatal("Unknown record class specified. Valid valued are INET (default), CSNET, CHAOS, HESIOD, NONE, ANY")
	}

	if GC.LookupAllNameServers {
		if AC.Servers_string != "" {
			log.Fatal("Name servers cannot be specified in --all-nameservers mode.")
		}
	}

	// prepareConfig may run more than once in-process; reset before appends
	// so repeated calls don't accumulate duplicate nameservers.
	GC.NameServers = nil
	GC.NameServersSpecified = false

	if AC.Servers_string == "" {
		// if we're doing recursive resolution, figure out default OS name servers
		// otherwise, use the set of root name servers
		if GC.IterativeResolution {
			for _, ns := range zdns.RootServersV4 {
				GC.NameServers = append(GC.NameServers, ns.String())
			}
			for _, ns := range zdns.RootServersV6 {
				GC.NameServers = append(GC.NameServers, ns.String())
			}
		} else {
			v4ns, v6ns, err := zdns.GetDNSServers(AC.Config_file)
			ns := slices.Concat(v4ns, v6ns)
			if err != nil || len(ns) == 0 {
				ns = GetDefaultResolvers()
				log.Warn("Unable to parse resolvers file. Using ZDNS defaults: ", strings.Join(ns, ", "))
			}
			GC.NameServers = ns
		}
		GC.NameServersSpecified = false
		log.Info("No name servers specified. will use: ", strings.Join(GC.NameServers, ", "))
	} else {
		var ns []string
		if (AC.Servers_string)[0] == '@' {
			filepath := (AC.Servers_string)[1:]
			f, err := os.ReadFile(filepath)
			if err != nil {
				log.Fatalf("Unable to read file (%s): %s", filepath, err.Error())
			}
			if len(f) == 0 {
				log.Fatalf("Empty file (%s)", filepath)
			}
			ns = strings.Split(strings.Trim(string(f), "\n"), "\n")
		} else {
			ns = strings.Split(AC.Servers_string, ",")
		}
		for i, s := range ns {
			ns[i] = AddDefaultPortToDNSServerName(s)
		}
		GC.NameServers = ns
		GC.NameServersSpecified = true
	}

	// prepareConfig may run more than once in-process; reset before appends
	// so repeated calls don't accumulate duplicate addresses.
	GC.LocalAddrs = nil
	GC.LocalAddrSpecified = false

	if AC.Localaddr_string != "" {
		for _, la := range strings.Split(AC.Localaddr_string, ",") {
			ip := net.ParseIP(la)
			if ip != nil {
				GC.LocalAddrs = append(GC.LocalAddrs, ip)
			} else {
				log.Fatal("Invalid argument for --local-addr (", la, "). Must be a comma-separated list of valid IP addresses.")
			}
		}
		log.Info("using local address: ", AC.Localaddr_string)
		GC.LocalAddrSpecified = true
	}

	if AC.Localif_string != "" {
		if GC.LocalAddrSpecified {
			log.Fatal("Both --local-addr and --local-interface specified.")
		} else {
			li, err := net.InterfaceByName(AC.Localif_string)
			if err != nil {
				log.Fatal("Invalid local interface specified: ", err)
			}
			addrs, err := li.Addrs()
			if err != nil {
				log.Fatal("Unable to detect addresses of local interface: ", err)
			}
			for _, la := range addrs {
				if ipnet, ok := la.(*net.IPNet); ok {
					GC.LocalAddrs = append(GC.LocalAddrs, ipnet.IP)
					GC.LocalAddrSpecified = true
				}
			}
			log.Info("using local interface: ", AC.Localif_string)
		}
	}
	// No auto-detected local address: with LocalAddrs empty, zdns v2 selects
	// the correct source address per nameserver at resolver init, which
	// handles loopback stub resolvers (e.g. 127.0.0.53) that a single
	// WAN-facing probe address could not reach.
	if AC.NanoSeconds {
		GC.TimeFormat = time.RFC3339Nano
	} else {
		GC.TimeFormat = time.RFC3339
	}
	if GC.GoMaxProcs < 0 {
		log.Fatal("Invalid argument for --go-processes. Must be >= 0.")
	}
	if GC.GoMaxProcs != 0 {
		runtime.GOMAXPROCS(GC.GoMaxProcs)
	}
	if GC.UDPOnly && GC.TCPOnly {
		log.Fatal("TCP Only and UDP Only are conflicting")
	}
	if GC.TLSAutoHTTP {
		log.Warn("--tls-auto-http is not implemented; no HTTP->HTTPS redirect listener will be started")
	}
	// Output Groups are defined by a base + any additional fields that the user wants
	groups := splitAndTrim(GC.IncludeInOutput, ",")
	if GC.ResultVerbosity != "short" && GC.ResultVerbosity != "normal" && GC.ResultVerbosity != "long" && GC.ResultVerbosity != "trace" {
		log.Fatal("Invalid result verbosity. Options: short, normal, long, trace")
	}

	// Reset rather than append — prepareConfig may run more than once
	// in-process (tests, reconfiguration) and must be idempotent.
	GC.OutputGroups = append([]string{GC.ResultVerbosity}, groups...)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

// init sets up the default logging format and sets up the viper configuration reader.
// It also sets up the root command and its flags.
func init() {
	log.SetFormatter(&log.TextFormatter{})

	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/zdns-rest/zdns-rest.conf, $HOME/.zdns.yaml). Supports .conf/.env (key=value) and .yaml formats")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().IntVar(&GC.Threads, "threads", 1000, "number of lightweight go threads")
	rootCmd.PersistentFlags().IntVar(&GC.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	rootCmd.PersistentFlags().StringVar(&GC.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	rootCmd.PersistentFlags().StringVar(&GC.NameOverride, "override-name", "", "name overrides all passed in names")
	rootCmd.PersistentFlags().BoolVar(&GC.IterativeResolution, "iterative", false, "Perform own iteration instead of relying on recursive resolver")
	rootCmd.PersistentFlags().BoolVar(&GC.LookupAllNameServers, "all-nameservers", false, "Perform the lookup via all the nameservers for the domain.")
	rootCmd.PersistentFlags().StringVar(&GC.LogFilePath, "log-file", "", "where should JSON logs be saved")

	rootCmd.PersistentFlags().StringVar(&GC.ResultVerbosity, "result-verbosity", "normal", "Sets verbosity of each output record. Options: short, normal, long, trace")
	rootCmd.PersistentFlags().StringVar(&GC.IncludeInOutput, "include-fields", "", "Comma separated list of fields to additionally output beyond result verbosity. Options: class, protocol, ttl, resolver, flags")

	rootCmd.PersistentFlags().IntVar(&GC.ApiPort, "bind-port", 8080, "port to bind API to")
	rootCmd.PersistentFlags().StringVar(&GC.ApiIP, "bind-ip", "", "ip to bind API to")

	// Rate limiting and validation flags
	rootCmd.PersistentFlags().BoolVar(&GC.RateLimitEnabled, "rate-limit", true, "enable rate limiting")
	rootCmd.PersistentFlags().IntVar(&GC.RateLimitRequests, "rate-limit-requests", 100, "max requests per window per IP")
	rootCmd.PersistentFlags().IntVar(&GC.RateLimitWindow, "rate-limit-window", 60, "rate limit window in seconds")
	rootCmd.PersistentFlags().IntVar(&GC.MaxQueriesPerReq, "max-queries", 1000, "max queries per request")
	rootCmd.PersistentFlags().Int64Var(&GC.MaxRequestBodySize, "max-body-size", 10*1024*1024, "max request body size in bytes (default 10MB)")

	// TLS flags
	rootCmd.PersistentFlags().BoolVar(&GC.TLSEnabled, "tls", false, "enable TLS/HTTPS")
	rootCmd.PersistentFlags().StringVar(&GC.TLSCertFile, "tls-cert", "", "TLS certificate file")
	rootCmd.PersistentFlags().StringVar(&GC.TLSKeyFile, "tls-key", "", "TLS key file")
	rootCmd.PersistentFlags().BoolVar(&GC.TLSAutoHTTP, "tls-auto-http", false, "redirect HTTP to HTTPS when TLS is enabled")

	// API Key authentication
	rootCmd.PersistentFlags().StringVar(&GC.APIKey, "api-key", "", "API key for authentication (empty=disabled)")

	// Proxy trust
	rootCmd.PersistentFlags().StringVar(&GC.TrustedProxies, "trusted-proxies", "", "comma-separated IPs/CIDRs allowed to set X-Forwarded-For/X-Real-IP (empty=trust direct peer only)")

	// CORS flags
	rootCmd.PersistentFlags().StringVar(&GC.CORSOrigins, "cors-origins", "", "allowed CORS origins (comma-separated, empty=CORS disabled)")
	rootCmd.PersistentFlags().StringVar(&GC.CORSMethods, "cors-methods", "GET,POST", "allowed CORS methods")
	rootCmd.PersistentFlags().StringVar(&GC.CORSHeaders, "cors-headers", "", "additional allowed CORS headers (comma-separated)")

	// pprof flags
	rootCmd.PersistentFlags().BoolVar(&GC.EnablePprof, "enable-pprof", false, "enable pprof profiling endpoints")
	rootCmd.PersistentFlags().IntVar(&GC.PprofPort, "pprof-port", 6060, "port for pprof endpoints")

	// Request timeout
	rootCmd.PersistentFlags().IntVar(&GC.RequestTimeout, "request-timeout", 30, "HTTP request timeout in seconds")

	// Circuit breaker flags
	rootCmd.PersistentFlags().BoolVar(&GC.CircuitBreakerEnabled, "circuit-breaker", false, "enable circuit breaker for DNS lookups")
	rootCmd.PersistentFlags().IntVar(&GC.CircuitBreakerFailures, "circuit-breaker-failures", 5, "circuit breaker failure threshold")
	rootCmd.PersistentFlags().IntVar(&GC.CircuitBreakerTimeout, "circuit-breaker-timeout", 60, "circuit breaker timeout in seconds")

	// Cache flags
	rootCmd.PersistentFlags().BoolVar(&GC.CacheEnabled, "cache-enabled", true, "enable in-memory DNS result cache")
	rootCmd.PersistentFlags().IntVar(&GC.CacheTTL, "cache-ttl", 300, "cache TTL in seconds (default 5 minutes)")
	rootCmd.PersistentFlags().IntVar(&GC.CacheMaxSize, "cache-max-size", 10000, "maximum number of items in cache")
	rootCmd.PersistentFlags().IntVar(&GC.CacheStaleTTL, "cache-stale-ttl", 150, "stale TTL in seconds (default 2.5 minutes)")

	rootCmd.PersistentFlags().IntVar(&GC.Verbosity, "verbosity", 4, "log verbosity: 1 (lowest)--5 (highest)")
	rootCmd.PersistentFlags().IntVar(&GC.Retries, "retries", 1, "how many times should zdns retry query if timeout or temporary failure")
	rootCmd.PersistentFlags().IntVar(&GC.MaxDepth, "max-depth", 10, "how deep should we recurse when performing iterative lookups")
	rootCmd.PersistentFlags().IntVar(&GC.CacheSize, "cache-size", 10000, "how many items can be stored in internal recursive cache")
	rootCmd.PersistentFlags().BoolVar(&GC.TCPOnly, "tcp-only", false, "Only perform lookups over TCP")
	rootCmd.PersistentFlags().BoolVar(&GC.UDPOnly, "udp-only", false, "Only perform lookups over UDP")
	rootCmd.PersistentFlags().BoolVar(&GC.RecycleSockets, "recycle-sockets", true, "Create long-lived unbound UDP socket for each thread at launch and reuse for all (UDP) queries")

	rootCmd.PersistentFlags().StringVar(&AC.Servers_string, "name-servers", "", "List of DNS servers to use. Can be passed as comma-delimited string or via @/path/to/file. If no port is specified, defaults to 53.")
	rootCmd.PersistentFlags().StringVar(&AC.Localaddr_string, "local-addr", "", "comma-delimited list of local addresses to use")
	rootCmd.PersistentFlags().StringVar(&AC.Localif_string, "local-interface", "", "local interface to use")
	rootCmd.PersistentFlags().StringVar(&AC.Config_file, "conf-file", "/etc/resolv.conf", "config file for DNS servers")
	rootCmd.PersistentFlags().IntVar(&AC.Timeout, "timeout", 15, "timeout for resolving an individual name")
	rootCmd.PersistentFlags().IntVar(&AC.IterationTimeout, "iteration-timeout", 4, "timeout for resolving a single iteration in an iterative query")
	rootCmd.PersistentFlags().StringVar(&AC.Class_string, "class", "INET", "DNS class to query. Options: INET, CSNET, CHAOS, HESIOD, NONE, ANY. Default: INET.")
	rootCmd.PersistentFlags().BoolVar(&AC.NanoSeconds, "nanoseconds", false, "Use nanosecond resolution timestamps")

	rootCmd.PersistentFlags().BoolVar(&GC.IPv4Lookup, "ipv4-lookup", false, "Perform an IPv4 Lookup in modules")
	rootCmd.PersistentFlags().BoolVar(&GC.IPv6Lookup, "ipv6-lookup", false, "Perform an IPv6 Lookup in modules")
	rootCmd.PersistentFlags().StringVar(&GC.BlacklistFile, "blacklist-file", "", "blacklist file for servers to exclude from lookups (AXFR module)")
	rootCmd.PersistentFlags().IntVar(&GC.MXCacheSize, "mx-cache-size", 1000, "deprecated: no effect with zdns v2")
	rootCmd.PersistentFlags().StringVar(&GC.OutputFormat, "output-format", "v2", "result envelope format: 'v2' (upstream zdns v2, default) or 'v1' (legacy flat)")
	rootCmd.PersistentFlags().IntVar(&AC.NetworkTimeout, "network-timeout", 2, "timeout for round trip network operations, in seconds")
}

// Reference: https://github.com/carolynvs/stingoftheviper/blob/main/main.go
// For how to make cobra/viper sync up, and still use custom struct
// Bind each cobra flag to its associated viper configuration (config file and environment variable)
func BindFlags(cmd *cobra.Command, v *viper.Viper, envPrefix string) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --alexa to ZDNS_ALEXA. Apply to every flag —
		// single-word flags (--threads -> ZDNS_THREADS) need binding too.
		envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		_ = v.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix))

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			switch val := v.Get(f.Name).(type) {
			case []interface{}:
				// YAML lists (e.g. name-servers: [8.8.8.8, 1.1.1.1]) must be
				// joined — fmt "%v" would produce "[8.8.8.8 1.1.1.1]".
				strs := make([]string, len(val))
				for i, e := range val {
					strs[i] = fmt.Sprintf("%v", e)
				}
				_ = cmd.Flags().Set(f.Name, strings.Join(strs, ","))
			default:
				_ = cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			}
		}
	})
}

// loadKeyValueConfig reads a simple key=value config file and loads into viper
func loadKeyValueConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split on first =
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		viper.Set(key, value)
	}
	return nil
}

// initConfig reads in config file and ENV variables if set.
// Supports YAML (.yaml, .yml) and key=value (.conf, .env) formats.
func initConfig() {
	isKeyValueFormat := false
	configFile := cfgFile

	if configFile != "" {
		// Use config file from the flag.
		// Auto-detect config type based on extension
		if strings.HasSuffix(configFile, ".conf") || strings.HasSuffix(configFile, ".env") {
			isKeyValueFormat = true
		}
	} else {
		// Check for system-wide config first
		sysConfig := "/etc/zdns-rest/zdns-rest.conf"
		if _, err := os.Stat(sysConfig); err == nil {
			configFile = sysConfig
			isKeyValueFormat = true
		} else {
			// Find home directory for YAML config.
			home, err := os.UserHomeDir()
			cobra.CheckErr(err)
			viper.AddConfigPath(home)
			viper.SetConfigType("yaml")
			viper.SetConfigName(".zdns")
		}
	}

	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()

	// Load config file if specified or found
	if configFile != "" {
		if isKeyValueFormat {
			if err := loadKeyValueConfig(configFile); err == nil {
				fmt.Fprintln(os.Stderr, "Using config file:", configFile)
			} else {
				log.Warnf("Unable to load config file %s: %s", configFile, err)
			}
		} else {
			viper.SetConfigFile(configFile)
			if err := viper.ReadInConfig(); err == nil {
				fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
			} else {
				log.Warnf("Unable to load config file %s: %s", configFile, err)
			}
		}
	} else {
		// Try viper's default search path
		if err := viper.ReadInConfig(); err == nil {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}

	// Bind the current command's flags to viper
	BindFlags(rootCmd, viper.GetViper(), EnvPrefix)
}

// getDefaultResolvers returns a slice of default DNS resolvers to be used when no system resolvers could be discovered.
func GetDefaultResolvers() []string {
	return []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}
}

// AddDefaultPortToDNSServerName adds a default port of 53 to the given DNS server name.
// If the DNS server name is an IPv6 address, it will be enclosed in square brackets.
func AddDefaultPortToDNSServerName(s string) string {
	if _, port, err := net.SplitHostPort(s); err == nil {
		if port != "" {
			return s // already includes a port (host:port or [v6]:port)
		}
		// "host:" or "[v6]:" with an empty port: strip the separator
		return strings.TrimSuffix(s, ":") + ":53"
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s + ":53" // bracketed IPv6 literal without port
	}
	if ip := net.ParseIP(s); ip != nil && strings.Contains(s, ":") {
		return "[" + s + "]:53" // bare IPv6 literal without port
	}
	return s + ":53"
}
