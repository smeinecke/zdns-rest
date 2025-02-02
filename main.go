package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/zmap/dns"
	_ "github.com/zmap/zdns/pkg/alookup"
	_ "github.com/zmap/zdns/pkg/axfr"
	_ "github.com/zmap/zdns/pkg/bindversion"
	_ "github.com/zmap/zdns/pkg/dmarc"
	_ "github.com/zmap/zdns/pkg/mxlookup"
	_ "github.com/zmap/zdns/pkg/nslookup"
	_ "github.com/zmap/zdns/pkg/spf"
	"github.com/zmap/zdns/pkg/zdns"
)

type GlobalConf struct {
	zdns.GlobalConf

	Flags   *pflag.FlagSet
	ApiPort int
	ApiIP   string
}

type ArgumentsConf struct {
	Servers_string   string
	Localaddr_string string
	Localif_string   string
	Config_file      string
	Timeout          int
	IterationTimeout int
	Class_string     string
	NanoSeconds      bool
}

var cfgFile string
var GC GlobalConf
var AC ArgumentsConf

var rePort *regexp.Regexp
var reV6 *regexp.Regexp

const EnvPrefix = "ZDNS"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "server",
	Short: "High-speed, low-drag DNS lookups",
	Long: `ZDNS is a library and CLI tool for making very fast DNS requests. It's built upon
https://github.com/zmap/dns (and in turn https://github.com/miekg/dns) for constructing
and parsing raw DNS packets.

ZDNS also includes its own recursive resolution and a cache to further optimize performance.`,
	Run: func(cmd *cobra.Command, args []string) {
		GC.Flags = cmd.Flags()
		prepareConfig()
		startServer()
	},
}

func prepareConfig() {
	if GC.LogFilePath != "" {
		f, err := os.OpenFile(GC.LogFilePath, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
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
	GC.Timeout = time.Duration(time.Second * time.Duration(AC.Timeout))
	GC.IterationTimeout = time.Duration(time.Second * time.Duration(AC.IterationTimeout))

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

	if AC.Servers_string == "" {
		// if we're doing recursive resolution, figure out default OS name servers
		// otherwise, use the set of 13 root name servers
		if GC.IterativeResolution {
			GC.NameServers = zdns.RootServers[:]
		} else {
			ns, err := zdns.GetDNSServers(AC.Config_file)
			if err != nil {
				ns = GetDefaultResolvers()
				log.Warn("Unable to parse resolvers file. Using ZDNS defaults: ", strings.Join(ns, ", "))
			}
			GC.NameServers = ns
		}
		GC.NameServersSpecified = false
		log.Info("No name servers specified. will use: ", strings.Join(GC.NameServers, ", "))
	} else {
		if GC.NameServerMode {
			log.Fatal("name servers cannot be specified on command line in --name-server-mode")
		}
		var ns []string
		if (AC.Servers_string)[0] == '@' {
			filepath := (AC.Servers_string)[1:]
			f, err := ioutil.ReadFile(filepath)
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
				GC.LocalAddrs = append(GC.LocalAddrs, la.(*net.IPNet).IP)
				GC.LocalAddrSpecified = true
			}
			log.Info("using local interface: ", AC.Localif_string)
		}
	}
	if !GC.LocalAddrSpecified {
		// Find local address for use in unbound UDP sockets
		if conn, err := net.Dial("udp", "8.8.8.8:53"); err != nil {
			log.Fatal("Unable to find default IP address: ", err)
		} else {
			GC.LocalAddrs = append(GC.LocalAddrs, conn.LocalAddr().(*net.UDPAddr).IP)
		}
	}
	if AC.NanoSeconds {
		GC.TimeFormat = time.RFC3339Nano
	} else {
		GC.TimeFormat = time.RFC3339
	}
	if GC.GoMaxProcs < 0 {
		log.Fatal("Invalid argument for --go-processes. Must be >1.")
	}
	if GC.GoMaxProcs != 0 {
		runtime.GOMAXPROCS(GC.GoMaxProcs)
	}
	if GC.UDPOnly && GC.TCPOnly {
		log.Fatal("TCP Only and UDP Only are conflicting")
	}
	if GC.NameServerMode && GC.AlexaFormat {
		log.Fatal("Alexa mode is incompatible with name server mode")
	}
	if GC.NameServerMode && GC.MetadataFormat {
		log.Fatal("Metadata mode is incompatible with name server mode")
	}
	if GC.NameServerMode && GC.NameOverride == "" && GC.Module != "BINDVERSION" {
		log.Fatal("Static Name must be defined with --override-name in --name-server-mode unless DNS module does not expect names (e.g., BINDVERSION).")
	}
	// Output Groups are defined by a base + any additional fields that the user wants
	groups := strings.Split(GC.IncludeInOutput, ",")
	if GC.ResultVerbosity != "short" && GC.ResultVerbosity != "normal" && GC.ResultVerbosity != "long" && GC.ResultVerbosity != "trace" {
		log.Fatal("Invalid result verbosity. Options: short, normal, long, trace")
	}

	// set defaults
	GC.InputFilePath = "-"
	GC.OutputFilePath = "-"
	GC.AlexaFormat = false

	GC.OutputGroups = append(GC.OutputGroups, GC.ResultVerbosity)
	GC.OutputGroups = append(GC.OutputGroups, groups...)

	// Seeding for RandomNameServer()
	rand.Seed(time.Now().UnixNano())
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rePort = regexp.MustCompile(":\\d+$")      // string ends with potential port number
	reV6 = regexp.MustCompile("^([0-9a-f]*:)") // string starts like valid IPv6 address
	log.SetFormatter(&log.TextFormatter{})

	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.zdns.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().IntVar(&GC.Threads, "threads", 1000, "number of lightweight go threads")
	rootCmd.PersistentFlags().IntVar(&GC.GoMaxProcs, "go-processes", 0, "number of OS processes (GOMAXPROCS)")
	rootCmd.PersistentFlags().StringVar(&GC.NamePrefix, "prefix", "", "name to be prepended to what's passed in (e.g., www.)")
	rootCmd.PersistentFlags().StringVar(&GC.NameOverride, "override-name", "", "name overrides all passed in names")
	rootCmd.PersistentFlags().BoolVar(&GC.MetadataFormat, "metadata-passthrough", false, "if input records have the form 'name,METADATA', METADATA will be propagated to the output")
	rootCmd.PersistentFlags().BoolVar(&GC.IterativeResolution, "iterative", false, "Perform own iteration instead of relying on recursive resolver")
	rootCmd.PersistentFlags().BoolVar(&GC.LookupAllNameServers, "all-nameservers", false, "Perform the lookup via all the nameservers for the domain.")
	rootCmd.PersistentFlags().StringVar(&GC.MetadataFilePath, "metadata-file", "", "where should JSON metadata be saved")
	rootCmd.PersistentFlags().StringVar(&GC.LogFilePath, "log-file", "", "where should JSON logs be saved")

	rootCmd.PersistentFlags().StringVar(&GC.ResultVerbosity, "result-verbosity", "normal", "Sets verbosity of each output record. Options: short, normal, long, trace")
	rootCmd.PersistentFlags().StringVar(&GC.IncludeInOutput, "include-fields", "", "Comma separated list of fields to additionally output beyond result verbosity. Options: class, protocol, ttl, resolver, flags")

	rootCmd.PersistentFlags().IntVar(&GC.ApiPort, "bind-port", 8080, "port to bind API to")
	rootCmd.PersistentFlags().StringVar(&GC.ApiIP, "bind-ip", "", "ip to bind API to")

	rootCmd.PersistentFlags().IntVar(&GC.Verbosity, "verbosity", 4, "log verbosity: 1 (lowest)--5 (highest)")
	rootCmd.PersistentFlags().IntVar(&GC.Retries, "retries", 1, "how many times should zdns retry query if timeout or temporary failure")
	rootCmd.PersistentFlags().IntVar(&GC.MaxDepth, "max-depth", 10, "how deep should we recurse when performing iterative lookups")
	rootCmd.PersistentFlags().IntVar(&GC.CacheSize, "cache-size", 10000, "how many items can be stored in internal recursive cache")
	rootCmd.PersistentFlags().BoolVar(&GC.TCPOnly, "tcp-only", false, "Only perform lookups over TCP")
	rootCmd.PersistentFlags().BoolVar(&GC.UDPOnly, "udp-only", false, "Only perform lookups over UDP")
	rootCmd.PersistentFlags().BoolVar(&GC.RecycleSockets, "recycle-sockets", true, "Create long-lived unbound UDP socket for each thread at launch and reuse for all (UDP) queries")
	rootCmd.PersistentFlags().BoolVar(&GC.NameServerMode, "name-server-mode", false, "Treats input as nameservers to query with a static query rather than queries to send to a static name server")

	rootCmd.PersistentFlags().StringVar(&AC.Servers_string, "name-servers", "", "List of DNS servers to use. Can be passed as comma-delimited string or via @/path/to/file. If no port is specified, defaults to 53.")
	rootCmd.PersistentFlags().StringVar(&AC.Localaddr_string, "local-addr", "", "comma-delimited list of local addresses to use")
	rootCmd.PersistentFlags().StringVar(&AC.Localif_string, "local-interface", "", "local interface to use")
	rootCmd.PersistentFlags().StringVar(&AC.Config_file, "conf-file", "/etc/resolv.conf", "config file for DNS servers")
	rootCmd.PersistentFlags().IntVar(&AC.Timeout, "timeout", 15, "timeout for resolving an individual name")
	rootCmd.PersistentFlags().IntVar(&AC.IterationTimeout, "iteration-timeout", 4, "timeout for resolving a single iteration in an iterative query")
	rootCmd.PersistentFlags().StringVar(&AC.Class_string, "class", "INET", "DNS class to query. Options: INET, CSNET, CHAOS, HESIOD, NONE, ANY. Default: INET.")
	rootCmd.PersistentFlags().BoolVar(&AC.NanoSeconds, "nanoseconds", false, "Use nanosecond resolution timestamps")

	rootCmd.PersistentFlags().Bool("ipv4-lookup", false, "Perform an IPv4 Lookup in modules")
	rootCmd.PersistentFlags().Bool("ipv6-lookup", false, "Perform an IPv6 Lookup in modules")
	rootCmd.PersistentFlags().String("blacklist-file", "", "blacklist file for servers to exclude from lookups")
	rootCmd.PersistentFlags().Int("mx-cache-size", 1000, "number of records to store in MX -> A/AAAA cache")
}

// Reference: https://github.com/carolynvs/stingoftheviper/blob/main/main.go
// For how to make cobra/viper sync up, and still use custom struct
// Bind each cobra flag to its associated viper configuration (config file and environment variable)
func BindFlags(cmd *cobra.Command, v *viper.Viper, envPrefix string) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --alexa to ZDNS_ALEXA
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			v.BindEnv(f.Name, fmt.Sprintf("%s_%s", envPrefix, envVarSuffix))
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".zdns" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".zdns")
	}

	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
	// Bind the current command's flags to viper
	BindFlags(rootCmd, viper.GetViper(), EnvPrefix)
}

// getDefaultResolvers returns a slice of default DNS resolvers to be used when no system resolvers could be discovered.
func GetDefaultResolvers() []string {
	return []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}
}

func AddDefaultPortToDNSServerName(s string) string {
	if !rePort.MatchString(s) {
		return s + ":53"
	} else if reV6.MatchString(s) {
		return "[" + s + "]:53"
	}
	return s
}
