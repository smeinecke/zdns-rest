package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/liip/sheriff"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/v2/src/cli"
	"github.com/zmap/zdns/v2/src/modules/alookup"
	"github.com/zmap/zdns/v2/src/modules/axfr"
	"github.com/zmap/zdns/v2/src/modules/mxlookup"
	"github.com/zmap/zdns/v2/src/modules/nslookup"
	"github.com/zmap/zdns/v2/src/zdns"
)

// parseNameServer converts a nameserver string ("1.1.1.1", "1.1.1.1:53",
// "[::1]:53") into a zdns.NameServer. Domain-name nameservers are not
// supported (no DoT/DoH/verify-server-cert surface is exposed).
func parseNameServer(s string) (*zdns.NameServer, error) {
	s = AddDefaultPortToDNSServerName(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("invalid name server %q: %w", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid name server %q: not an IP address", s)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid name server %q: bad port %q: %w", s, port, err)
	}
	if p <= 0 || p > 65535 {
		return nil, fmt.Errorf("invalid name server %q: port %d out of range", s, p)
	}
	return &zdns.NameServer{IP: ip, Port: uint16(p)}, nil
}

// resultSink consumes marshalled NDJSON lines produced by executeQueries:
// it buffers them into the ordered collector, records per-lookup
// metrics/logging, and stores definitive answers in the cache. Both the
// synchronous request path and async jobs share it — despite the old
// "OutputHandler" names this never wrote to the client; the caller flushes
// the collector after consume() returns.
type resultSink struct {
	requestID  string
	module     string
	nameserver string
	collector  *OrderedResultCollector
	start      time.Time
	onResult   func() // optional per-result hook (e.g. job progress)
}

func (s *resultSink) consume(results <-chan string) {
	cache := GetCache()
	for n := range results {
		if s.onResult != nil {
			s.onResult()
		}
		name, status := extractResultMeta(s.module, n)
		if name == "" {
			continue
		}
		if s.collector != nil {
			s.collector.Add(name, n)
		}
		LogDNSLookup(s.requestID, s.module, name, status, time.Since(s.start))
		if cache != nil && cache.enabled && isCacheableStatus(status) {
			cache.Set(s.module, name, s.nameserver, n)
			log.WithFields(log.Fields{
				"request_id": s.requestID,
				"module":     s.module,
				"domain":     name,
			}).Debug("Cached DNS result")
		}
	}
}

// parseNameServers converts a list of nameserver strings into IPv4/IPv6 splits.
func parseNameServers(servers []string) (v4, v6 []zdns.NameServer, err error) {
	for _, s := range servers {
		ns, err := parseNameServer(s)
		if err != nil {
			return nil, nil, err
		}
		if ns.IP.To4() != nil {
			v4 = append(v4, *ns)
		} else {
			v6 = append(v6, *ns)
		}
	}
	return v4, v6, nil
}

// buildResolverConfig translates our GlobalConf into a v2 ResolverConfig.
// Unlike the zdns CLI it returns errors instead of calling log.Fatal.
func buildResolverConfig(cfg *GlobalConf, confFile string) (*zdns.ResolverConfig, error) {
	rc := zdns.NewResolverConfig()

	rc.TransportMode = zdns.GetTransportMode(cfg.UDPOnly, cfg.TCPOnly)
	rc.Timeout = cfg.Timeout
	rc.IterativeTimeout = cfg.IterationTimeout
	if cfg.NetworkTimeout > 0 {
		rc.NetworkTimeout = cfg.NetworkTimeout
	}
	rc.Retries = cfg.Retries
	rc.MaxDepth = cfg.MaxDepth
	rc.CacheSize = cfg.CacheSize
	rc.Cache = nil // CacheSize and Cache are mutually exclusive
	rc.LookupAllNameServers = cfg.LookupAllNameServers
	rc.ShouldRecycleSockets = cfg.RecycleSockets
	rc.FollowCNAMEs = true
	rc.DNSConfigFilePath = confFile

	// Verbosity maps 1:1 onto logrus levels in both our config and zdns'.
	rc.LogLevel = log.Level(cfg.Verbosity) //nolint:gosec // G115: verbosity validated to 0-5 in prepareConfig

	// Local addresses, split by IP family.
	for _, ip := range cfg.LocalAddrs {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			rc.LocalAddrsV4 = append(rc.LocalAddrsV4, ip)
		} else {
			rc.LocalAddrsV6 = append(rc.LocalAddrsV6, ip)
		}
	}

	// Nameservers: user-provided list wins; otherwise OS resolvers; iterative
	// mode without explicit servers starts from the root servers. Both
	// External and Root lists are populated since the resolver doesn't know
	// ahead of time whether a module will do iterative lookups.
	switch {
	case len(cfg.NameServers) > 0:
		v4, v6, err := parseNameServers(cfg.NameServers)
		if err != nil {
			return nil, err
		}
		rc.ExternalNameServersV4 = v4
		rc.RootNameServersV4 = slices.Clone(v4)
		rc.ExternalNameServersV6 = v6
		rc.RootNameServersV6 = slices.Clone(v6)
	case cfg.IterativeResolution:
		rc.ExternalNameServersV4 = slices.Clone(zdns.RootServersV4)
		rc.RootNameServersV4 = slices.Clone(zdns.RootServersV4)
		rc.ExternalNameServersV6 = slices.Clone(zdns.RootServersV6)
		rc.RootNameServersV6 = slices.Clone(zdns.RootServersV6)
	default:
		v4strings, v6strings, err := zdns.GetDNSServers(confFile)
		if err != nil {
			log.Warnf("unable to parse DNS config file %s (%v); using defaults", confFile, err)
		}
		v4, err := stringsToNameServers(v4strings)
		if err != nil {
			return nil, err
		}
		v6, err := stringsToNameServers(v6strings)
		if err != nil {
			return nil, err
		}
		if len(v4) == 0 {
			v4 = zdns.DefaultExternalResolversV4
		}
		if len(v6) == 0 {
			v6 = zdns.DefaultExternalResolversV6
		}
		rc.ExternalNameServersV4 = v4
		rc.RootNameServersV4 = append([]zdns.NameServer{}, v4...)
		rc.ExternalNameServersV6 = v6
		rc.RootNameServersV6 = append([]zdns.NameServer{}, v6...)
	}

	if err := rc.Validate(); err != nil {
		return nil, fmt.Errorf("invalid resolver config: %w", err)
	}
	return rc, nil
}

// stringsToNameServers converts "host:port" strings (as returned by
// zdns.GetDNSServers) into NameServer structs.
func stringsToNameServers(servers []string) ([]zdns.NameServer, error) {
	out := make([]zdns.NameServer, 0, len(servers))
	for _, s := range servers {
		ns, err := parseNameServer(s)
		if err != nil {
			return nil, err
		}
		out = append(out, *ns)
	}
	return out, nil
}

// moduleConfigMu guards the zdns module registry. cli.GetLookupModule returns
// process-global singletons; CLIInit writes fields (IsIterative, DNSClass,
// LookupAllNameServers, module options) that Lookup reads. Re-initializing
// modules (e.g. a second Server in the same process) while lookups from a
// previous engine are in-flight races on those fields. Write-lock around
// CLIInit, read-lock around each Lookup call: lookups stay fully concurrent,
// init only waits for in-flight queries.
var moduleConfigMu sync.RWMutex

// initLookupModules returns the set of lookup modules initialized against the
// given configuration. Modules that fail CLIInit are logged and excluded —
// requests for them will fail validation at request time.
func initLookupModules(cfg *GlobalConf, rc *zdns.ResolverConfig) map[string]cli.LookupModule {
	cliConf := &cli.CLIConf{}
	cliConf.Class = cfg.Class
	cliConf.IterativeResolution = cfg.IterativeResolution
	cliConf.LookupAllNameServers = cfg.LookupAllNameServers
	cliConf.OutputGroups = cfg.OutputGroups
	cliConf.TimeFormat = cfg.TimeFormat

	moduleConfigMu.Lock()
	defer moduleConfigMu.Unlock()

	modules := make(map[string]cli.LookupModule)
	for name := range cli.GetValidLookups() {
		mod, err := cli.GetLookupModule(name)
		if err != nil {
			continue
		}
		// AXFR's CLIInit calls log.Fatal under iterative resolution —
		// skip it instead of dying at startup.
		if name == "AXFR" && cfg.IterativeResolution {
			log.Warn("AXFR module does not support iterative resolution, disabled")
			continue
		}
		// Module-specific flags that used to flow through v1's
		// factory.SetFlags are now struct fields set before CLIInit.
		switch m := mod.(type) {
		case *alookup.ALookupModule:
			m.IPv4Lookup = cfg.IPv4Lookup
			m.IPv6Lookup = cfg.IPv6Lookup
		case *mxlookup.MXLookupModule:
			m.IPv4Lookup = cfg.IPv4Lookup
			m.IPv6Lookup = cfg.IPv6Lookup
		case *nslookup.NSLookupModule:
			m.IPv4Lookup = cfg.IPv4Lookup
			m.IPv6Lookup = cfg.IPv6Lookup
		case *axfr.AxfrLookupModule:
			m.IPv4Lookup = cfg.IPv4Lookup
			m.IPv6Lookup = cfg.IPv6Lookup
			m.BlacklistPath = cfg.BlacklistFile
		}
		if err := mod.CLIInit(cliConf, rc); err != nil {
			log.Warnf("lookup module %s failed to initialize: %v", name, err)
			continue
		}
		modules[name] = mod
	}
	return modules
}

// makeName applies the configured name prefix/override, like the zdns CLI.
func makeName(rawName, prefix, override string) (lookupName string, changed bool) {
	if override != "" {
		return override, true
	}
	if prefix != "" {
		return prefix + rawName, true
	}
	return rawName, false
}

// lookupResult mirrors the v1 zdns.Result wire shape: a flat envelope with
// name/status/data. Used for --output-format=v1.
type lookupResult struct {
	AlteredName string      `json:"altered_name,omitempty" groups:"short,normal,long,trace"`
	Name        string      `json:"name,omitempty" groups:"short,normal,long,trace"`
	Class       string      `json:"class,omitempty" groups:"long,trace"`
	Status      string      `json:"status,omitempty" groups:"short,normal,long,trace"`
	Error       string      `json:"error,omitempty" groups:"short,normal,long,trace"`
	Timestamp   string      `json:"timestamp,omitempty" groups:"short,normal,long,trace"`
	Data        interface{} `json:"data,omitempty" groups:"short,normal,long,trace"`
	Trace       zdns.Trace  `json:"trace,omitempty" groups:"trace"`
}

var sheriffAPIVersion = version.Must(version.NewVersion("0.0.0"))

// marshalResult renders one lookup result as an NDJSON line in the configured
// output format (v1 flat envelope or the upstream v2 nested envelope).
func marshalResult(cfg *GlobalConf, module, rawName, lookupName string, changed bool, status zdns.Status, data any, trace zdns.Trace, lerr error, duration float64) (string, error) {
	errStr := ""
	if lerr != nil {
		errStr = lerr.Error()
	}
	timestamp := time.Now().Format(cfg.TimeFormat)

	var obj interface{}
	if cfg.OutputFormat == "v1" {
		res := lookupResult{
			Name:      rawName,
			Class:     dns.Class(cfg.Class).String(),
			Status:    string(status),
			Error:     errStr,
			Timestamp: timestamp,
			Data:      data,
			Trace:     trace,
		}
		if changed {
			res.AlteredName = lookupName
		}
		o := &sheriff.Options{
			Groups:     cfg.OutputGroups,
			ApiVersion: sheriffAPIVersion,
		}
		var err error
		obj, err = sheriff.Marshal(o, res)
		if err != nil {
			return "", err
		}
	} else {
		res := zdns.Result{
			Name:  rawName,
			Class: dns.Class(cfg.Class).String(),
			Results: map[string]zdns.SingleModuleResult{
				module: {
					Status:    string(status),
					Error:     errStr,
					Timestamp: timestamp,
					Duration:  duration,
					Data:      data,
					Trace:     trace,
				},
			},
		}
		if changed {
			res.AlteredName = lookupName
		}
		o := &sheriff.Options{
			Groups:          cfg.OutputGroups,
			ApiVersion:      sheriffAPIVersion,
			IncludeEmptyTag: true,
		}
		m, err := sheriff.Marshal(o, res)
		if err != nil {
			return "", err
		}
		obj = replaceIntSliceInterface(m)
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// replaceIntSliceInterface is ported from the zdns v2 CLI: integer slices
// would otherwise serialize as base64 strings via encoding/json.
func replaceIntSliceInterface(data any) any {
	if jsonData, err := marshalIntSlice(data); err == nil && jsonData != nil {
		return jsonData
	}
	switch casted := data.(type) {
	case map[string]any:
		for k, v := range casted {
			casted[k] = replaceIntSliceInterface(v)
		}
		return casted
	case []any:
		for i, v := range casted {
			casted[i] = replaceIntSliceInterface(v)
		}
		return casted
	default:
		return data
	}
}

// marshalIntSlice converts any integer slice into []any so encoding/json emits
// a real array (e.g. [1,2,3]) rather than a base64 string. Returns (nil, nil)
// when data isn't an integer slice.
func marshalIntSlice(data any) (any, error) {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Slice {
		return nil, nil
	}
	switch v.Type().Elem().Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	default:
		return nil, nil
	}
	out := make([]any, v.Len())
	for i := 0; i < v.Len(); i++ {
		out[i] = v.Index(i).Interface()
	}
	return out, nil
}

// extractResultMeta pulls the name and status out of a marshalled result line
// in either output format (v1: flat "status"; v2: "results"."MOD"."status").
func extractResultMeta(module, line string) (name, status string) {
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		return "", ""
	}
	name, _ = decoded["name"].(string)
	status, _ = decoded["status"].(string)
	if status == "" {
		if results, ok := decoded["results"].(map[string]interface{}); ok {
			if modRes, ok := results[module].(map[string]interface{}); ok {
				status, _ = modRes["status"].(string)
			}
		}
	}
	return name, status
}

// lookupEngine is the shared zdns v2 execution path used by the sync
// (runModule) and async (processJob) handlers. It owns the immutable resolver
// config and the initialized module registry.
type lookupEngine struct {
	cfg     *GlobalConf
	rc      *zdns.ResolverConfig
	modules map[string]cli.LookupModule
}

// executeQueries runs lookups for the given module over all queries, pushing
// marshalled NDJSON result lines to out (which is closed when done). Workers
// each own a dedicated zdns.Resolver — the resolver carries per-lookup mutable
// state and is not safe for concurrent use. Context cancellation aborts
// in-flight queries (v2 checks ctx per network call).
func (e *lookupEngine) executeQueries(ctx context.Context, module string, queries []string, ns *zdns.NameServer, out chan<- string) error {
	defer close(out)

	mod, ok := e.modules[module]
	if !ok {
		return fmt.Errorf("module %s not found", module)
	}

	rc := e.rc
	if ns != nil && e.cfg.LookupAllNameServers {
		// In all-nameservers mode the per-lookup ns argument is ignored by
		// the module, so pin the resolver config to the requested server.
		clone := *rc
		v4, v6, err := parseNameServers([]string{ns.String()})
		if err != nil {
			return err
		}
		clone.ExternalNameServersV4 = v4
		clone.RootNameServersV4 = append([]zdns.NameServer{}, v4...)
		clone.ExternalNameServersV6 = v6
		clone.RootNameServersV6 = append([]zdns.NameServer{}, v6...)
		ns = nil // resolver config now pins the single nameserver
		rc = &clone
	}

	workers := e.cfg.Threads
	if workers <= 0 || workers > len(queries) {
		workers = len(queries)
	}

	// Buffered so the feeder never blocks even if all workers exited early
	// (resolver init failure or cancelled context).
	in := make(chan string, len(queries))
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error
	setErr := func(err error) {
		errOnce.Do(func() { firstErr = err })
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolver, err := zdns.InitResolver(rc)
			if err != nil {
				setErr(fmt.Errorf("could not init resolver: %w", err))
				return
			}
			defer resolver.Close()
			for rawName := range in {
				lookupName, changed := makeName(rawName, e.cfg.NamePrefix, e.cfg.NameOverride)
				start := time.Now()
				// RLock guards against concurrent module re-init on the
				// shared registry singletons; lookups stay parallel.
				moduleConfigMu.RLock()
				data, trace, status, lerr := mod.Lookup(ctx, resolver, lookupName, ns)
				moduleConfigMu.RUnlock()
				duration := time.Since(start).Seconds()
				if status == zdns.StatusNoOutput {
					continue
				}
				line, merr := marshalResult(e.cfg, module, rawName, lookupName, changed, status, data, trace, lerr, duration)
				if merr != nil {
					setErr(fmt.Errorf("unable to marshal result: %w", merr))
					continue
				}
				select {
				case out <- line:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Feed queries; stop early if the context dies.
	for _, q := range queries {
		if ctx.Err() != nil {
			break
		}
		in <- q
	}
	close(in)
	wg.Wait()
	return firstErr
}
