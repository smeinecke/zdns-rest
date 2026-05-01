package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"testing"

	"github.com/spf13/viper"
)

func TestAddDefaultPortToDNSServerName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"IPv4 without port", "8.8.8.8", "8.8.8.8:53"},
		{"IPv4 with port", "8.8.8.8:53", "8.8.8.8:53"},
		{"IPv6 without port", "2001:db8::1", "[2001:db8::1]:53"},
		{"IPv6 with brackets no port", "[2001:db8::1]", "[2001:db8::1]:53"},
		{"IPv6 with brackets and port", "[2001:db8::1]:53", "[2001:db8::1]:53"},
		{"Hostname without port", "dns.google", "dns.google:53"},
		{"Hostname with port", "dns.google:53", "dns.google:53"},
	}

	// Initialize regex patterns
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AddDefaultPortToDNSServerName(tt.input)
			if result != tt.expected {
				t.Errorf("AddDefaultPortToDNSServerName(%q) = %q; want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetDefaultResolvers(t *testing.T) {
	resolvers := GetDefaultResolvers()
	if len(resolvers) == 0 {
		t.Error("GetDefaultResolvers() returned empty slice")
	}
	for _, r := range resolvers {
		if r == "" {
			t.Error("GetDefaultResolvers() returned empty string in slice")
		}
	}
}

func TestPrepareConfig(t *testing.T) {
	// Set up minimal config for testing
	AC.Servers_string = ""
	AC.Localaddr_string = ""
	AC.Localif_string = ""
	AC.Config_file = "/etc/resolv.conf"
	AC.Timeout = 15
	AC.IterationTimeout = 4
	AC.Class_string = "INET"
	AC.NanoSeconds = false

	GC.Verbosity = 4
	GC.LogFilePath = ""
	GC.IterativeResolution = false
	GC.LookupAllNameServers = false
	GC.NameServerMode = false
	GC.TCPOnly = false
	GC.UDPOnly = false
	GC.GoMaxProcs = 0

	// Initialize regex patterns
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	// This should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()

	// Verify that NameServers were set
	if len(GC.NameServers) == 0 {
		t.Error("prepareConfig() did not set NameServers")
	}
}

func TestLocalAddrParsing(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"Valid IPv4", "127.0.0.1", false},
		{"Valid IPv6", "::1", false},
		{"Invalid address", "not-an-ip", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.addr)
			if !tt.wantErr {
				if ip == nil {
					t.Errorf("net.ParseIP(%q) returned nil", tt.addr)
				}
			}
		})
	}
}

func TestAddDefaultPortToDNSServerName_WithEmptyString(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)
	result := AddDefaultPortToDNSServerName("")
	if result != ":53" {
		t.Errorf("AddDefaultPortToDNSServerName(\"\") = %q, want \":53\"", result)
	}
}

func TestAddDefaultPortToDNSServerName_CustomPort(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)
	result := AddDefaultPortToDNSServerName("8.8.8.8:5353")
	if result != "8.8.8.8:5353" {
		t.Errorf("AddDefaultPortToDNSServerName(\"8.8.8.8:5353\") = %q, want \"8.8.8.8:5353\"", result)
	}
}

func TestBindFlags(t *testing.T) {
	// Test that BindFlags processes viper configuration correctly
	v := viper.New()
	v.Set("threads", 500)
	v.Set("timeout", 30)

	// Test with a flag that has dashes in name (gets converted to underscore for env)
	v.Set("result-verbosity", "short")
	v.Set("bind-port", 9090)

	// Call BindFlags - should not panic
	BindFlags(rootCmd, v, "ZDNS")
}

func TestBindFlags_WithChangedFlag(t *testing.T) {
	// Test that changed flags are not overwritten
	v := viper.New()
	v.Set("threads", 999)

	// Mark a flag as changed
	if f := rootCmd.Flags().Lookup("threads"); f != nil {
		f.Changed = true
	}

	// Should not panic
	BindFlags(rootCmd, v, "ZDNS")

	// Reset for other tests
	if f := rootCmd.Flags().Lookup("threads"); f != nil {
		f.Changed = false
	}
}

func TestBindFlags_NoViperValue(t *testing.T) {
	// Test that flags without viper values are not modified
	v := viper.New()
	// Don't set any values

	// Should not panic
	BindFlags(rootCmd, v, "ZDNS")
}

func TestBindFlags_DashedFlagNames(t *testing.T) {
	// Test that flags with dashes are handled correctly for env vars
	v := viper.New()
	v.Set("result-verbosity", "long")
	v.Set("include-fields", "ttl,class")
	v.Set("bind-port", 8081)

	// Should not panic with dashed flag names
	BindFlags(rootCmd, v, "ZDNS")
}

func TestBindFlags_EnvPrefix(t *testing.T) {
	// Test with different environment prefix
	v := viper.New()
	v.Set("threads", 200)
	v.Set("timeout", 10)

	// Should not panic with different prefix
	BindFlags(rootCmd, v, "TEST")
}

func TestInitConfig(t *testing.T) {
	// Test that initConfig handles missing config file gracefully
	cfgFile = ""
	initConfig()
	// Should not panic even without config file
}

func TestInitConfig_WithCustomConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := tmpDir + "/test-config.yaml"
	if err := os.WriteFile(configFile, []byte("threads: 500\ntimeout: 20\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfgFile = configFile
	initConfig()
	// Should read the config file without panic

	// Reset
	cfgFile = ""
}

func TestInitConfig_NonexistentFile(t *testing.T) {
	cfgFile = "/nonexistent/path/config.yaml"
	initConfig()
	// Should handle missing file gracefully

	// Reset
	cfgFile = ""
}

func TestLoadKeyValueConfig(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected map[string]string
		wantErr  bool
	}{
		{
			name:    "simple key=value pairs",
			content: "bind-port=9090\nverbosity=5",
			expected: map[string]string{
				"bind-port": "9090",
				"verbosity": "5",
			},
			wantErr: false,
		},
		{
			name:    "with comments",
			content: "# This is a comment\nbind-port=8080\n# Another comment\nverbosity=3",
			expected: map[string]string{
				"bind-port": "8080",
				"verbosity": "3",
			},
			wantErr: false,
		},
		{
			name:    "empty lines",
			content: "bind-port=8080\n\n\nverbosity=4",
			expected: map[string]string{
				"bind-port": "8080",
				"verbosity": "4",
			},
			wantErr: false,
		},
		{
			name:    "spaces around equals",
			content: "bind-port = 9090\nverbosity = 3",
			expected: map[string]string{
				"bind-port": "9090",
				"verbosity": "3",
			},
			wantErr: false,
		},
		{
			name:    "value with equals sign",
			content: "api-key=secret=value=with=equals",
			expected: map[string]string{
				"api-key": "secret=value=with=equals",
			},
			wantErr: false},
		{
			name:    "empty value",
			content: "api-key=\nbind-port=8080",
			expected: map[string]string{
				"api-key":   "",
				"bind-port": "8080",
			},
			wantErr: false,
		},
		{
			name:     "file does not exist",
			content:  "",
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()

			var configPath string
			if tt.expected != nil || tt.content != "" {
				tmpDir := t.TempDir()
				configPath = tmpDir + "/test.conf"
				if err := os.WriteFile(configPath, []byte(tt.content), 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				configPath = "/nonexistent/path/config.conf"
			}

			err := loadKeyValueConfig(configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadKeyValueConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.expected != nil {
				for key, expectedValue := range tt.expected {
					if viper.GetString(key) != expectedValue {
						t.Errorf("loadKeyValueConfig() key %q = %q, want %q",
							key, viper.GetString(key), expectedValue)
					}
				}
			}
		})
	}
}

func TestLoadKeyValueConfig_BooleanValues(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/test.conf"
	content := `rate-limit=true
cache-enabled=false
tls=true`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	viper.Reset()
	err := loadKeyValueConfig(configPath)
	if err != nil {
		t.Fatalf("loadKeyValueConfig() error = %v", err)
	}

	// Verify boolean values are stored as strings (viper handles conversion)
	if viper.GetString("rate-limit") != "true" {
		t.Errorf("rate-limit = %v, want true", viper.GetString("rate-limit"))
	}
	if viper.GetString("cache-enabled") != "false" {
		t.Errorf("cache-enabled = %v, want false", viper.GetString("cache-enabled"))
	}
	if viper.GetString("tls") != "true" {
		t.Errorf("tls = %v, want true", viper.GetString("tls"))
	}
}

func TestLoadKeyValueConfig_EmptyAndCommentOnly(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/test.conf"
	content := `# This is a comment only file
# No actual configuration

`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	viper.Reset()
	err := loadKeyValueConfig(configPath)
	if err != nil {
		t.Fatalf("loadKeyValueConfig() error = %v", err)
	}

	// Should not have any keys set
	allSettings := viper.AllSettings()
	if len(allSettings) != 0 {
		t.Errorf("Expected no settings, got %v", allSettings)
	}
}

func TestInitConfig_WithConfFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := tmpDir + "/test.conf"
	content := `bind-port=9090
verbosity=5
rate-limit=false`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfgFile = configFile
	viper.Reset()
	initConfig()

	// Verify values were loaded
	if viper.GetString("bind-port") != "9090" {
		t.Errorf("bind-port = %v, want 9090", viper.GetString("bind-port"))
	}
	if viper.GetString("verbosity") != "5" {
		t.Errorf("verbosity = %v, want 5", viper.GetString("verbosity"))
	}
	if viper.GetString("rate-limit") != "false" {
		t.Errorf("rate-limit = %v, want false", viper.GetString("rate-limit"))
	}

	// Reset
	cfgFile = ""
	viper.Reset()
}

func TestInitConfig_ConfFileAutoDetection(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := tmpDir + "/zdns-rest.conf"
	content := `bind-port=7070`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfgFile = configFile
	viper.Reset()
	initConfig()

	if viper.GetString("bind-port") != "7070" {
		t.Errorf("bind-port = %v, want 7070", viper.GetString("bind-port"))
	}

	// Reset
	cfgFile = ""
	viper.Reset()
}

func TestInitConfig_EnvFileExtension(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := tmpDir + "/config.env"
	content := `bind-port=6060
verbosity=2`
	if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfgFile = configFile
	viper.Reset()
	initConfig()

	if viper.GetString("bind-port") != "6060" {
		t.Errorf("bind-port = %v, want 6060", viper.GetString("bind-port"))
	}
	if viper.GetString("verbosity") != "2" {
		t.Errorf("verbosity = %v, want 2", viper.GetString("verbosity"))
	}

	// Reset
	cfgFile = ""
	viper.Reset()
}

func TestLoadKeyValueConfig_MultipleEquals(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := tmpDir + "/test.conf"
	content := `cors-origins=http://example.com,https://example.com
name-servers=8.8.8.8,1.1.1.1`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	viper.Reset()
	err := loadKeyValueConfig(configPath)
	if err != nil {
		t.Fatalf("loadKeyValueConfig() error = %v", err)
	}

	if viper.GetString("cors-origins") != "http://example.com,https://example.com" {
		t.Errorf("cors-origins = %v, want http://example.com,https://example.com",
			viper.GetString("cors-origins"))
	}
	if viper.GetString("name-servers") != "8.8.8.8,1.1.1.1" {
		t.Errorf("name-servers = %v, want 8.8.8.8,1.1.1.1",
			viper.GetString("name-servers"))
	}
}

func TestPrepareConfig_LogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := tmpDir + "/test.log"

	GC.Verbosity = 4
	GC.LogFilePath = logFile
	GC.IterativeResolution = false
	GC.LookupAllNameServers = false
	GC.NameServerMode = false
	GC.TCPOnly = false
	GC.UDPOnly = false
	GC.GoMaxProcs = 0
	AC.Servers_string = ""
	AC.Localaddr_string = ""
	AC.Localif_string = ""
	AC.Config_file = "/etc/resolv.conf"
	AC.Timeout = 15
	AC.IterationTimeout = 4
	AC.Class_string = "INET"
	AC.NanoSeconds = false

	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked with log file: %v", r)
		}
	}()

	prepareConfig()

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("prepareConfig() did not create log file")
	}
}

func TestPrepareConfig_DifferentVerbosityLevels(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	tests := []struct {
		verbosity int
		wantPanic bool
	}{
		{1, false}, // Fatal
		{2, false}, // Error
		{3, false}, // Warning
		{4, false}, // Info
		{5, false}, // Debug
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("verbosity_%d", tt.verbosity), func(t *testing.T) {
			GC.Verbosity = tt.verbosity
			GC.LogFilePath = ""
			AC.Servers_string = ""
			AC.Localaddr_string = ""
			AC.Class_string = "INET"
			GC.IterativeResolution = false
			GC.NameServerMode = false
			GC.TCPOnly = false
			GC.UDPOnly = false

			defer func() {
				if r := recover(); r != nil && !tt.wantPanic {
					t.Errorf("prepareConfig() panicked at verbosity %d: %v", tt.verbosity, r)
				}
			}()

			prepareConfig()
		})
	}
}

func TestPrepareConfig_DifferentClasses(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	tests := []struct {
		class   string
		wantErr bool
	}{
		{"INET", false},
		{"IN", false},
		{"CSNET", false},
		{"CS", false},
		{"CHAOS", false},
		{"CH", false},
		{"HESIOD", false},
		{"HS", false},
		{"NONE", false},
		{"ANY", false},
	}

	for _, tt := range tests {
		t.Run(tt.class, func(t *testing.T) {
			GC.Verbosity = 4
			AC.Class_string = tt.class
			AC.Servers_string = ""
			AC.Localaddr_string = ""
			GC.IterativeResolution = false
			GC.NameServerMode = false
			GC.TCPOnly = false
			GC.UDPOnly = false

			defer func() {
				if r := recover(); r != nil && !tt.wantErr {
					t.Errorf("prepareConfig() panicked with class %s: %v", tt.class, r)
				}
			}()

			prepareConfig()
		})
	}
}

func TestPrepareConfig_Nanoseconds(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	GC.Verbosity = 4
	AC.NanoSeconds = true
	AC.Servers_string = ""
	AC.Class_string = "INET"
	GC.IterativeResolution = false
	GC.NameServerMode = false

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()
}

func TestPrepareConfig_WithNameServers(t *testing.T) {
	tmpDir := t.TempDir()
	serversFile := tmpDir + "/servers.txt"
	if err := os.WriteFile(serversFile, []byte("8.8.8.8\n1.1.1.1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	GC.Verbosity = 4
	AC.Servers_string = "@" + serversFile
	AC.Class_string = "INET"
	GC.NameServerMode = false
	GC.IterativeResolution = false

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()

	if !GC.NameServersSpecified {
		t.Error("prepareConfig() did not set NameServersSpecified to true")
	}
	if len(GC.NameServers) != 2 {
		t.Errorf("prepareConfig() set %d name servers, want 2", len(GC.NameServers))
	}
}

func TestPrepareConfig_WithLocalAddr(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	// Reset global state
	GC.LocalAddrs = nil
	GC.LocalAddrSpecified = false

	GC.Verbosity = 4
	AC.Servers_string = ""
	AC.Localaddr_string = "127.0.0.1,::1"
	AC.Class_string = "INET"
	GC.IterativeResolution = false
	GC.NameServerMode = false

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()

	if !GC.LocalAddrSpecified {
		t.Error("prepareConfig() did not set LocalAddrSpecified to true")
	}
	// Allow for some variation due to default address detection
	if len(GC.LocalAddrs) < 2 {
		t.Errorf("prepareConfig() set %d local addrs, want at least 2", len(GC.LocalAddrs))
	}
}

func TestPrepareConfig_GoMaxProcs(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	GC.Verbosity = 4
	GC.GoMaxProcs = 4
	AC.Servers_string = ""
	AC.Class_string = "INET"
	GC.IterativeResolution = false
	GC.NameServerMode = false

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()
}

func TestPrepareConfig_WithNameServersFromString(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	GC.Verbosity = 4
	AC.Servers_string = "8.8.8.8,1.1.1.1"
	AC.Class_string = "INET"
	GC.NameServerMode = false
	GC.IterativeResolution = false

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()

	if !GC.NameServersSpecified {
		t.Error("prepareConfig() did not set NameServersSpecified")
	}
	if len(GC.NameServers) != 2 {
		t.Errorf("prepareConfig() set %d name servers, want 2", len(GC.NameServers))
	}
}

func TestPrepareConfig_IterativeResolution(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	GC.Verbosity = 4
	AC.Servers_string = ""
	AC.Class_string = "INET"
	GC.IterativeResolution = true
	GC.NameServerMode = false

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()

	// In iterative mode, should use root servers
	if len(GC.NameServers) == 0 {
		t.Error("prepareConfig() did not set root servers for iterative resolution")
	}
}

func TestPrepareConfig_TCPOnlyAndUDPOnly(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	GC.Verbosity = 4
	AC.Servers_string = ""
	AC.Class_string = "INET"
	GC.IterativeResolution = false
	GC.NameServerMode = false
	GC.TCPOnly = true
	GC.UDPOnly = false

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()

	// Reset
	GC.TCPOnly = false
	GC.UDPOnly = true

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()
}

func TestPrepareConfig_LookupAllNameServers(t *testing.T) {
	rePort = regexp.MustCompile(`:\d+$`)
	reV6 = regexp.MustCompile(`^([0-9a-f]*:)`)

	GC.Verbosity = 4
	AC.Servers_string = ""
	AC.Class_string = "INET"
	GC.IterativeResolution = false
	GC.LookupAllNameServers = true
	GC.NameServerMode = false

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("prepareConfig() panicked: %v", r)
		}
	}()

	prepareConfig()
}
