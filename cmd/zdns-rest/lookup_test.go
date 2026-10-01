package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zmap/dns"
	"github.com/zmap/zdns/v2/src/zdns"
)

// mockLookuper is a zdns.Lookuper returning a canned SingleQueryResult, letting
// tests exercise the full executeQueries path without real DNS traffic.
type mockLookuper struct {
	status zdns.Status
	answer string
	called chan struct{}
}

func (m mockLookuper) DoDstServersLookup(ctx context.Context, r *zdns.Resolver, q zdns.Question, nameServers []zdns.NameServer, isIterative bool) (*zdns.SingleQueryResult, zdns.Trace, zdns.Status, error) {
	if m.called != nil {
		select {
		case m.called <- struct{}{}:
		default:
		}
	}
	status := m.status
	if status == "" {
		status = zdns.StatusNoError
	}
	answer := m.answer
	if answer == "" {
		answer = "93.184.216.34"
	}
	res := &zdns.SingleQueryResult{
		Answers: []interface{}{
			zdns.Answer{Name: q.Name, Type: "A", Class: "IN", Answer: answer, TTL: 300},
		},
		Protocol: "udp",
		Resolver: nameServers[0].String(),
	}
	return res, zdns.Trace{}, status, nil
}

func newMockEngine(t *testing.T, lu zdns.Lookuper) *lookupEngine {
	t.Helper()
	cfg := testConfigSnapshot()
	rc, err := buildResolverConfig(&cfg, AC.Config_file)
	require.NoError(t, err)
	rc.LookupClient = lu
	return &lookupEngine{cfg: &cfg, rc: rc, modules: initLookupModules(&cfg, rc)}
}

func TestParseNameServer(t *testing.T) {
	tests := []struct {
		in       string
		wantIP   string
		wantPort uint16
		wantErr  bool
	}{
		{"8.8.8.8", "8.8.8.8", 53, false},
		{"8.8.8.8:53", "8.8.8.8", 53, false},
		{"1.1.1.1:5353", "1.1.1.1", 5353, false},
		{"::1", "::1", 53, false},
		{"[2001:4860:4860::8888]:53", "2001:4860:4860::8888", 53, false},
		{"[2001:4860:4860::8888]", "2001:4860:4860::8888", 53, false},
		{"dns.google", "", 0, true},    // domain names unsupported
		{"8.8.8.8:bad", "", 0, true},   // non-numeric port
		{"8.8.8.8:0", "", 0, true},     // port 0 invalid
		{"8.8.8.8:70000", "", 0, true}, // port out of range
		{"", "", 0, true},              // empty
	}
	for _, tt := range tests {
		ns, err := parseNameServer(tt.in)
		if tt.wantErr {
			assert.Error(t, err, "parseNameServer(%q)", tt.in)
			continue
		}
		require.NoError(t, err, "parseNameServer(%q)", tt.in)
		assert.Equal(t, tt.wantPort, ns.Port)
		assert.Equal(t, tt.wantIP, ns.IP.String())
	}
}

func TestMakeName(t *testing.T) {
	name, changed := makeName("example.com", "", "")
	assert.Equal(t, "example.com", name)
	assert.False(t, changed)

	name, changed = makeName("example.com", "www.", "")
	assert.Equal(t, "www.example.com", name)
	assert.True(t, changed)

	name, changed = makeName("example.com", "www.", "override.test")
	assert.Equal(t, "override.test", name)
	assert.True(t, changed)
}

func TestMarshalResult_V1Format(t *testing.T) {
	cfg := testConfigSnapshot()
	cfg.OutputFormat = "v1"
	cfg.OutputGroups = []string{"normal"}
	cfg.TimeFormat = time.RFC3339

	data := &zdns.SingleQueryResult{
		Answers: []interface{}{zdns.Answer{Answer: "1.2.3.4", Type: "A"}},
	}
	line, err := marshalResult(&cfg, "A", "example.com", "example.com", false,
		zdns.StatusNoError, data, zdns.Trace{}, nil, 0.05)
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(line), &decoded))
	assert.Equal(t, "example.com", decoded["name"])
	assert.Equal(t, "NOERROR", decoded["status"])
	assert.Contains(t, decoded, "data")
	assert.Contains(t, decoded, "timestamp")
	assert.NotContains(t, decoded, "results") // v1 is flat, no nested results map
	assert.NotContains(t, decoded, "duration")
}

func TestMarshalResult_V2Format(t *testing.T) {
	cfg := testConfigSnapshot()
	cfg.OutputFormat = "v2"
	cfg.OutputGroups = []string{"normal"}
	cfg.TimeFormat = time.RFC3339
	cfg.Class = dns.ClassINET

	data := &zdns.SingleQueryResult{
		Answers: []interface{}{zdns.Answer{Answer: "1.2.3.4", Type: "A"}},
	}
	line, err := marshalResult(&cfg, "A", "example.com", "example.com", false,
		zdns.StatusNoError, data, zdns.Trace{}, nil, 0.05)
	require.NoError(t, err)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(line), &decoded))
	assert.Equal(t, "example.com", decoded["name"])
	assert.NotContains(t, decoded, "status") // v2 nests under results.MODULE
	require.Contains(t, decoded, "results")
	results := decoded["results"].(map[string]interface{})
	require.Contains(t, results, "A")
	modRes := results["A"].(map[string]interface{})
	assert.Equal(t, "NOERROR", modRes["status"])
	assert.Equal(t, 0.05, modRes["duration"])
	assert.Contains(t, modRes, "data")
	assert.Contains(t, modRes, "timestamp")
}

func TestMarshalResult_Error(t *testing.T) {
	cfg := testConfigSnapshot()
	cfg.OutputFormat = "v2"
	cfg.OutputGroups = []string{"normal"}
	cfg.TimeFormat = time.RFC3339

	line, err := marshalResult(&cfg, "A", "bad.example", "bad.example", false,
		zdns.StatusServFail, nil, nil, assert.AnError, 0.01)
	require.NoError(t, err)
	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(line), &decoded))
	modRes := decoded["results"].(map[string]interface{})["A"].(map[string]interface{})
	assert.Equal(t, "SERVFAIL", modRes["status"])
	assert.Equal(t, assert.AnError.Error(), modRes["error"])
}

func TestMarshalResult_AlteredName(t *testing.T) {
	cfg := testConfigSnapshot()
	cfg.OutputFormat = "v2"
	cfg.OutputGroups = []string{"normal", "short"}
	cfg.TimeFormat = time.RFC3339

	line, err := marshalResult(&cfg, "A", "example.com", "www.example.com", true,
		zdns.StatusNoError, nil, nil, nil, 0.01)
	require.NoError(t, err)
	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(line), &decoded))
	assert.Equal(t, "example.com", decoded["name"])
	assert.Equal(t, "www.example.com", decoded["altered_name"])
}

func TestExtractResultMeta(t *testing.T) {
	v1line := `{"name":"example.com","status":"NOERROR","data":{"answers":[]}}`
	name, status := extractResultMeta("A", v1line)
	assert.Equal(t, "example.com", name)
	assert.Equal(t, "NOERROR", status)

	v2line := `{"name":"example.com","results":{"A":{"status":"SERVFAIL","data":{}}}}`
	name, status = extractResultMeta("A", v2line)
	assert.Equal(t, "example.com", name)
	assert.Equal(t, "SERVFAIL", status)

	name, status = extractResultMeta("A", "not json")
	assert.Equal(t, "", name)
	assert.Equal(t, "", status)
}

func TestExecuteQueries_MockLookup(t *testing.T) {
	setupJobTestConfig(t)
	engine := newMockEngine(t, mockLookuper{})

	out := make(chan string)
	go func() {
		err := engine.executeQueries(context.Background(), "A", []string{"example.com", "example.org"}, nil, out)
		assert.NoError(t, err)
	}()

	var lines []string
	for line := range out {
		lines = append(lines, line)
	}
	require.Len(t, lines, 2)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &decoded))
	// v2 default format
	results := decoded["results"].(map[string]interface{})
	modRes := results["A"].(map[string]interface{})
	assert.Equal(t, "NOERROR", modRes["status"])
	data := modRes["data"].(map[string]interface{})
	answers := data["answers"].([]interface{})
	assert.Equal(t, "93.184.216.34", answers[0].(map[string]interface{})["answer"])
}

func TestExecuteQueries_MockLookup_V1Format(t *testing.T) {
	setupJobTestConfig(t)
	GCMu.Lock()
	GC.OutputFormat = "v1"
	GCMu.Unlock()
	engine := newMockEngine(t, mockLookuper{})

	out := make(chan string)
	go func() {
		err := engine.executeQueries(context.Background(), "A", []string{"example.com"}, nil, out)
		assert.NoError(t, err)
	}()

	var lines []string
	for line := range out {
		lines = append(lines, line)
	}
	require.Len(t, lines, 1)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &decoded))
	assert.Equal(t, "example.com", decoded["name"])
	assert.Equal(t, "NOERROR", decoded["status"])
	assert.Contains(t, decoded, "data")
}

func TestExecuteQueries_InvalidModule(t *testing.T) {
	setupJobTestConfig(t)
	engine := newMockEngine(t, mockLookuper{})

	out := make(chan string)
	err := engine.executeQueries(context.Background(), "NOTAMODULE", []string{"example.com"}, nil, out)
	assert.Error(t, err)
	// out channel must be closed so consumers don't hang
	_, ok := <-out
	assert.False(t, ok)
}

func TestExecuteQueries_Cancellation(t *testing.T) {
	setupJobTestConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already dead

	engine := newMockEngine(t, mockLookuper{})
	out := make(chan string)
	done := make(chan error, 1)
	go func() {
		done <- engine.executeQueries(ctx, "A", []string{"example.com"}, nil, out)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("executeQueries did not return after context cancellation")
	}
}

func TestExecuteQueries_CustomNameserver(t *testing.T) {
	setupJobTestConfig(t)
	engine := newMockEngine(t, mockLookuper{})

	ns, err := parseNameServer("9.9.9.9:53")
	require.NoError(t, err)

	out := make(chan string)
	go func() {
		err := engine.executeQueries(context.Background(), "A", []string{"example.com"}, ns, out)
		assert.NoError(t, err)
	}()
	var lines []string
	for line := range out {
		lines = append(lines, line)
	}
	require.Len(t, lines, 1)
	// the mock echoes the target resolver back
	assert.Contains(t, lines[0], "9.9.9.9:53")
}

func TestBuildResolverConfig(t *testing.T) {
	setupJobTestConfig(t)
	cfg := testConfigSnapshot()
	cfg.NameServers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	cfg.Retries = 7
	cfg.MaxDepth = 3

	rc, err := buildResolverConfig(&cfg, "/etc/resolv.conf")
	require.NoError(t, err)
	assert.Equal(t, 7, rc.Retries)
	assert.Equal(t, 3, rc.MaxDepth)
	require.Len(t, rc.ExternalNameServersV4, 2)
	require.Len(t, rc.RootNameServersV4, 2)
	assert.Equal(t, "8.8.8.8", rc.ExternalNameServersV4[0].IP.String())
	assert.Equal(t, uint16(53), rc.ExternalNameServersV4[0].Port)
}

func TestBuildResolverConfig_BadNameserver(t *testing.T) {
	setupJobTestConfig(t)
	cfg := testConfigSnapshot()
	cfg.NameServers = []string{"not-an-ip"}

	_, err := buildResolverConfig(&cfg, "/etc/resolv.conf")
	assert.Error(t, err)
}

func TestInitLookupModules(t *testing.T) {
	setupJobTestConfig(t)
	cfg := testConfigSnapshot()
	rc, err := buildResolverConfig(&cfg, "/etc/resolv.conf")
	require.NoError(t, err)

	modules := initLookupModules(&cfg, rc)
	// spot-check core + custom modules are present
	for _, name := range []string{"A", "AAAA", "MX", "NS", "TXT", "ALOOKUP", "MXLOOKUP", "NSLOOKUP", "BINDVERSION", "DMARC", "SPF", "AXFR"} {
		assert.Contains(t, modules, name)
	}
}
