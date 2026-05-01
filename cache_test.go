package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewDNSCache(t *testing.T) {
	tests := []struct {
		name      string
		enabled   bool
		maxSize   int
		ttl       time.Duration
		wantSize  int
		wantTTL   time.Duration
		wantStale time.Duration
	}{
		{
			name:      "default values",
			enabled:   true,
			maxSize:   0,
			ttl:       0,
			wantSize:  10000,
			wantTTL:   5 * time.Minute,
			wantStale: 2*time.Minute + 30*time.Second,
		},
		{
			name:      "custom values",
			enabled:   true,
			maxSize:   500,
			ttl:       10 * time.Minute,
			wantSize:  500,
			wantTTL:   10 * time.Minute,
			wantStale: 5 * time.Minute,
		},
		{
			name:      "disabled cache",
			enabled:   false,
			maxSize:   100,
			ttl:       time.Minute,
			wantSize:  100,
			wantTTL:   time.Minute,
			wantStale: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewDNSCache(tt.enabled, tt.maxSize, tt.ttl)
			assert.NotNil(t, cache)
			assert.Equal(t, tt.enabled, cache.enabled)
			assert.Equal(t, tt.wantSize, cache.maxSize)
			assert.Equal(t, tt.wantTTL, cache.ttl)
			assert.Equal(t, tt.wantStale, cache.staleTTL)
			assert.NotNil(t, cache.entries)
			assert.NotNil(t, cache.lruList)
			assert.NotNil(t, cache.lruIndex)
		})
	}
}

func TestDNSCache_NilReceiver(t *testing.T) {
	var cache *DNSCache

	assert.Nil(t, cache.Get("A", "example.com", "8.8.8.8:53", false))
	assert.NotPanics(t, func() {
		cache.Set("A", "example.com", "8.8.8.8:53", "value")
		cache.Delete("A", "example.com", "8.8.8.8:53")
		cache.Clear()
		cache.Cleanup()
	})
	assert.Equal(t, 0, cache.Size())
	assert.Equal(t, CacheStats{}, cache.Stats())

	stop := cache.StartCleanup(time.Millisecond)
	assert.NotNil(t, stop)
	close(stop)
}

func TestGenerateCacheKey(t *testing.T) {
	tests := []struct {
		name       string
		module     string
		query      string
		nameserver string
		wantDiff   bool
		compare    struct {
			module     string
			query      string
			nameserver string
		}
	}{
		{
			name:       "same inputs same key",
			module:     "A",
			query:      "example.com",
			nameserver: "8.8.8.8:53",
			wantDiff:   false,
			compare:    struct{ module, query, nameserver string }{"A", "example.com", "8.8.8.8:53"},
		},
		{
			name:       "different module different key",
			module:     "A",
			query:      "example.com",
			nameserver: "8.8.8.8:53",
			wantDiff:   true,
			compare:    struct{ module, query, nameserver string }{"MX", "example.com", "8.8.8.8:53"},
		},
		{
			name:       "different query different key",
			module:     "A",
			query:      "example.com",
			nameserver: "8.8.8.8:53",
			wantDiff:   true,
			compare:    struct{ module, query, nameserver string }{"A", "example.org", "8.8.8.8:53"},
		},
		{
			name:       "different nameserver different key",
			module:     "A",
			query:      "example.com",
			nameserver: "8.8.8.8:53",
			wantDiff:   true,
			compare:    struct{ module, query, nameserver string }{"A", "example.com", "1.1.1.1:53"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1 := generateCacheKey(tt.module, tt.query, tt.nameserver)
			key2 := generateCacheKey(tt.compare.module, tt.compare.query, tt.compare.nameserver)

			if tt.wantDiff {
				assert.NotEqual(t, key1, key2)
			} else {
				assert.Equal(t, key1, key2)
			}
		})
	}
}

func TestCacheEntryIsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		entry CacheEntry
		want  bool
	}{
		{
			name: "not expired",
			entry: CacheEntry{
				ExpiresAt: now.Add(time.Minute),
			},
			want: false,
		},
		{
			name: "expired",
			entry: CacheEntry{
				ExpiresAt: now.Add(-time.Minute),
			},
			want: true,
		},
		{
			name: "exactly at expiration",
			entry: CacheEntry{
				ExpiresAt: now,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.IsExpired())
		})
	}
}

func TestCacheEntryIsStale(t *testing.T) {
	now := time.Now()
	staleTTL := 5 * time.Minute

	tests := []struct {
		name     string
		entry    CacheEntry
		staleTTL time.Duration
		want     bool
	}{
		{
			name: "fresh entry",
			entry: CacheEntry{
				ExpiresAt: now.Add(time.Minute),
			},
			staleTTL: staleTTL,
			want:     false,
		},
		{
			name: "within stale window",
			entry: CacheEntry{
				ExpiresAt: now.Add(-2 * time.Minute),
			},
			staleTTL: staleTTL,
			want:     true,
		},
		{
			name: "past stale window",
			entry: CacheEntry{
				ExpiresAt: now.Add(-10 * time.Minute),
			},
			staleTTL: staleTTL,
			want:     false,
		},
		{
			name: "zero stale TTL",
			entry: CacheEntry{
				ExpiresAt: now.Add(-time.Minute),
			},
			staleTTL: 0,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.IsStale(tt.staleTTL))
		})
	}
}

func TestDNSCacheSetAndGet(t *testing.T) {
	cache := NewDNSCache(true, 100, time.Hour)

	// Test Set and Get
	cache.Set("A", "example.com", "8.8.8.8:53", `{"result": "success"}`)

	entry := cache.Get("A", "example.com", "8.8.8.8:53", false)
	assert.NotNil(t, entry)
	assert.Equal(t, `{"result": "success"}`, entry.Result)

	// Test Get non-existent
	entry = cache.Get("A", "nonexistent.com", "8.8.8.8:53", false)
	assert.Nil(t, entry)

	// Test Get with different nameserver
	entry = cache.Get("A", "example.com", "1.1.1.1:53", false)
	assert.Nil(t, entry)
}

func TestDNSCacheExpiration(t *testing.T) {
	cache := NewDNSCache(true, 100, 100*time.Millisecond)

	cache.Set("A", "example.com", "8.8.8.8:53", `{"result": "success"}`)

	// Should be available immediately
	entry := cache.Get("A", "example.com", "8.8.8.8:53", false)
	assert.NotNil(t, entry)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired now
	entry = cache.Get("A", "example.com", "8.8.8.8:53", false)
	assert.Nil(t, entry)
}

func TestDNSCacheStaleOnError(t *testing.T) {
	cache := NewDNSCache(true, 100, 100*time.Millisecond)
	cache.staleTTL = 200 * time.Millisecond

	cache.Set("A", "example.com", "8.8.8.8:53", `{"result": "success"}`)

	// Wait for expiration but within stale window
	time.Sleep(150 * time.Millisecond)

	// Should serve stale when allowStale=true
	entry := cache.Get("A", "example.com", "8.8.8.8:53", true)
	assert.NotNil(t, entry)
	assert.Equal(t, `{"result": "success"}`, entry.Result)

	// Should not serve stale when allowStale=false
	entry = cache.Get("A", "example.com", "8.8.8.8:53", false)
	assert.Nil(t, entry)

	// Wait past stale window
	time.Sleep(200 * time.Millisecond)

	// Should be completely gone now even with allowStale=true
	entry = cache.Get("A", "example.com", "8.8.8.8:53", true)
	assert.Nil(t, entry)
}

func TestDNSCacheLRUEviction(t *testing.T) {
	cache := NewDNSCache(true, 3, time.Hour)

	// Add 3 entries
	cache.Set("A", "domain1.com", "8.8.8.8:53", `{"result": "1"}`)
	cache.Set("A", "domain2.com", "8.8.8.8:53", `{"result": "2"}`)
	cache.Set("A", "domain3.com", "8.8.8.8:53", `{"result": "3"}`)

	assert.Equal(t, 3, cache.Size())

	// Access domain1 to make it recently used
	_ = cache.Get("A", "domain1.com", "8.8.8.8:53", false)

	// Add 4th entry - should evict domain2 (least recently used)
	cache.Set("A", "domain4.com", "8.8.8.8:53", `{"result": "4"}`)

	assert.Equal(t, 3, cache.Size())

	// domain1 should still exist (was accessed)
	assert.NotNil(t, cache.Get("A", "domain1.com", "8.8.8.8:53", false))

	// domain2 should be evicted
	assert.Nil(t, cache.Get("A", "domain2.com", "8.8.8.8:53", false))

	// domain3 and domain4 should exist
	assert.NotNil(t, cache.Get("A", "domain3.com", "8.8.8.8:53", false))
	assert.NotNil(t, cache.Get("A", "domain4.com", "8.8.8.8:53", false))
}

func TestDNSCacheUpdateExistingDoesNotDuplicateLRU(t *testing.T) {
	cache := NewDNSCache(true, 3, time.Hour)

	cache.Set("A", "example.com", "8.8.8.8:53", `{"result":"1"}`)
	cache.Set("A", "example.com", "8.8.8.8:53", `{"result":"2"}`)

	assert.Equal(t, 1, cache.Size())
	assert.Equal(t, 1, cache.lruList.Len())
	assert.Len(t, cache.lruIndex, 1)

	entry := cache.Get("A", "example.com", "8.8.8.8:53", false)
	assert.NotNil(t, entry)
	assert.Equal(t, `{"result":"2"}`, entry.Result)
}

func TestDNSCacheDelete(t *testing.T) {
	cache := NewDNSCache(true, 100, time.Hour)

	cache.Set("A", "example.com", "8.8.8.8:53", `{"result": "success"}`)
	assert.Equal(t, 1, cache.Size())

	cache.Delete("A", "example.com", "8.8.8.8:53")
	assert.Equal(t, 0, cache.Size())

	entry := cache.Get("A", "example.com", "8.8.8.8:53", false)
	assert.Nil(t, entry)
}

func TestDNSCacheClear(t *testing.T) {
	cache := NewDNSCache(true, 100, time.Hour)

	cache.Set("A", "domain1.com", "8.8.8.8:53", `{"result": "1"}`)
	cache.Set("A", "domain2.com", "8.8.8.8:53", `{"result": "2"}`)
	cache.Set("MX", "domain3.com", "8.8.8.8:53", `{"result": "3"}`)

	assert.Equal(t, 3, cache.Size())

	cache.Clear()

	assert.Equal(t, 0, cache.Size())
	assert.Nil(t, cache.Get("A", "domain1.com", "8.8.8.8:53", false))
	assert.Nil(t, cache.Get("A", "domain2.com", "8.8.8.8:53", false))
	assert.Nil(t, cache.Get("MX", "domain3.com", "8.8.8.8:53", false))
}

func TestDNSCacheStats(t *testing.T) {
	cache := NewDNSCache(true, 100, time.Hour)

	// Empty cache stats
	stats := cache.Stats()
	assert.Equal(t, 0, stats.Size)
	assert.Equal(t, 0, stats.Fresh)
	assert.Equal(t, 100, stats.MaxSize)
	assert.Equal(t, time.Hour, stats.TTL)

	// Add entries
	cache.Set("A", "fresh.com", "8.8.8.8:53", `{"result": "1"}`)

	stats = cache.Stats()
	assert.Equal(t, 1, stats.Size)
	assert.Equal(t, 1, stats.Fresh)
	assert.Equal(t, 0, stats.Stale)
	assert.Equal(t, 0, stats.Expired)
}

func TestDNSCacheCleanup(t *testing.T) {
	cache := NewDNSCache(true, 100, 100*time.Millisecond)
	cache.staleTTL = 50 * time.Millisecond

	cache.Set("A", "expired.com", "8.8.8.8:53", `{"result": "1"}`)

	// Wait for full expiration including stale window
	time.Sleep(200 * time.Millisecond)

	// Entry should still be in cache (cleanup hasn't run)
	cache.mu.RLock()
	_, exists := cache.entries[generateCacheKey("A", "expired.com", "8.8.8.8:53")]
	cache.mu.RUnlock()
	assert.True(t, exists)

	// Run cleanup
	cache.Cleanup()

	// Entry should be gone
	cache.mu.RLock()
	_, exists = cache.entries[generateCacheKey("A", "expired.com", "8.8.8.8:53")]
	cache.mu.RUnlock()
	assert.False(t, exists)
}

func TestDisabledCache(t *testing.T) {
	cache := NewDNSCache(false, 100, time.Hour)

	cache.Set("A", "example.com", "8.8.8.8:53", `{"result": "success"}`)

	entry := cache.Get("A", "example.com", "8.8.8.8:53", false)
	assert.Nil(t, entry)

	assert.Equal(t, 0, cache.Size())

	stats := cache.Stats()
	assert.Equal(t, 0, stats.Size)
}

func TestInitCacheReinitialization(t *testing.T) {
	InitCache(true, 10, time.Minute)
	first := GetCache()
	assert.NotNil(t, first)
	assert.True(t, first.enabled)

	InitCache(false, 0, 0)
	second := GetCache()
	assert.NotNil(t, second)
	assert.False(t, second.enabled)
	assert.NotSame(t, first, second)

	InitCache(true, 5, time.Second)
	third := GetCache()
	assert.NotNil(t, third)
	assert.True(t, third.enabled)
	assert.Equal(t, 5, third.maxSize)
	assert.Equal(t, time.Second, third.ttl)
}

func TestCacheStatsToJSON(t *testing.T) {
	stats := CacheStats{
		Size:     10,
		Fresh:    8,
		Stale:    1,
		Expired:  1,
		MaxSize:  100,
		TTL:      time.Minute,
		StaleTTL: 30 * time.Second,
	}

	json := stats.ToJSON()
	assert.Contains(t, json, `"size":10`)
	assert.Contains(t, json, `"fresh":8`)
	assert.Contains(t, json, `"stale":1`)
	assert.Contains(t, json, `"expired":1`)
	assert.Contains(t, json, `"max_size":100`)
}
