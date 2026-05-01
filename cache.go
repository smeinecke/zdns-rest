package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

// Cache metrics
var (
	cacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_cache_hits_total",
			Help: "Total number of cache hits",
		},
		[]string{"module"},
	)

	cacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_cache_misses_total",
			Help: "Total number of cache misses",
		},
		[]string{"module"},
	)

	cacheEvictions = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_cache_evictions_total",
			Help: "Total number of cache evictions",
		},
	)

	cacheSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "zdns_cache_size",
			Help: "Current number of items in cache",
		},
	)
)

// CacheEntry represents a cached DNS lookup result
type CacheEntry struct {
	Key        string
	Result     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Module     string
	Query      string
	Nameserver string
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// IsStale checks if the entry is past TTL but within stale window
func (e *CacheEntry) IsStale(staleTTL time.Duration) bool {
	if staleTTL <= 0 {
		return false
	}
	staleDeadline := e.ExpiresAt.Add(staleTTL)
	return time.Now().After(e.ExpiresAt) && time.Now().Before(staleDeadline)
}

// DNSCache is an in-memory cache for DNS lookup results
type DNSCache struct {
	mu       sync.RWMutex
	entries  map[string]*CacheEntry
	lruList  []string
	maxSize  int
	ttl      time.Duration
	staleTTL time.Duration
	enabled  bool
}

// NewDNSCache creates a new DNS cache with the specified configuration
func NewDNSCache(enabled bool, maxSize int, ttl time.Duration) *DNSCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	return &DNSCache{
		entries:  make(map[string]*CacheEntry),
		lruList:  make([]string, 0, maxSize),
		maxSize:  maxSize,
		ttl:      ttl,
		staleTTL: ttl / 2, // Stale window is half of TTL by default
		enabled:  enabled,
	}
}

// generateCacheKey creates a unique key for a DNS lookup
func generateCacheKey(module, query, nameserver string) string {
	h := sha256.New()
	h.Write([]byte(module))
	h.Write([]byte("|"))
	h.Write([]byte(query))
	h.Write([]byte("|"))
	h.Write([]byte(nameserver))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Get retrieves a cached result. Returns nil if not found or expired.
// If allowStale is true, may return stale entries.
func (c *DNSCache) Get(module, query, nameserver string, allowStale bool) *CacheEntry {
	if !c.enabled || c == nil {
		return nil
	}

	key := generateCacheKey(module, query, nameserver)

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		cacheMisses.WithLabelValues(module).Inc()
		return nil
	}

	// Check if entry is fresh
	if !entry.IsExpired() {
		// Move to front of LRU list
		c.updateLRU(key)
		cacheHits.WithLabelValues(module).Inc()
		return entry
	}

	// Entry is expired - check if we can serve stale
	if allowStale && entry.IsStale(c.staleTTL) {
		log.WithFields(log.Fields{
			"module": module,
			"query":  query,
		}).Debug("Serving stale cache entry")
		cacheHits.WithLabelValues(module).Inc()
		return entry
	}

	// Entry is expired and stale window passed
	delete(c.entries, key)
	c.removeFromLRU(key)
	cacheSize.Set(float64(len(c.entries)))
	cacheMisses.WithLabelValues(module).Inc()
	return nil
}

// Set stores a result in the cache
func (c *DNSCache) Set(module, query, nameserver, result string) {
	if !c.enabled || c == nil {
		return
	}

	key := generateCacheKey(module, query, nameserver)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict
	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	entry := &CacheEntry{
		Key:        key,
		Result:     result,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(c.ttl),
		Module:     module,
		Query:      query,
		Nameserver: nameserver,
	}

	// If updating existing entry, remove from LRU first
	if _, exists := c.entries[key]; exists {
		c.removeFromLRU(key)
	}

	c.entries[key] = entry
	c.lruList = append(c.lruList, key)
	cacheSize.Set(float64(len(c.entries)))
}

// Delete removes an entry from the cache
func (c *DNSCache) Delete(module, query, nameserver string) {
	if !c.enabled || c == nil {
		return
	}

	key := generateCacheKey(module, query, nameserver)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; exists {
		delete(c.entries, key)
		c.removeFromLRU(key)
		cacheSize.Set(float64(len(c.entries)))
	}
}

// Clear removes all entries from the cache
func (c *DNSCache) Clear() {
	if !c.enabled || c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
	c.lruList = make([]string, 0, c.maxSize)
	cacheSize.Set(0)
}

// Size returns the current number of entries in the cache
func (c *DNSCache) Size() int {
	if !c.enabled || c == nil {
		return 0
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Stats returns cache statistics
func (c *DNSCache) Stats() CacheStats {
	if !c.enabled || c == nil {
		return CacheStats{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var fresh, stale, expired int

	for _, entry := range c.entries {
		if entry.IsExpired() {
			if entry.IsStale(c.staleTTL) {
				stale++
			} else {
				expired++
			}
		} else {
			fresh++
		}
	}

	return CacheStats{
		Size:     len(c.entries),
		Fresh:    fresh,
		Stale:    stale,
		Expired:  expired,
		MaxSize:  c.maxSize,
		TTL:      c.ttl,
		StaleTTL: c.staleTTL,
	}
}

// CacheStats holds cache statistics
type CacheStats struct {
	Size     int           `json:"size"`
	Fresh    int           `json:"fresh"`
	Stale    int           `json:"stale"`
	Expired  int           `json:"expired"`
	MaxSize  int           `json:"max_size"`
	TTL      time.Duration `json:"ttl"`
	StaleTTL time.Duration `json:"stale_ttl"`
}

// ToJSON returns cache stats as JSON
func (s CacheStats) ToJSON() string {
	data, _ := json.Marshal(s)
	return string(data)
}

// updateLRU moves the key to the end of the LRU list (most recently used)
func (c *DNSCache) updateLRU(key string) {
	c.removeFromLRU(key)
	c.lruList = append(c.lruList, key)
}

// removeFromLRU removes a key from the LRU list
func (c *DNSCache) removeFromLRU(key string) {
	for i, k := range c.lruList {
		if k == key {
			c.lruList = append(c.lruList[:i], c.lruList[i+1:]...)
			return
		}
	}
}

// evictLRU removes the least recently used entry
func (c *DNSCache) evictLRU() {
	if len(c.lruList) == 0 {
		return
	}

	// Remove oldest entry (first in list)
	oldestKey := c.lruList[0]
	delete(c.entries, oldestKey)
	c.lruList = c.lruList[1:]
	cacheEvictions.Inc()
}

// Cleanup removes expired entries from the cache
func (c *DNSCache) Cleanup() {
	if !c.enabled || c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var toDelete []string
	for key, entry := range c.entries {
		if entry.IsExpired() && !entry.IsStale(c.staleTTL) {
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		delete(c.entries, key)
		c.removeFromLRU(key)
	}

	if len(toDelete) > 0 {
		log.Debugf("Cleaned up %d expired cache entries", len(toDelete))
		cacheSize.Set(float64(len(c.entries)))
	}
}

// StartCleanup starts a background goroutine to periodically clean up expired entries
func (c *DNSCache) StartCleanup(interval time.Duration) chan<- struct{} {
	stop := make(chan struct{})

	if !c.enabled || c == nil {
		return stop
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.Cleanup()
			case <-stop:
				return
			}
		}
	}()

	return stop
}

// Global cache instance
var globalCache *DNSCache

// InitCache initializes the global DNS cache
func InitCache(enabled bool, maxSize int, ttl time.Duration) {
	globalCache = NewDNSCache(enabled, maxSize, ttl)
	if enabled {
		log.Infof("DNS cache initialized: max_size=%d, ttl=%v", maxSize, ttl)
		// Start cleanup every minute
		globalCache.StartCleanup(1 * time.Minute)
	} else {
		log.Info("DNS cache disabled")
	}
}

// GetCache returns the global cache instance
func GetCache() *DNSCache {
	return globalCache
}
