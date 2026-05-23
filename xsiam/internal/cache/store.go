package cache

import (
	"encoding/json"
	"strings"

	"github.com/dgraph-io/ristretto"
)

// Store wraps a Ristretto cache with typed helpers.
type Store struct {
	c *ristretto.Cache
}

// New creates a Store backed by a 128 MB Ristretto cache.
func New() (*Store, error) {
	c, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,       // track 10 million keys for admission policy
		MaxCost:     128 << 20, // 128 MB
		BufferItems: 64,
	})
	if err != nil {
		return nil, err
	}
	return &Store{c: c}, nil
}

// Set serializes val as JSON and stores it under key with the given cost.
// cost is in bytes; pass 0 to let ristretto estimate from value size.
func Set[T any](s *Store, key string, val T, cost int64) bool {
	b, err := json.Marshal(val)
	if err != nil {
		return false
	}
	if cost == 0 {
		cost = int64(len(b))
	}
	return s.c.Set(key, b, cost)
}

// Get deserializes the cached JSON into T. Returns (zero, false) on miss.
func Get[T any](s *Store, key string) (T, bool) {
	var zero T
	raw, ok := s.c.Get(key)
	if !ok {
		return zero, false
	}
	b, ok := raw.([]byte)
	if !ok {
		return zero, false
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return zero, false
	}
	return v, true
}

// Del removes a single key.
func (s *Store) Del(key string) {
	s.c.Del(key)
}

// DelPrefix is a best-effort prefix invalidation hint.
// Ristretto does not support prefix iteration; callers should embed version
// counters into cache keys and increment them to invalidate prefix ranges.
func (s *Store) DelPrefix(prefix string) {
	_ = prefix
}

// HasPrefix reports whether key starts with prefix.
func HasPrefix(key, prefix string) bool {
	return strings.HasPrefix(key, prefix)
}

// Close shuts down the cache and releases resources.
func (s *Store) Close() {
	s.c.Close()
}
