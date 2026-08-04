// Package memory provides an in-process implementation of cache.Client.
// It is intended for unit tests, `make dev`, and any deployment that does
// not need cross-instance coordination. It is NOT a drop-in replacement
// for Redis in production — pub/sub and atomic script execution are
// serialized through a single mutex and therefore do not scale.
package memory

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-signal/pkg/cache"
)

// Client is an in-memory cache.Client. The zero value is not usable; call
// New.
type Client struct {
	mu       sync.Mutex
	data     map[string]*entry
	subs     map[string][]chan cache.Message // channel → subscribers
	subCount int64                           // monotonic subscription ID generator
	closed   bool
}

// entry holds a single key's value. Only one of string, sorted-set, or
// hash is populated at a time; trying to use the same key as two kinds
// returns an error, matching Redis's WRONGTYPE behavior.
type entry struct {
	expiresAt time.Time // zero = no expiration
	str       []byte
	zset      []zmember // kept sorted by score, then member
	hash      map[string][]byte
}

type zmember struct {
	score  float64
	member []byte
}

// New returns a ready-to-use in-memory cache client.
func New() *Client {
	return &Client{
		data: make(map[string]*entry),
		subs: make(map[string][]chan cache.Message),
	}
}

// Compile-time interface check.
var _ cache.Client = (*Client)(nil)

// --- Helpers -----------------------------------------------------------

func (c *Client) ensureOpen() error {
	if c.closed {
		return errors.New("cache: client closed")
	}
	return nil
}

// getLive returns the entry at key if it exists and has not expired. It
// transparently removes expired entries as a side effect. Callers must
// hold c.mu.
func (c *Client) getLive(key string) *entry {
	e, ok := c.data[key]
	if !ok {
		return nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		delete(c.data, key)
		return nil
	}
	return e
}

// wrongType returns a human-readable WRONGTYPE-style error.
func wrongType(key, want, got string) error {
	return signalerrors.New(signalerrors.ErrInvalidArgument, "cache: key "+strconv.Quote(key)+" has type "+got+", expected "+want)
}

func kindOf(e *entry) string {
	switch {
	case e.str != nil:
		return "string"
	case e.zset != nil:
		return "zset"
	case e.hash != nil:
		return "hash"
	}
	return "empty"
}

// --- Keyed values -----------------------------------------------------

// Set stores a string value with optional TTL.
func (c *Client) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return err
	}
	cp := make([]byte, len(value))
	copy(cp, value)

	e := &entry{str: cp}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	}
	c.data[key] = e
	return nil
}

// Get retrieves a string value.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	e := c.getLive(key)
	if e == nil {
		return nil, cache.ErrKeyNotFound
	}
	if e.str == nil {
		return nil, wrongType(key, "string", kindOf(e))
	}
	cp := make([]byte, len(e.str))
	copy(cp, e.str)
	return cp, nil
}

// Del removes one or more keys.
func (c *Client) Del(ctx context.Context, keys ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return err
	}
	for _, k := range keys {
		delete(c.data, k)
	}
	return nil
}

// Exists reports presence.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return false, err
	}
	return c.getLive(key) != nil, nil
}

// Expire updates a key's TTL.
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return false, err
	}
	e := c.getLive(key)
	if e == nil {
		return false, nil
	}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	} else {
		e.expiresAt = time.Time{}
	}
	return true, nil
}

// TTL returns the remaining TTL.
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return 0, err
	}
	e := c.getLive(key)
	if e == nil || e.expiresAt.IsZero() {
		return 0, nil
	}
	return time.Until(e.expiresAt), nil
}

// --- Counters ---------------------------------------------------------

// Incr atomically increments by 1.
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.IncrBy(ctx, key, 1)
}

// IncrBy atomically increments by delta. The value is stored as a decimal
// string, matching Redis's INCRBY semantics.
func (c *Client) IncrBy(ctx context.Context, key string, delta int64) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return 0, err
	}

	var current int64
	e := c.getLive(key)
	if e != nil {
		if e.str == nil {
			return 0, wrongType(key, "string", kindOf(e))
		}
		n, err := strconv.ParseInt(string(e.str), 10, 64)
		if err != nil {
			return 0, signalerrors.New(signalerrors.ErrInvalidArgument, "cache: value at "+strconv.Quote(key)+" is not an integer")
		}
		current = n
	}
	current += delta
	if e == nil {
		e = &entry{}
		c.data[key] = e
	}
	e.str = []byte(strconv.FormatInt(current, 10))
	return current, nil
}

// --- Distributed locks ------------------------------------------------

// Lock is the SET NX EX primitive.
func (c *Client) Lock(ctx context.Context, key, token string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return err
	}
	if c.getLive(key) != nil {
		return cache.ErrLockNotAcquired
	}
	e := &entry{str: []byte(token)}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
	}
	c.data[key] = e
	return nil
}

// Unlock releases a lock if and only if the value matches the token.
func (c *Client) Unlock(ctx context.Context, key, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return err
	}
	e := c.getLive(key)
	if e == nil || e.str == nil {
		return nil
	}
	if string(e.str) == token {
		delete(c.data, key)
	}
	return nil
}

// --- Sorted sets ------------------------------------------------------

// ZAdd inserts scored members into a sorted set.
func (c *Client) ZAdd(ctx context.Context, key string, members ...cache.ScoredMember) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return err
	}

	e := c.data[key]
	if e != nil && !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		delete(c.data, key)
		e = nil
	}
	if e == nil {
		e = &entry{zset: []zmember{}}
		c.data[key] = e
	} else if e.zset == nil {
		return wrongType(key, "zset", kindOf(e))
	}

	for _, m := range members {
		// Remove any existing member with the same bytes (Redis ZADD
		// updates score on duplicate member).
		filtered := e.zset[:0]
		for _, existing := range e.zset {
			if !bytesEqual(existing.member, m.Member) {
				filtered = append(filtered, existing)
			}
		}
		e.zset = filtered
		cp := make([]byte, len(m.Member))
		copy(cp, m.Member)
		e.zset = append(e.zset, zmember{score: m.Score, member: cp})
	}
	sortZSet(e.zset)
	return nil
}

// ZRange returns members in [start, stop] by ascending score.
func (c *Client) ZRange(ctx context.Context, key string, start, stop int64) ([][]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	e := c.getLive(key)
	if e == nil {
		return [][]byte{}, nil
	}
	if e.zset == nil {
		return nil, wrongType(key, "zset", kindOf(e))
	}

	n := int64(len(e.zset))
	if start < 0 {
		start = n + start
	}
	if stop < 0 {
		stop = n + stop
	}
	if start < 0 {
		start = 0
	}
	if stop >= n {
		stop = n - 1
	}
	if start > stop || start >= n {
		return [][]byte{}, nil
	}
	out := make([][]byte, 0, stop-start+1)
	for i := start; i <= stop; i++ {
		cp := make([]byte, len(e.zset[i].member))
		copy(cp, e.zset[i].member)
		out = append(out, cp)
	}
	return out, nil
}

// ZRem removes members from a sorted set.
func (c *Client) ZRem(ctx context.Context, key string, members ...[]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return err
	}
	e := c.getLive(key)
	if e == nil {
		return nil
	}
	if e.zset == nil {
		return wrongType(key, "zset", kindOf(e))
	}
	filtered := e.zset[:0]
outer:
	for _, existing := range e.zset {
		for _, m := range members {
			if bytesEqual(existing.member, m) {
				continue outer
			}
		}
		filtered = append(filtered, existing)
	}
	e.zset = filtered
	if len(e.zset) == 0 {
		delete(c.data, key)
	}
	return nil
}

// ZCard returns the cardinality of the sorted set at key.
func (c *Client) ZCard(ctx context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return 0, err
	}
	e := c.getLive(key)
	if e == nil {
		return 0, nil
	}
	if e.zset == nil {
		return 0, wrongType(key, "zset", kindOf(e))
	}
	return int64(len(e.zset)), nil
}

// --- Hashes -----------------------------------------------------------

// HSet sets a hash field.
func (c *Client) HSet(ctx context.Context, key, field string, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return err
	}
	e := c.data[key]
	if e != nil && !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		delete(c.data, key)
		e = nil
	}
	if e == nil {
		e = &entry{hash: make(map[string][]byte)}
		c.data[key] = e
	} else if e.hash == nil {
		return wrongType(key, "hash", kindOf(e))
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	e.hash[field] = cp
	return nil
}

// HGet retrieves a hash field.
func (c *Client) HGet(ctx context.Context, key, field string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	e := c.getLive(key)
	if e == nil {
		return nil, cache.ErrKeyNotFound
	}
	if e.hash == nil {
		return nil, wrongType(key, "hash", kindOf(e))
	}
	v, ok := e.hash[field]
	if !ok {
		return nil, cache.ErrKeyNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

// HDel removes one or more hash fields.
func (c *Client) HDel(ctx context.Context, key string, fields ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return err
	}
	e := c.getLive(key)
	if e == nil {
		return nil
	}
	if e.hash == nil {
		return wrongType(key, "hash", kindOf(e))
	}
	for _, f := range fields {
		delete(e.hash, f)
	}
	if len(e.hash) == 0 {
		delete(c.data, key)
	}
	return nil
}

// HLen returns the number of fields in the hash at key.
func (c *Client) HLen(ctx context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return 0, err
	}
	e := c.getLive(key)
	if e == nil {
		return 0, nil
	}
	if e.hash == nil {
		return 0, wrongType(key, "hash", kindOf(e))
	}
	return int64(len(e.hash)), nil
}

// --- Pub/sub ----------------------------------------------------------

// Publish broadcasts a message to all subscribers of channel. The send is
// non-blocking (drops on a full buffer, matching Redis's best-effort pub/sub
// semantics), so holding the client mutex through the send loop cannot
// deadlock and is required to serialize against subscription.Close, which
// closes the underlying channels under the same mutex.
func (c *Client) Publish(ctx context.Context, channel string, message []byte) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return 0, err
	}

	delivered := int64(0)
	for _, sub := range c.subs[channel] {
		cp := make([]byte, len(message))
		copy(cp, message)
		select {
		case sub <- cache.Message{Channel: channel, Payload: cp}:
			delivered++
		default:
		}
	}
	return delivered, nil
}

// Subscribe returns a Subscription that delivers published messages.
func (c *Client) Subscribe(ctx context.Context, channels ...string) (cache.Subscription, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	ch := make(chan cache.Message, 64)
	for _, name := range channels {
		c.subs[name] = append(c.subs[name], ch)
	}
	c.subCount++
	return &subscription{
		client:   c,
		channels: append([]string(nil), channels...),
		ch:       ch,
	}, nil
}

type subscription struct {
	client   *Client
	channels []string
	ch       chan cache.Message
	closed   bool
}

func (s *subscription) Channel() <-chan cache.Message { return s.ch }

func (s *subscription) Close() error {
	s.client.mu.Lock()
	defer s.client.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, name := range s.channels {
		slice := s.client.subs[name]
		filtered := slice[:0]
		for _, existing := range slice {
			if existing != s.ch {
				filtered = append(filtered, existing)
			}
		}
		if len(filtered) == 0 {
			delete(s.client.subs, name)
		} else {
			s.client.subs[name] = filtered
		}
	}
	close(s.ch)
	return nil
}

// --- Scripts ----------------------------------------------------------

// Eval runs a Lua script. The in-memory client does not execute Lua; this
// is a stub meant to keep tests that exercise the interface compiling. A
// real Lua runtime would be significant scope; callers that need actual
// Lua semantics must use the redis backend.
func (c *Client) Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error) {
	return nil, errors.New("cache/memory: Eval not supported; use the redis backend")
}

// --- Lifecycle --------------------------------------------------------

// Ping is a no-op on the memory backend.
func (c *Client) Ping(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureOpen()
}

// Close marks the client closed. Subsequent operations return an error.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, subs := range c.subs {
		for _, ch := range subs {
			close(ch)
		}
	}
	c.subs = nil
	return nil
}

// sortZSet sorts a zset by (score, member bytes) lexicographic order.
func sortZSet(z []zmember) {
	sort.Slice(z, func(i, j int) bool {
		if z[i].score != z[j].score {
			return z[i].score < z[j].score
		}
		return string(z[i].member) < string(z[j].member)
	})
}

// bytesEqual is a small local helper to avoid a bytes import loop when
// future dependencies change.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
