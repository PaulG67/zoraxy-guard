package main

import (
	"sync"
	"time"
)

// captureStore bridges the two-step dynamic-capture protocol: the sniff
// handler decides *whether* to block and stores that decision here; the
// capture (ingress) handler that Zoraxy calls right after picks it up by
// request UUID and writes the actual response.
type captureStore struct {
	mu      sync.Mutex
	pending map[string]capturedDecision
}

type capturedDecision struct {
	rule    PathRule
	created time.Time
}

const captureTTL = 15 * time.Second

func newCaptureStore() *captureStore {
	return &captureStore{pending: make(map[string]capturedDecision)}
}

func (c *captureStore) put(requestID string, rule PathRule) {
	if requestID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[requestID] = capturedDecision{rule: rule, created: time.Now()}
	c.gcLocked()
}

func (c *captureStore) take(requestID string) (PathRule, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dec, ok := c.pending[requestID]
	if ok {
		delete(c.pending, requestID)
	}
	if !ok || time.Since(dec.created) > captureTTL {
		return PathRule{}, false
	}
	return dec.rule, true
}

// gcLocked drops stale entries so a plugin under load never accumulates
// unbounded memory if a capture ingress call never arrives.
func (c *captureStore) gcLocked() {
	if len(c.pending) < 512 {
		return
	}
	cutoff := time.Now().Add(-captureTTL)
	for k, v := range c.pending {
		if v.created.Before(cutoff) {
			delete(c.pending, k)
		}
	}
}
