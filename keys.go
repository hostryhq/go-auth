package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"
)

// KeySet resolves a key id to a public key from a local cache only. It must
// never fetch anything on behalf of a token (IC-01): a token cannot make the
// verifier go and look for a key.
type KeySet interface {
	// Key returns the key for kid, or an error carrying ReasonUnknownKey or
	// ReasonRevokedKey.
	Key(kid string) (*ecdsa.PublicKey, error)
}

// KeyDoc is what a loader returns: the published keys and the key ids that
// identity has revoked (ADR-0005 section 2, emergency rotation).
type KeyDoc struct {
	Keys    map[string]*ecdsa.PublicKey
	Revoked []string
}

// KeyLoader fetches the current key set, for example from identity's JWKS
// endpoint. It is called only by CachedKeySet.Refresh, on a timer or at start.
type KeyLoader interface {
	Load(ctx context.Context) (KeyDoc, error)
}

// StaticKeySet is a fixed key set (service key registry, tests, offline
// verifiers built from a pack).
type StaticKeySet struct {
	keys    map[string]*ecdsa.PublicKey
	revoked map[string]bool
}

// NewStaticKeySet copies doc.
func NewStaticKeySet(doc KeyDoc) *StaticKeySet {
	s := &StaticKeySet{keys: map[string]*ecdsa.PublicKey{}, revoked: map[string]bool{}}
	for k, v := range doc.Keys {
		s.keys[k] = v
	}
	for _, k := range doc.Revoked {
		s.revoked[k] = true
	}
	return s
}

// Keys returns a copy of the key map.
func (s *StaticKeySet) Keys() map[string]*ecdsa.PublicKey {
	out := make(map[string]*ecdsa.PublicKey, len(s.keys))
	for k, v := range s.keys {
		out[k] = v
	}
	return out
}

// Key implements KeySet.
func (s *StaticKeySet) Key(kid string) (*ecdsa.PublicKey, error) {
	return lookup(s.keys, s.revoked, kid)
}

func lookup(keys map[string]*ecdsa.PublicKey, revoked map[string]bool, kid string) (*ecdsa.PublicKey, error) {
	if revoked[kid] {
		return nil, refuse(ReasonRevokedKey)
	}
	k, ok := keys[kid]
	if !ok {
		return nil, refuse(ReasonUnknownKey)
	}
	return k, nil
}

// CachedKeySet holds the last good KeyDoc. Refresh replaces it; a failed
// refresh keeps the previous set, so a JWKS outage never stops verification.
type CachedKeySet struct {
	loader KeyLoader
	log    *slog.Logger
	mu     sync.RWMutex
	keys   map[string]*ecdsa.PublicKey
	rev    map[string]bool
}

// NewCachedKeySet returns an empty set; call Refresh before serving.
func NewCachedKeySet(l KeyLoader, log *slog.Logger) *CachedKeySet {
	if log == nil {
		log = slog.Default()
	}
	return &CachedKeySet{loader: l, log: log, keys: map[string]*ecdsa.PublicKey{}, rev: map[string]bool{}}
}

// Refresh loads the key set. Start-up should fail if the first Refresh fails.
func (c *CachedKeySet) Refresh(ctx context.Context) error {
	doc, err := c.loader.Load(ctx)
	if err != nil {
		return fmt.Errorf("auth: key refresh: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for kid, k := range doc.Keys {
		if k == nil || k.Curve != elliptic.P256() {
			return fmt.Errorf("auth: key %q is not a P-256 key", kid)
		}
		keys[kid] = k
	}
	rev := make(map[string]bool, len(doc.Revoked))
	for _, kid := range doc.Revoked {
		rev[kid] = true
	}
	c.mu.Lock()
	c.keys, c.rev = keys, rev
	c.mu.Unlock()
	return nil
}

// Run refreshes every interval until ctx ends. Errors are logged and the
// previous set stays in force.
func (c *CachedKeySet) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Refresh(ctx); err != nil {
				c.log.WarnContext(ctx, "key refresh failed; keeping previous key set", "error", err)
			}
		}
	}
}

// Key implements KeySet. It never calls the loader.
func (c *CachedKeySet) Key(kid string) (*ecdsa.PublicKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return lookup(c.keys, c.rev, kid)
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseJWKS reads a JWKS document of EC P-256 keys. Keys of any other type or
// curve are an error, not skipped: a silently ignored key hides a rotation bug.
func ParseJWKS(b []byte) (map[string]*ecdsa.PublicKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("auth: jwks: %w", err)
	}
	out := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			return nil, errors.New("auth: jwks: only EC P-256 keys with a kid are accepted")
		}
		x, errx := base64.RawURLEncoding.DecodeString(k.X)
		y, erry := base64.RawURLEncoding.DecodeString(k.Y)
		if errx != nil || erry != nil {
			return nil, errors.New("auth: jwks: bad coordinates")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if _, err := pub.ECDH(); err != nil { // validates the point is on the curve
			return nil, errors.New("auth: jwks: point not on curve")
		}
		out[k.Kid] = pub
	}
	return out, nil
}
