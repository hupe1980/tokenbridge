package cache

import (
	"context"
	"crypto"
	"sync"
)

// Cache defines the interface for a thread-safe cache that stores public keys.
type Cache interface {
	// Add inserts a public key into the cache with the specified key ID.
	Add(ctx context.Context, keyID string, key crypto.PublicKey)

	// Get retrieves a public key from the cache by its key ID.
	// Returns nil if the key is not found.
	Get(ctx context.Context, keyID string) (crypto.PublicKey, bool)
}

// memoryCache is a thread-safe implementation of the Cache interface.
type memoryCache struct {
	pubKeys map[string]crypto.PublicKey
	mutex   sync.RWMutex
}

// NewMemoryCache creates a new instance of the memory cache.
func NewMemoryCache() Cache {
	return &memoryCache{
		pubKeys: make(map[string]crypto.PublicKey),
	}
}

// Add inserts a public key into the cache with the specified key ID.
func (m *memoryCache) Add(_ context.Context, keyID string, key crypto.PublicKey) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.pubKeys[keyID] = key
}

// Get retrieves a public key from the cache by its key ID.
// Returns the public key and a boolean indicating whether the key was found.
func (m *memoryCache) Get(_ context.Context, keyID string) (crypto.PublicKey, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	key, exists := m.pubKeys[keyID]

	return key, exists
}

// noopCache is a no-operation implementation of the Cache interface.
// It does not store or retrieve any keys.
type noopCache struct{}

// NewNoopCache creates a new instance of the noop cache.
func NewNoopCache() Cache {
	return &noopCache{}
}

// Add is a no-op. It does nothing.
func (n *noopCache) Add(_ context.Context, _ string, _ crypto.PublicKey) {
	// No operation
}

// Get always returns nil and false, indicating that no key is found.
func (n *noopCache) Get(_ context.Context, _ string) (crypto.PublicKey, bool) {
	return nil, false
}
