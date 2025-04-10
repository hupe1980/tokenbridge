package cache

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryCache(t *testing.T) {
	// Create a new memory cache instance
	c := NewMemoryCache()

	t.Run("Cache Operations", func(t *testing.T) {
		t.Run("Add and Get Key", func(t *testing.T) {
			// Generate a sample RSA public key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NoError(t, err, "Failed to generate RSA key")

			publicKey := privateKey.Public()

			// Add the public key to the cache
			keyID := "key1"
			c.Add(context.Background(), keyID, publicKey)

			// Retrieve the public key from the cache
			retrievedKey, found := c.Get(context.Background(), keyID)
			assert.True(t, found, "Expected key to be found in cache")
			assert.Equal(t, publicKey, retrievedKey, "Retrieved key should match the added key")
		})

		t.Run("Get Non-Existent Key", func(t *testing.T) {
			// Attempt to retrieve a key that doesn't exist
			retrievedKey, found := c.Get(context.Background(), "nonexistent")
			assert.False(t, found, "Expected key to not be found in cache")
			assert.Nil(t, retrievedKey, "Retrieved key should be nil for non-existent key")
		})

		t.Run("Overwrite Existing Key", func(t *testing.T) {
			// Generate a new RSA public key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NoError(t, err, "Failed to generate RSA key")

			newPublicKey := privateKey.Public()

			// Overwrite the existing key in the cache
			keyID := "key1"
			c.Add(context.Background(), keyID, newPublicKey)

			// Retrieve the updated key from the cache
			retrievedKey, found := c.Get(context.Background(), keyID)
			assert.True(t, found, "Expected key to be found in cache")
			assert.Equal(t, newPublicKey, retrievedKey, "Retrieved key should match the updated key")
		})
	})
}

func TestNoopCache(t *testing.T) {
	// Create a new noop cache instance
	c := NewNoopCache()

	t.Run("Noop Cache Operations", func(t *testing.T) {
		t.Run("Add Key Does Nothing", func(t *testing.T) {
			// Generate a sample RSA public key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NoError(t, err, "Failed to generate RSA key")

			publicKey := privateKey.Public()

			// Attempt to add the public key to the noop cache
			keyID := "key1"
			c.Add(context.Background(), keyID, publicKey)

			// Attempt to retrieve the key from the noop cache
			retrievedKey, found := c.Get(context.Background(), keyID)
			assert.False(t, found, "Expected key to not be found in noop cache")
			assert.Nil(t, retrievedKey, "Retrieved key should be nil for noop cache")
		})

		t.Run("Get Non-Existent Key Always Fails", func(t *testing.T) {
			// Attempt to retrieve a key that doesn't exist
			retrievedKey, found := c.Get(context.Background(), "nonexistent")
			assert.False(t, found, "Expected key to not be found in noop cache")
			assert.Nil(t, retrievedKey, "Retrieved key should be nil for non-existent key in noop cache")
		})
	})
}
