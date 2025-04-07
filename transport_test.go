package tokenbridge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateThumbprint(t *testing.T) {
	t.Run("Thumbprint Calculation", func(t *testing.T) {
		t.Run("RSA Key", func(t *testing.T) {
			// Generate an RSA public key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NoError(t, err, "Failed to generate RSA key")

			// Calculate the thumbprint using the function
			thumbprint, err := calculateThumbprint(&privateKey.PublicKey)
			assert.NoError(t, err, "Failed to calculate thumbprint for RSA key")
			assert.NotEmpty(t, thumbprint, "Thumbprint should not be empty")

			// Manually calculate the expected thumbprint
			expectedJWK := map[string]string{
				"n": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
				"e": "AQAB", // Default exponent for RSA keys
			}
			expectedJWKBytes, err := json.Marshal(expectedJWK)
			assert.NoError(t, err, "Failed to marshal expected JWK")

			expectedHash := sha256.Sum256(expectedJWKBytes)
			expectedThumbprint := base64.RawURLEncoding.EncodeToString(expectedHash[:])

			// Compare the calculated thumbprint with the expected thumbprint
			assert.Equal(t, expectedThumbprint, thumbprint, "Thumbprint should match the expected value")
		})

		t.Run("EC Key", func(t *testing.T) {
			// Generate an EC public key
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			assert.NoError(t, err, "Failed to generate EC key")

			// Calculate the thumbprint using the function
			thumbprint, err := calculateThumbprint(&privateKey.PublicKey)
			assert.NoError(t, err, "Failed to calculate thumbprint for EC key")
			assert.NotEmpty(t, thumbprint, "Thumbprint should not be empty")

			// Manually calculate the expected thumbprint
			expectedJWK := map[string]string{
				"x": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
				"y": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
			}
			expectedJWKBytes, err := json.Marshal(expectedJWK)
			assert.NoError(t, err, "Failed to marshal expected JWK")

			expectedHash := sha256.Sum256(expectedJWKBytes)
			expectedThumbprint := base64.RawURLEncoding.EncodeToString(expectedHash[:])

			// Compare the calculated thumbprint with the expected thumbprint
			assert.Equal(t, expectedThumbprint, thumbprint, "Thumbprint should match the expected value")
		})

		t.Run("Unsupported Key Type", func(t *testing.T) {
			// Pass an unsupported key type
			_, err := calculateThumbprint("unsupported-key")
			assert.Error(t, err, "Expected an error for unsupported key type")
		})
	})
}
