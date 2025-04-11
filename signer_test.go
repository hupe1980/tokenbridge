package tokenbridge

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestHMACSigner(t *testing.T) {
	secret := "my-secret-key"
	keyID := "hmac-key-id"
	hmacSigner := NewHMAC256Signer(secret, keyID)

	t.Run("SignToken", func(t *testing.T) {
		// Create a JWT token
		token := jwt.NewWithClaims(hmacSigner.SigningMethod(), jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(), // Token expires in 1 hour
		})

		// Add the Key ID (kid) to the token header
		token.Header["kid"] = hmacSigner.KeyID()

		// Sign the token
		tokenString, err := hmacSigner.SignToken(context.Background(), token)
		assert.NoError(t, err, "SignToken should not return an error")
		assert.NotEmpty(t, tokenString, "Signed token should not be empty")

		// Verify the token
		parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			// Ensure the signing method is HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}

			return []byte(secret), nil
		})

		assert.NoError(t, err, "Token verification should not return an error")
		assert.True(t, parsedToken.Valid, "Token should be valid")
	})

	t.Run("GetJWKS", func(t *testing.T) {
		// Retrieve the JWKS
		_, err := hmacSigner.GetJWKS(context.Background())
		assert.Error(t, err, "GetJWKS should return an error for HMAC")
	})

	t.Run("SigningMethod", func(t *testing.T) {
		// Ensure the correct signing method is returned
		signingMethod := hmacSigner.SigningMethod()
		assert.Equal(t, jwt.SigningMethodHS256, signingMethod, "Signing method should be HS256")
	})

	t.Run("KeyID", func(t *testing.T) {
		// Ensure the correct key ID is returned
		assert.Equal(t, keyID, hmacSigner.KeyID(), "KeyID should match the configured key ID")
	})
}

func TestECSignerWithRotatedKeys(t *testing.T) {
	// Generate EC private keys for testing
	privateKey, err := generateECPrivateKey() // Replace with a helper function to generate an EC private key
	assert.NoError(t, err, "Failed to generate EC private key")
	assert.NotNil(t, privateKey, "Private key should not be nil")

	rotatedKey1, err := generateECPrivateKey()
	assert.NoError(t, err, "Failed to generate EC rotated key 1")
	assert.NotNil(t, rotatedKey1, "Rotated key 1 should not be nil")

	rotatedKey2, err := generateECPrivateKey()
	assert.NoError(t, err, "Failed to generate EC rotated key 2")
	assert.NotNil(t, rotatedKey2, "Rotated key 2 should not be nil")

	// Create an EC signer with rotated keys
	signer := NewEC256Signer(privateKey, "active-key-id", func(opts *ECSignerOptions) {
		opts.RotatedKeys = []RotatedECDAKey{
			{
				KeyID:     "rotated-key-id-1",
				PublicKey: &rotatedKey1.PublicKey,
			},
			{
				KeyID:     "rotated-key-id-2",
				PublicKey: &rotatedKey2.PublicKey,
			},
		}
	})

	t.Run("GetJWKS_IncludesRotatedKeys", func(t *testing.T) {
		// Retrieve the JWKS
		jwks, err := signer.GetJWKS(context.Background())
		assert.NoError(t, err, "GetJWKS should not return an error")

		// Ensure the JWKS contains the active key and rotated keys
		assert.Len(t, jwks.Keys, 3, "JWKS should contain 3 keys (1 active + 2 rotated)")

		// Check the active key
		activeKey := jwks.Keys[0]
		assert.Equal(t, "active-key-id", activeKey.Kid, "Active key ID should match")

		// Check the rotated keys
		rotatedKey1 := jwks.Keys[1]
		assert.Equal(t, "rotated-key-id-1", rotatedKey1.Kid, "First rotated key ID should match")

		rotatedKey2 := jwks.Keys[2]
		assert.Equal(t, "rotated-key-id-2", rotatedKey2.Kid, "Second rotated key ID should match")
	})

	t.Run("VerifyTokenWithRotatedKey", func(t *testing.T) {
		// Create a JWT token signed with the first rotated key
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		token.Header["kid"] = "rotated-key-id-1"

		// Sign the token with the first rotated key
		tokenString, err := token.SignedString(rotatedKey1)
		assert.NoError(t, err, "Signing with rotated key should not return an error")

		// Verify the token using the JWKS
		jwks, _ := signer.GetJWKS(context.Background())
		parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			for _, key := range jwks.Keys {
				if key.Kid == token.Header["kid"] {
					return parseECDSAPublicKey(key)
				}
			}

			return nil, fmt.Errorf("key not found")
		})

		assert.NoError(t, err, "Token verification should not return an error")
		assert.True(t, parsedToken.Valid, "Token should be valid")
	})
}

// Helper function to generate an EC private key
func generateECPrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC private key: %w", err)
	}

	return privateKey, nil
}

// Helper function to parse an EC public key from a JWK
func parseECDSAPublicKey(jwk JWK) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	// Use crypto/ecdh for safer on-curve checks
	ecdhCurve := ecdh.P256()

	// Construct the public key bytes in the format expected by crypto/ecdh
	publicKeyBytes := append([]byte{0x04}, append(xBytes, yBytes...)...) // Uncompressed point format

	// Validate the public key
	_, err = ecdhCurve.NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid EC public key: %w", err)
	}

	// Return the parsed ECDSA public key
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(), // Adjust based on the curve in the JWK
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
