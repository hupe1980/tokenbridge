package tokenbridge

import (
	"context"
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
