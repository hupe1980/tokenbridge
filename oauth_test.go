package tokenbridge

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestAuthServer(t *testing.T) {
	secret := "top-secret"
	signer := NewHMAC256Signer(secret, "key-id")
	authServer := NewAuthServer("https://my-auth-server.org", signer)

	t.Run("CreateAccessToken_Success", func(t *testing.T) {
		idToken := &oidc.IDToken{
			Subject:  "user123",
			Issuer:   "https://issuer.example.com",
			Audience: []string{"client123"},
			Expiry:   time.Now().Add(time.Hour),
			IssuedAt: time.Now(),
		}

		accessToken, err := authServer.CreateAccessToken(context.Background(), idToken)
		assert.NoError(t, err, "CreateAccessToken should not return an error")
		assert.NotEmpty(t, accessToken, "Access token should not be empty")

		// Verify the token
		parsedToken, err := jwt.Parse(accessToken, func(token *jwt.Token) (any, error) {
			// Ensure the signing method is HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}

			return []byte(secret), nil
		})

		assert.NoError(t, err, "Token verification should not return an error")
		assert.True(t, parsedToken.Valid, "Token should be valid")
	})

	t.Run("GetJWKS_Success", func(t *testing.T) {
		_, err := authServer.GetJWKS(context.Background())
		assert.Error(t, err, "GetJWKS should return an error for HMAC")
	})
}
