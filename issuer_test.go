package tokenbridge

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestTokenIssuerWithJWKS(t *testing.T) {
	secret := "top-secret"
	signer := NewHMAC256Signer(secret, "key-id")
	tokenIssuer := NewTokenIssuerWithJWKS("https://my-auth-server.org", signer)

	t.Run("IssueAccessToken_Success", func(t *testing.T) {
		idToken := &oidc.IDToken{
			Subject:  "user123",
			Issuer:   "https://issuer.example.com",
			Audience: []string{"client123"},
			Expiry:   time.Now().Add(time.Hour),
			IssuedAt: time.Now(),
		}

		accessToken, expiresIn, err := tokenIssuer.IssueAccessToken(context.Background(), idToken)
		assert.NoError(t, err, "IssueAccessToken should not return an error")
		assert.NotEmpty(t, accessToken, "Access token should not be empty")
		assert.NotEqual(t, 0, expiresIn, "ExpiresIn should not be zero")

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
		_, err := tokenIssuer.GetJWKS(context.Background())
		assert.Error(t, err, "GetJWKS should return an error for HMAC")
	})
}
