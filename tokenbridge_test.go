package tokenbridge

import (
	"context"
	"reflect"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
)

type MockTokenIssuer struct {
	accessToken string
}

func (m *MockTokenIssuer) IssueAccessToken(_ context.Context, _ *oidc.IDToken) (string, error) {
	return m.accessToken, nil
}

func TestTokenBridge(t *testing.T) {
	t.Run("AddRoute_Success", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		tokenBridge := New(oidcVerifier)

		mockIssuer1 := &MockTokenIssuer{accessToken: "mock-access-token-1"}

		err := tokenBridge.AddRoute(map[string]string{
			"role": "admin",
			"org":  "example-org",
		}, mockIssuer1)
		assert.NoError(t, err, "AddRoute should not return an error")
	})

	t.Run("AddRoute_InvalidRegex", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		tokenBridge := New(oidcVerifier)

		mockIssuer1 := &MockTokenIssuer{accessToken: "mock-access-token-1"}

		err := tokenBridge.AddRoute(map[string]string{
			"role": "[invalid-regex",
		}, mockIssuer1)
		assert.Error(t, err, "AddRoute should return an error for invalid regex")
	})

	t.Run("MatchRoute_Success", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		tokenBridge := New(oidcVerifier)

		mockIssuer1 := &MockTokenIssuer{accessToken: "mock-access-token-1"}
		mockIssuer2 := &MockTokenIssuer{accessToken: "mock-access-token-2"}

		// Add routes
		_ = tokenBridge.AddRoute(map[string]string{
			"role": "admin",
			"org":  "example-org",
		}, mockIssuer1)

		_ = tokenBridge.AddRoute(map[string]string{
			"role": "user",
			"org":  ".*",
		}, mockIssuer2)

		// Test matching claims
		claims := map[string]any{
			"role": "admin",
			"org":  "example-org",
		}

		issuer, err := tokenBridge.matchRoute(claims)
		assert.NoError(t, err, "matchRoute should not return an error")
		assert.Equal(t, mockIssuer1, issuer, "Expected mockIssuer1 to be returned")
	})

	t.Run("MatchRoute_NoMatch", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		tokenBridge := New(oidcVerifier)

		claims := map[string]any{
			"role": "guest",
			"org":  "unknown-org",
		}

		issuer, err := tokenBridge.matchRoute(claims)
		assert.Error(t, err, "matchRoute should return an error for no matching route")
		assert.Nil(t, issuer, "Issuer should be nil when no route matches")
	})

	t.Run("ExchangeToken_Success", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		tokenBridge := New(oidcVerifier)

		mockIssuer1 := &MockTokenIssuer{accessToken: "mock-access-token-1"}
		mockIssuer2 := &MockTokenIssuer{accessToken: "mock-access-token-2"}

		// Mock OIDCVerifier
		tokenBridge.oidcVerifier = &MockOIDCVerifier{
			VerifyFunc: func(_ context.Context, _ string) (*oidc.IDToken, error) {
				idToken := &oidc.IDToken{
					Subject: "user123",
					Issuer:  "https://issuer.example.com",
				}

				setIDTokenClaims(idToken, []byte(`{"role":"admin","org":"example-org"}`))

				return idToken, nil
			},
		}

		// Add a route
		_ = tokenBridge.AddRoute(map[string]string{
			"role": "guest",
			"org":  "example-org",
		}, mockIssuer1)

		_ = tokenBridge.AddRoute(map[string]string{
			"role": "admin",
			"org":  "example-org",
		}, mockIssuer2)

		// Exchange token
		accessToken, err := tokenBridge.ExchangeToken(context.Background(), "raw-id-token")
		assert.NoError(t, err, "ExchangeToken should not return an error")
		assert.Equal(t, "mock-access-token-2", accessToken, "Expected mock-access-token to be returned")
	})

	t.Run("ExchangeToken_NoMatchingRoute", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		tokenBridge := New(oidcVerifier)

		// Mock OIDCVerifier
		tokenBridge.oidcVerifier = &MockOIDCVerifier{
			VerifyFunc: func(_ context.Context, _ string) (*oidc.IDToken, error) {
				idToken := &oidc.IDToken{
					Subject: "user123",
					Issuer:  "https://issuer.example.com",
				}

				setIDTokenClaims(idToken, []byte(`{"role":"guest","org":"unknown-org"}`))

				return idToken, nil
			},
		}

		// Exchange token
		accessToken, err := tokenBridge.ExchangeToken(context.Background(), "raw-id-token")
		assert.Error(t, err, "ExchangeToken should return an error for no matching route")
		assert.Empty(t, accessToken, "Access token should be empty when no route matches")
	})
}

// MockOIDCVerifier is a mock implementation of the OIDCVerifier.
type MockOIDCVerifier struct {
	VerifyFunc func(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

func (m *MockOIDCVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return m.VerifyFunc(ctx, rawIDToken)
}

// hack because the claims field is unexported
// see https://github.com/coreos/go-oidc/pull/329
func setIDTokenClaims(idToken *oidc.IDToken, claims []byte) {
	pointerVal := reflect.ValueOf(idToken)
	val := reflect.Indirect(pointerVal)
	member := val.FieldByName("claims")
	ptr := unsafe.Pointer(member.UnsafeAddr())
	realPtr := (*[]byte)(ptr)
	*realPtr = claims
}
