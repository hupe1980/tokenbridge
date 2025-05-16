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

func (m *MockTokenIssuer) IssueAccessToken(_ context.Context, _ *oidc.IDToken) (string, int64, error) {
	return m.accessToken, 300, nil
}

func TestTokenBridge(t *testing.T) {
	t.Run("ExchangeToken_Success", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		mockIssuer := &MockTokenIssuer{accessToken: "mock-access-token"}

		tokenBridge := New(oidcVerifier, mockIssuer)

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

		result, err := tokenBridge.ExchangeToken(context.Background(), "raw-id-token")
		assert.NoError(t, err, "ExchangeToken should not return an error")
		assert.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "mock-access-token", result.AccessToken, "Expected mock-access-token to be returned")
		assert.Equal(t, int64(300), result.ExpiresIn)
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", result.IssuedTokenType)
		assert.Equal(t, "Bearer", result.TokenType)
	})

	t.Run("ExchangeToken_NoIssuer", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		tokenBridge := New(oidcVerifier, nil)

		result, err := tokenBridge.ExchangeToken(context.Background(), "raw-id-token")
		assert.Error(t, err, "ExchangeToken should return an error if no issuer is configured")
		assert.Nil(t, result, "Result should be nil when no issuer is configured")
	})

	t.Run("ExchangeToken_VerifyFail", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation
		mockIssuer := &MockTokenIssuer{accessToken: "mock-access-token"}

		tokenBridge := New(oidcVerifier, mockIssuer)

		tokenBridge.oidcVerifier = &MockOIDCVerifier{
			VerifyFunc: func(_ context.Context, _ string) (*oidc.IDToken, error) {
				return nil, assert.AnError
			},
		}

		result, err := tokenBridge.ExchangeToken(context.Background(), "raw-id-token")
		assert.Error(t, err, "ExchangeToken should return an error if verification fails")
		assert.Nil(t, result, "Result should be nil when verification fails")
	})

	t.Run("ExchangeToken_IssueFail", func(t *testing.T) {
		oidcVerifier := &OIDCVerifier{} // Mock or stub implementation

		mockIssuer := &MockTokenIssuer{accessToken: "mock-access-token"}
		tokenBridge := New(oidcVerifier, mockIssuer)

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

		// Override IssueAccessToken to return an error
		tokenBridge.issuer = &struct{ MockTokenIssuer }{
			MockTokenIssuer{accessToken: "mock-access-token"},
		}
		tokenBridge.issuer = &errorIssuer{}

		result, err := tokenBridge.ExchangeToken(context.Background(), "raw-id-token")
		assert.Error(t, err, "ExchangeToken should return an error if issuing fails")
		assert.Nil(t, result, "Result should be nil when issuing fails")
	})
}

// errorIssuer always returns an error for IssueAccessToken
type errorIssuer struct{}

func (e *errorIssuer) IssueAccessToken(_ context.Context, _ *oidc.IDToken) (string, int64, error) {
	return "", 0, assert.AnError
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
