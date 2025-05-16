// Package tokenbridge provides functionality to interact with an authentication system.
// It allows verifying ID tokens, exchanging them for access tokens, and retrieving
// the JSON Web Key Set (JWKS) from the authorization server.
package tokenbridge

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Verifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

// TokenIssuer defines an interface for issuing access tokens.
type TokenIssuer interface {
	// IssueAccessToken generates an access token based on the provided ID token.
	IssueAccessToken(ctx context.Context, idToken *oidc.IDToken) (string, int64, error)
}

// TokenBridge is the main struct that facilitates interaction between an OIDC (OpenID Connect)
// verifier and a token issuer. It provides methods to verify ID tokens, exchange them
// for access tokens, and retrieve the JWKS used to verify the tokens.
type TokenBridge struct {
	// oidcVerifier is responsible for verifying the authenticity and validity of ID tokens.
	oidcVerifier Verifier

	// issuer is the TokenIssuer used for all token exchanges.
	issuer TokenIssuer
}

// New creates and returns a new TokenBridge instance. This function initializes the
// TokenBridge with an OIDCVerifier and a TokenIssuer to enable token exchange and verification.
func New(oidcVerifier Verifier, issuer TokenIssuer) *TokenBridge {
	return &TokenBridge{
		oidcVerifier: oidcVerifier,
		issuer:       issuer,
	}
}

// ExchangeTokenResult represents the result of an exchange token operation.
type ExchangeTokenResult struct {
	// AccessToken is the generated access token.
	AccessToken string `json:"access_token"`
	// ExpiresIn is the duration in seconds until the access token expires.
	ExpiresIn int64 `json:"expires_in"`
	// IssuedTokenType is the type of the issued token, as per RFC 8693.
	IssuedTokenType string `json:"issued_token_type"`
	// TokenType is the type of the token, typically "Bearer".
	TokenType string `json:"token_type"`
}

// ExchangeToken exchanges a raw ID token for an access token. It first verifies the ID token using
// the OIDCVerifier, and then creates an access token using the TokenIssuer.
//
// Parameters:
// - ctx: The context for managing the request lifecycle.
// - subjectToken: The raw ID token to be verified and exchanged.
//
// Returns:
// - An ExchangeTokenResult containing the access token and its expiration.
// - An error if there was an issue during the token exchange process.
func (tb *TokenBridge) ExchangeToken(ctx context.Context, subjectToken string) (*ExchangeTokenResult, error) {
	if tb.issuer == nil {
		return nil, fmt.Errorf("no TokenIssuer configured")
	}

	// Verify the ID token using the OIDC verifier.
	idToken, err := tb.oidcVerifier.Verify(ctx, subjectToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Create an access token using the authenticated ID token.
	accessToken, expiresIn, err := tb.issuer.IssueAccessToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to issue access token: %w", err)
	}

	return &ExchangeTokenResult{
		AccessToken:     accessToken,
		ExpiresIn:       expiresIn,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		TokenType:       "Bearer",
	}, nil
}
