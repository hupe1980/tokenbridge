// Package tokenbridge provides functionality to interact with an authentication system.
// It allows verifying ID tokens, exchanging them for access tokens, and retrieving
// the JSON Web Key Set (JWKS) from the authorization server.
package tokenbridge

import (
	"context"
	"fmt"

	"github.com/hupe1980/tokenbridge/keyset"
)

// TokenBridge is the main struct that facilitates interaction between an OIDC (OpenID Connect)
// verifier and an authentication server. It provides methods to verify ID tokens, exchange them
// for access tokens, and retrieve the JWKS used to verify the tokens.
type TokenBridge struct {
	// oidcVerifier is responsible for verifying the authenticity and validity of ID tokens.
	oidcVerifier *OIDCVerifier

	// authServer is the server responsible for issuing access tokens and providing JWKS.
	authServer *AuthServer
}

// New creates and returns a new TokenBridge instance. This function initializes the
// TokenBridge with an OIDCVerifier and AuthServer to enable token exchange and verification.
func New(oidcVerifier *OIDCVerifier, authServer *AuthServer) *TokenBridge {
	return &TokenBridge{
		oidcVerifier: oidcVerifier,
		authServer:   authServer,
	}
}

// ExchangeToken exchanges a raw ID token for an access token. It first verifies the ID token using
// the OIDCVerifier, and then creates an access token using the AuthServer.
//
// Parameters:
// - ctx: The context for managing the request lifecycle.
// - rawIDToken: The raw ID token to be verified and exchanged.
//
// Returns:
// - The created access token string.
// - An error if there was an issue during the token exchange process.
func (tb *TokenBridge) ExchangeToken(ctx context.Context, rawIDToken string) (string, error) {
	// Verify the ID token using the OIDC verifier.
	idToken, err := tb.oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Create an access token using the authenticated ID token.
	accessToken, err := tb.authServer.CreateAccessToken(ctx, idToken)
	if err != nil {
		return "", fmt.Errorf("failed to create access token: %w", err)
	}

	return accessToken, nil
}

// GetJWKS retrieves the JSON Web Key Set (JWKS) from the AuthServer. This set of keys can be used
// to verify the signatures of tokens issued by the authorization server.
//
// Parameters:
// - ctx: The context for managing the request lifecycle.
//
// Returns:
// - A JWKS object containing the key set from the authentication server.
// - An error if there was an issue retrieving the JWKS.
func (tb *TokenBridge) GetJWKS(ctx context.Context) (*keyset.JWKS, error) {
	// Retrieve the JWKS from the AuthServer.
	jwks, err := tb.authServer.GetJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	return jwks, nil
}
