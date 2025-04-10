// Package tokenbridge provides functionality to interact with an authentication system.
// It allows verifying ID tokens, exchanging them for access tokens, and retrieving
// the JSON Web Key Set (JWKS) from the authorization server.
package tokenbridge

import (
	"context"
	"fmt"
	"regexp"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Verifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

// TokenIssuer defines an interface for issuing access tokens.
type TokenIssuer interface {
	// IssueAccessToken generates an access token based on the provided ID token.
	IssueAccessToken(ctx context.Context, idToken *oidc.IDToken) (string, error)
}

type route struct {
	claims map[string]*regexp.Regexp // Claim key-value pairs with regex for matching
	issuer TokenIssuer               // The TokenIssuer for this route
}

// TokenBridge is the main struct that facilitates interaction between an OIDC (OpenID Connect)
// verifier and a token issuer. It provides methods to verify ID tokens, exchange them
// for access tokens, and retrieve the JWKS used to verify the tokens.
type TokenBridge struct {
	// oidcVerifier is responsible for verifying the authenticity and validity of ID tokens.
	oidcVerifier Verifier

	// routes is a slice of routes that define the mapping between claims and token issuers.
	// Each route contains a set of claims (as regex patterns) and the corresponding TokenIssuer.
	// The routes are used to determine which TokenIssuer to use based on the claims present in the ID token.
	// The routes are matched in the order they are added, so the first matching route will be used.
	routes []route

	// defaultIssuer is the default TokenIssuer to be used when no specific route matches the claims.
	// This allows the TokenBridge to handle cases where no specific route is defined for the claims.
	// The default issuer is used as a fallback option.
	// If no default issuer is set, an error will be returned if no matching route is found.
	defaultIssuer TokenIssuer
}

// New creates and returns a new TokenBridge instance. This function initializes the
// TokenBridge with an OIDCVerifier to enable token exchange and verification.
func New(oidcVerifier *OIDCVerifier) *TokenBridge {
	return &TokenBridge{
		oidcVerifier:  oidcVerifier,
		routes:        make([]route, 0),
		defaultIssuer: nil,
	}
}

// AddRoute registers a route with specific claims and a corresponding TokenIssuer.
// The `claims` map can contain regular expressions as values for flexible matching.
func (tb *TokenBridge) AddRoute(claims map[string]string, issuer TokenIssuer) error {
	compiledClaims := make(map[string]*regexp.Regexp)

	for key, pattern := range claims {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern for claim '%s': %w", key, err)
		}

		compiledClaims[key] = regex
	}

	tb.routes = append(tb.routes, route{
		claims: compiledClaims,
		issuer: issuer,
	})

	return nil
}

// SetDefaultIssuer sets a default TokenIssuer to be used when no routes match the claims.
// This allows the TokenBridge to handle cases where no specific route is defined for the claims.
func (tb *TokenBridge) SetDefaultIssuer(issuer TokenIssuer) {
	tb.defaultIssuer = issuer
}

// matchRoute finds the first route that matches the given claims using regex.
func (tb *TokenBridge) matchRoute(idTokenClaims map[string]any) (TokenIssuer, error) {
	for _, r := range tb.routes {
		matched := true

		for key, regex := range r.claims {
			claimValue, exists := idTokenClaims[key]
			if !exists || !regex.MatchString(fmt.Sprintf("%v", claimValue)) {
				matched = false
				break
			}
		}

		if matched {
			return r.issuer, nil
		}
	}

	// If no route matches, return the default issuer if set.
	if tb.defaultIssuer != nil {
		return tb.defaultIssuer, nil
	}

	return nil, fmt.Errorf("no matching route found for claims")
}

// ExchangeToken exchanges a raw ID token for an access token. It first verifies the ID token using
// the OIDCVerifier, and then creates an access token using the TokenIssuer.
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

	// Extract claims from the ID token.
	claims := make(map[string]any)
	if err := idToken.Claims(&claims); err != nil {
		return "", fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Find the appropriate TokenIssuer based on the claims.
	issuer, err := tb.matchRoute(claims)
	if err != nil {
		return "", fmt.Errorf("failed to find matching route: %w", err)
	}

	// Create an access token using the authenticated ID token.
	accessToken, err := issuer.IssueAccessToken(ctx, idToken)
	if err != nil {
		return "", fmt.Errorf("failed to issue access token: %w", err)
	}

	return accessToken, nil
}
