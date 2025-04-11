package tokenbridge

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"

	"golang.org/x/oauth2/clientcredentials"
)

// JWKSProvider defines an additional interface for retrieving the JWKS.
type JWKSProvider interface {
	// GetJWKS retrieves the JSON Web Key Set (JWKS) containing the public keys used to verify the signed tokens.
	GetJWKS(ctx context.Context) (*JWKS, error)
}

// TokenIssuerWithJWKSOptions defines the configuration options for the TokenIssuerWithJWKS.
// These options control the behavior of the token issuer, such as token expiration and subject overwriting.
type TokenIssuerWithJWKSOptions struct {
	// MandatoryClaims are the claims that must be present in the access token.
	MandatoryClaims []string

	// TokenExpiration defines the duration for which the access token will be valid.
	// The default is set to one hour.
	TokenExpiration time.Duration

	// OnTokenCreate is a callback function that allows customization of claims during token creation.
	// If not set, a default implementation will be used.
	OnTokenCreate func(ctx context.Context, issuer string, idToken *oidc.IDToken) (jwt.MapClaims, error)
}

// DefaultOnTokenCreate is the default implementation of the OnTokenCreate callback.
// It generates a set of default claims based on the provided ID token.
// This function can be overridden by the user to customize the claims as needed.
// The default implementation includes the issuer, subject, and audience claims.
// It returns a map of claims that will be included in the generated access token.
// The "sub" claim is set to the subject of the ID token, and the "iss" claim is set to the issuer of the ID token.
// The "aud" claim is set to the audience of the ID token.
func DefaultOnTokenCreate(_ context.Context, issuer string, idToken *oidc.IDToken) (jwt.MapClaims, error) {
	return jwt.MapClaims{
		"iss": issuer,
		"sub": idToken.Subject,
		"aud": idToken.Audience,
	}, nil
}

// TokenIssuerWithJWKS is responsible for creating and signing access tokens for authenticated users.
// It implements both the TokenIssuer and JWKSProvider interfaces.
type TokenIssuerWithJWKS struct {
	iss    string
	signer Signer
	opts   TokenIssuerWithJWKSOptions
}

// NewTokenIssuerWithJWKS creates a new TokenIssuerWithJWKS instance with the provided signer and optional configuration functions.
//
// Parameters:
//   - signer: A Signer implementation used to sign the generated access tokens.
//   - optFns: A variadic list of functions to customize the TokenIssuerWithJWKSOptions.
//
// Returns:
//   - A new TokenIssuerWithJWKS instance configured with the provided options.
func NewTokenIssuerWithJWKS(iss string, signer Signer, optFns ...func(o *TokenIssuerWithJWKSOptions)) *TokenIssuerWithJWKS {
	opts := TokenIssuerWithJWKSOptions{
		MandatoryClaims: []string{"sub", "iss", "aud", "exp", "iat"},
		TokenExpiration: time.Hour, // Default token expiration is one hour.
		OnTokenCreate:   DefaultOnTokenCreate,
	}

	// Apply any custom options provided through optFns
	for _, fn := range optFns {
		fn(&opts)
	}

	return &TokenIssuerWithJWKS{iss: iss, signer: signer, opts: opts}
}

// checkMandatoryClaims ensures that all mandatory claims are present in the provided claims map.
// If any mandatory claim is missing, it returns an error.
func checkMandatoryClaims(claims jwt.MapClaims, mandatoryClaims []string) error {
	for _, claim := range mandatoryClaims {
		if _, exists := claims[claim]; !exists {
			return fmt.Errorf("missing mandatory claim '%s'", claim)
		}
	}

	return nil
}

// IssueAccessToken generates an access token based on the provided OIDC ID token.
//
// Parameters:
//   - ctx: The context used for making requests.
//   - idToken: The ID token obtained from the OIDC provider, which will be used to create the access token.
//   - customClaims: A map of custom claims to be added to the access token. Claims like "sub" and "exp" are reserved and cannot be overwritten.
//
// Returns:
//   - The signed JWT access token as a string if successful.
//   - An error if there is a problem generating or signing the token.
func (ti *TokenIssuerWithJWKS) IssueAccessToken(ctx context.Context, idToken *oidc.IDToken) (string, error) {
	claims, err := ti.opts.OnTokenCreate(ctx, ti.iss, idToken)
	if err != nil {
		return "", fmt.Errorf("failed to create token claims: %w", err)
	}

	// Ensure the "exp" claim is set to the token expiration time
	if _, exists := claims["exp"]; !exists {
		if slices.Contains(ti.opts.MandatoryClaims, "exp") {
			claims["exp"] = time.Now().Add(ti.opts.TokenExpiration).Unix()
		}
	}

	// Ensure the "iat" claim is set to the current time
	if _, exists := claims["iat"]; !exists {
		if slices.Contains(ti.opts.MandatoryClaims, "iat") {
			claims["iat"] = time.Now().Unix()
		}
	}

	// Check for mandatory claims
	if err := checkMandatoryClaims(claims, ti.opts.MandatoryClaims); err != nil {
		return "", err
	}

	// Create a new JWT token with the required claims
	token := jwt.NewWithClaims(ti.signer.SigningMethod(), claims)

	// Add the Key ID (kid) to the token header
	token.Header["kid"] = ti.signer.KeyID()

	// Sign the token using the provided signer
	tokenString, err := ti.signer.SignToken(ctx, token)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GetJWKS retrieves the JSON Web Key Set (JWKS) containing the public keys used to verify the signed tokens.
//
// Parameters:
//   - ctx: The context used for making requests.
//
// Returns:
//   - The JWKS containing the public key(s) used for verifying tokens.
//   - An error if there is a problem retrieving the JWKS.
func (ti *TokenIssuerWithJWKS) GetJWKS(ctx context.Context) (*JWKS, error) {
	return ti.signer.GetJWKS(ctx)
}

// ClientCredentialIssuer is responsible for issuing access tokens using the client credentials flow.
type ClientCredentialIssuer struct {
	config *clientcredentials.Config
}

// NewClientCredentialIssuer creates a new ClientCredentialIssuer instance.
//
// Parameters:
//   - config: A clientcredentials.Config instance containing the OAuth2 client credentials configuration.
//
// Returns:
//   - A new ClientCredentialIssuer instance.
func NewClientCredentialIssuer(config *clientcredentials.Config) *ClientCredentialIssuer {
	return &ClientCredentialIssuer{config: config}
}

// IssueAccessToken generates an access token using the client credentials flow.
//
// Parameters:
//   - ctx: The context used for making requests.
//
// Returns:
//   - The access token as a string if successful.
//   - An error if there is a problem generating the access token.
func (cci *ClientCredentialIssuer) IssueAccessToken(ctx context.Context, _ *oidc.IDToken) (string, error) {
	// Use the client credentials config to retrieve a token
	token, err := cci.config.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve access token: %w", err)
	}

	return token.AccessToken, nil
}
