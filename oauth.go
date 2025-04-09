package tokenbridge

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hupe1980/tokenbridge/keyset"
)

// AuthServerOptions defines the configuration options for the AuthServer.
// These options control the behavior of the authentication server, such as token expiration and subject overwriting.
type AuthServerOptions struct {
	// MandatoryClaims are the claims that must be present in the access token.
	MandatoryClaims []string

	// TokenExpiration defines the duration for which the access token will be valid.
	// The default is set to one hour.
	TokenExpiration time.Duration

	// OnTokenCreate is a callback function that allows customization of claims during token creation.
	// If not set, a default implementation will be used.
	OnTokenCreate func(ctx context.Context, idToken *oidc.IDToken) (jwt.MapClaims, error)
}

// AuthServer is responsible for creating and signing access tokens for authenticated users.
// It uses an underlying signer and the configuration provided in AuthServerOptions.
type AuthServer struct {
	iss    string
	signer Signer
	opts   AuthServerOptions
}

// NewAuthServer creates a new AuthServer instance with the provided signer and optional configuration functions.
//
// Parameters:
//   - signer: A Signer implementation used to sign the generated access tokens.
//   - optFns: A variadic list of functions to customize the AuthServerOptions.
//
// Returns:
//   - A new AuthServer instance configured with the provided options.
func NewAuthServer(iss string, signer Signer, optFns ...func(o *AuthServerOptions)) *AuthServer {
	opts := AuthServerOptions{
		MandatoryClaims: []string{"sub", "iss", "aud", "exp", "iat"},
		TokenExpiration: time.Hour, // Default token expiration is one hour.
		OnTokenCreate: func(_ context.Context, idToken *oidc.IDToken) (jwt.MapClaims, error) {
			// Default implementation returns the claims from the ID token.
			return jwt.MapClaims{
				"iss": idToken.Issuer,
				"sub": idToken.Subject,
				"aud": idToken.Audience,
			}, nil
		},
	}

	// Apply any custom options provided through optFns
	for _, fn := range optFns {
		fn(&opts)
	}

	return &AuthServer{iss: iss, signer: signer, opts: opts}
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

// CreateAccessToken generates an access token based on the provided OIDC ID token and custom claims.
//
// Parameters:
//   - ctx: The context used for making requests.
//   - idToken: The ID token obtained from the OIDC provider, which will be used to create the access token.
//   - customClaims: A map of custom claims to be added to the access token. Claims like "sub" and "exp" are reserved and cannot be overwritten.
//
// Returns:
//   - The signed JWT access token as a string if successful.
//   - An error if there is a problem generating or signing the token.
func (as *AuthServer) CreateAccessToken(ctx context.Context, idToken *oidc.IDToken) (string, error) {
	claims, err := as.opts.OnTokenCreate(ctx, idToken)
	if err != nil {
		return "", fmt.Errorf("failed to create token claims: %w", err)
	}

	// Ensure the "exp" claim is set to the token expiration time
	if _, exists := claims["exp"]; !exists {
		claims["exp"] = time.Now().Add(as.opts.TokenExpiration).Unix()
	}

	// Ensure the "iat" claim is set to the current time
	if _, exists := claims["iat"]; !exists {
		claims["iat"] = time.Now().Unix()
	}

	// Check for mandatory claims
	if err := checkMandatoryClaims(claims, as.opts.MandatoryClaims); err != nil {
		return "", err
	}

	// Create a new JWT token with the required claims
	token := jwt.NewWithClaims(as.signer.SigningMethod(), claims)

	// Add the Key ID (kid) to the token header
	token.Header["kid"] = as.signer.KeyID()

	// Sign the token using the provided signer
	tokenString, err := as.signer.SignToken(ctx, token)
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
func (as *AuthServer) GetJWKS(ctx context.Context) (*keyset.JWKS, error) {
	return as.signer.GetJWKS(ctx)
}
