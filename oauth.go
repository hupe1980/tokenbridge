package tokenbridge

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hupe1980/tokenbridge/keyset"
)

// AuthServerOptions defines the configuration options for the AuthServer.
// These options control the behavior of the authentication server, such as token expiration and subject overwriting.
type AuthServerOptions struct {
	// SubjectOverwrite allows you to specify a custom subject for the access token.
	// If not set, the subject from the ID token will be used.
	SubjectOverwrite string

	// AudienceOverwrite allows you to specify a custom audience for the access token.
	// If not set, the audience from the ID token will be used.
	AudienceOverwrite []string

	// TokenExpiration defines the duration for which the access token will be valid.
	// The default is set to one hour.
	TokenExpiration time.Duration
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
		TokenExpiration: time.Hour, // Default token expiration is one hour.
	}

	// Apply any custom options provided through optFns
	for _, fn := range optFns {
		fn(&opts)
	}

	return &AuthServer{iss: iss, signer: signer, opts: opts}
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
func (as *AuthServer) CreateAccessToken(ctx context.Context, idToken *oidc.IDToken, customClaims map[string]any) (string, error) {
	// Set the subject of the access token. If SubjectOverwrite is set, use it instead of the ID token's subject.
	sub := idToken.Subject
	if as.opts.SubjectOverwrite != "" {
		sub = as.opts.SubjectOverwrite
	}

	aud := idToken.Audience
	if len(as.opts.AudienceOverwrite) > 0 {
		aud = as.opts.AudienceOverwrite
	}

	// Create a new JWT token with the required claims
	token := jwt.NewWithClaims(as.signer.SigningMethod(), jwt.MapClaims{
		"iss":                     as.iss,
		"sub":                     sub,
		"aud":                     aud,
		"exp":                     time.Now().Add(as.opts.TokenExpiration).Unix(),
		"tokenbridge:idtoken_iss": idToken.Issuer,
		"tokenbridge:idtoken_aud": idToken.Audience,
		"tokenbridge:idtoken_sub": idToken.Subject,
		"tokenbridge:idtoken_exp": idToken.Expiry.Unix(),
		"tokenbridge:idtoken_iat": idToken.IssuedAt.Unix(),
	})

	// Add any custom claims to the token, ensuring reserved claims are not overwritten
	for key, value := range customClaims {
		// Reserved claims cannot be overwritten
		if slices.Contains([]string{"iss", "sub", "exp"}, key) {
			return "", fmt.Errorf("cannot overwrite reserved claim %s", key)
		}

		if strings.HasPrefix(key, "tokenbridge:") {
			return "", fmt.Errorf("cannot overwrite reserved claim %s", key)
		}

		// Add the custom claim to the token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return "", fmt.Errorf("failed to assert token claims as jwt.MapClaims")
		}

		claims[key] = value
	}

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
