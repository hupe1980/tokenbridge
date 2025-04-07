package tokenbridge

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCVerifierOptions defines the available configuration options for the OIDCVerifier.
// These options control the behavior of the verification process, such as enabling or disabling
// specific checks (e.g., issuer, client ID, expiry), and controlling the supported signing algorithms.
type OIDCVerifierOptions struct {
	// Transport is an optional custom HTTP transport used for making HTTP requests.
	Transport http.RoundTripper

	// Thumbprints is a list of valid thumbprints for the keys used to verify ID tokens.
	// If this is set, the transport will be configured to validate the thumbprints of the keys.
	Thumbprints []string

	// SupportedSigningAlgs is a list of signing algorithms supported for verifying ID tokens.
	SupportedSigningAlgs []string

	// SkipClientIDCheck controls whether the client ID check is skipped during verification.
	SkipClientIDCheck bool

	// SkipExpiryCheck controls whether the expiry check is skipped during verification.
	SkipExpiryCheck bool

	// SkipIssuerCheck controls whether the issuer check is skipped during verification.
	SkipIssuerCheck bool

	// Now is a function that returns the current time, which can be used for expiry and validity checks.
	// If not provided, the default time function (time.Now) is used.
	Now func() time.Time
}

// OIDCVerifier is responsible for verifying OpenID Connect ID tokens.
// It uses an OIDC provider and supports various verification options, including
// client ID validation, expiry checks, and issuer checks.
type OIDCVerifier struct {
	issuer    string
	clientIDs []string
	provider  *oidc.Provider
	opts      OIDCVerifierOptions
}

// NewOIDCVerifier creates a new OIDCVerifier instance using the provided configuration options.
//
// Parameters:
//   - ctx: The context used for making requests.
//   - issuer: The URL of the OpenID Connect provider.
//   - clientIDs: A list of allowed client IDs to validate the ID token against.
//   - optFns: A variadic list of functions to customize the OIDCVerifierOptions.
//
// Returns:
//   - A new OIDCVerifier instance.
func NewOIDCVerifier(ctx context.Context, issuerURL *url.URL, clientIDs []string, optFns ...func(o *OIDCVerifierOptions)) (*OIDCVerifier, error) {
	// Validate the provider URL
	if issuerURL == nil || issuerURL.String() == "" {
		return nil, fmt.Errorf("OIDC provider URL cannot be empty")
	}

	// Validate client IDs
	if len(clientIDs) == 0 {
		return nil, fmt.Errorf("at least one client ID must be provided")
	}

	for _, clientID := range clientIDs {
		if clientID == "" {
			return nil, fmt.Errorf("client ID cannot be empty")
		}
	}

	opts := OIDCVerifierOptions{
		Transport:         http.DefaultTransport,
		SkipClientIDCheck: false,
		SkipExpiryCheck:   false,
		SkipIssuerCheck:   false,
		Now:               time.Now,
	}

	// Apply custom options provided through optFns
	for _, fn := range optFns {
		fn(&opts)
	}

	// Validate thumbprints
	if len(opts.Thumbprints) > 0 {
		for _, thumbprint := range opts.Thumbprints {
			if !isValidBase64URLEncoding(thumbprint) {
				return nil, fmt.Errorf("invalid thumbprint format: %s", thumbprint)
			}
		}
	}

	// Create a transport layer that checks for thumbprints, if provided.
	transport := opts.Transport
	if len(opts.Thumbprints) > 0 {
		transport = &thumbprintValidatingTransport{
			transport:   opts.Transport,
			thumbprints: opts.Thumbprints,
		}
	}

	// Create an OIDC client context using the provided transport
	clientCtx := oidc.ClientContext(ctx, &http.Client{
		Transport: transport,
	})

	// Create an OIDC provider using the provided URL
	provider, err := oidc.NewProvider(clientCtx, issuerURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Return a new OIDCVerifier instance with the provider and configuration options
	return &OIDCVerifier{
		issuer:    issuerURL.String(),
		clientIDs: clientIDs,
		provider:  provider,
		opts:      opts,
	}, nil
}

// Issuer returns the URL of the OpenID Connect provider used by the OIDCVerifier.
func (p *OIDCVerifier) Issuer() string {
	return p.issuer
}

// ClientIDs returns the list of allowed client IDs for which the ID token will be verified.
func (p *OIDCVerifier) ClientIDs() []string {
	return p.clientIDs
}

// Verify verifies the provided raw ID token using the configured client IDs and the OpenID Connect provider.
//
// Parameters:
//   - ctx: The context used for making requests.
//   - rawIDToken: The raw ID token string that needs to be verified.
//
// Returns:
//   - A verified *oidc.IDToken if verification is successful.
//   - An error if verification fails for all client IDs.
func (p *OIDCVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	var lastErr error

	// Iterate through all allowed clientIDs and try verifying the token for each client ID
	for _, clientID := range p.clientIDs {
		verifier := p.provider.Verifier(&oidc.Config{
			ClientID:             clientID,
			SupportedSigningAlgs: p.opts.SupportedSigningAlgs,
			SkipClientIDCheck:    p.opts.SkipClientIDCheck,
			SkipExpiryCheck:      p.opts.SkipExpiryCheck,
			SkipIssuerCheck:      p.opts.SkipIssuerCheck,
			Now:                  p.opts.Now,
		})

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err == nil {
			// If verification is successful for this client ID, return the verified token
			return idToken, nil
		}
		// If verification fails, store the last error
		lastErr = err
	}

	// If all client IDs failed to verify the token, return the last error encountered
	return nil, fmt.Errorf("failed to verify ID token for all clientIDs: %w", lastErr)
}

// isValidBase64URLEncoding checks if the given string is a valid Base64 URL-encoded string.
// It attempts to decode the string using base64.RawURLEncoding and returns true if the decoding
// succeeds without error, indicating the string is valid. Otherwise, it returns false.
func isValidBase64URLEncoding(s string) bool {
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}
