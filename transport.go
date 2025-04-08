package tokenbridge

import (
	"crypto/sha1" // nolint:gosec // SHA-1 is required for certificate thumbprints
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// thumbprintValidatingTransport is a custom HTTP transport that intercepts requests and responses
// to validate the thumbprints of the certificates in JWKS (JSON Web Key Set) responses. This transport
// ensures that only trusted certificate chains, based on their thumbprints, are used. If the thumbprint
// of a certificate does not match one of the valid thumbprints, the response is rejected.
type thumbprintValidatingTransport struct {
	// transport is the underlying HTTP RoundTripper that performs the actual HTTP requests.
	transport http.RoundTripper

	// thumbprints is a slice of valid thumbprints that will be compared against the thumbprints
	// of certificates in the JWKS response. If the thumbprint of a certificate in the chain does not match
	// one of the valid thumbprints, the response is rejected.
	thumbprints []string

	// tlsConfig is a customizable TLS configuration used when establishing the TLS connection.
	tlsConfig *tls.Config

	// dialer is a custom network dialer that will be used to establish the network connection.
	dialer *net.Dialer
}

// RoundTrip executes the HTTP request and processes the response. It validates the thumbprints
// of the public keys in the JWKS response.
func (t *thumbprintValidatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Perform the HTTP request
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}

	// Handle specific paths: OpenID configuration and JWKS retrieval
	switch {
	case strings.HasSuffix(req.URL.Path, "/.well-known/openid-configuration"):
		// Parse the OIDC configuration response to extract the jwks_uri
		defer resp.Body.Close()

		var oidcConfig struct {
			JWKSURI string `json:"jwks_uri"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&oidcConfig); err != nil {
			return nil, fmt.Errorf("failed to parse OIDC configuration: %w", err)
		}

		// Validate the jwks_uri
		if oidcConfig.JWKSURI == "" {
			return nil, fmt.Errorf("jwks_uri is missing in the OIDC configuration")
		}

		// Fetch the JWKS certificate and calculate thumbprint
		jwksURL, err := url.Parse(oidcConfig.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("invalid jwks_uri: %w", err)
		}

		thumbprint, err := CalculateThumbprintFromJWKS(jwksURL, func(o *CalculateThumbprintOptions) {
			// Use the custom TLS configuration and dialer
			if t.tlsConfig != nil {
				o.TLSConfig = t.tlsConfig
			}

			if t.dialer != nil {
				o.Dialer = t.dialer
			}
		})
		if err != nil {
			return nil, fmt.Errorf("failed to calculate thumbprint from JWKS: %w", err)
		}

		// Check if the thumbprint is valid
		if !t.isThumbprintValid(thumbprint) {
			return nil, fmt.Errorf("thumbprint %s is not valid", thumbprint)
		}

		return resp, nil
	default:
		// Handle unexpected paths
		return resp, nil
	}
}

// isThumbprintValid checks if a given thumbprint matches any of the valid thumbprints.
func (t *thumbprintValidatingTransport) isThumbprintValid(thumbprint string) bool {
	for _, validThumbprint := range t.thumbprints {
		if thumbprint == validThumbprint {
			return true
		}
	}

	return false
}

// CalculateThumbprintOptions holds configuration for CalculateThumbprintFromJWKS
type CalculateThumbprintOptions struct {
	TLSConfig *tls.Config
	Dialer    *net.Dialer
}

// CalculateThumbprintFromJWKS retrieves the certificate chain from the JWKS URI, extracts the last certificate,
// and calculates its thumbprint (SHA-1).
func CalculateThumbprintFromJWKS(jwksURI *url.URL, optFns ...func(o *CalculateThumbprintOptions)) (string, error) {
	// Step 1: Fetch the certificate from the JWKS URI
	certs, err := fetchCertificateFromJWKS(jwksURI, optFns...)
	if err != nil {
		return "", fmt.Errorf("failed to fetch certificate from JWKS URI: %v", err)
	}

	// Step 2: Ensure the certificate chain is not empty
	if len(certs) == 0 {
		return "", fmt.Errorf("certificate chain is empty")
	}

	// Retrieve the last certificate in the chain (usually the top intermediate CA certificate)
	lastCert := certs[len(certs)-1]

	// Step 3: Calculate the thumbprint (SHA-1 fingerprint) of the last certificate in the chain
	thumbprint, err := calculateThumbprint(lastCert)
	if err != nil {
		return "", fmt.Errorf("failed to calculate thumbprint: %v", err)
	}

	return thumbprint, nil
}

// fetchCertificateFromJWKS establishes a TLS connection to the server and retrieves the certificate chain.
// It returns the certificates (including any intermediate certificates) from the server's TLS handshake.
func fetchCertificateFromJWKS(jwksURI *url.URL, optFns ...func(o *CalculateThumbprintOptions)) ([]*x509.Certificate, error) {
	// Apply default options
	opts := CalculateThumbprintOptions{
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		},
		Dialer: &net.Dialer{
			Timeout: 5 * time.Second,
		},
	}

	// Apply custom options
	for _, fn := range optFns {
		fn(&opts)
	}

	// Create a custom dialer with the provided config
	conn, err := tls.DialWithDialer(opts.Dialer, "tcp", fmt.Sprintf("%s:443", jwksURI.Hostname()), opts.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish TLS connection: %v", err)
	}
	defer conn.Close()

	// Retrieve the certificate chain from the connection state
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in the chain")
	}

	return certs, nil
}

// calculateThumbprint calculates the SHA-1 thumbprint of the certificate (used to verify its authenticity).
func calculateThumbprint(cert *x509.Certificate) (string, error) {
	// Calculate the thumbprint using SHA-1 (this is required for certificate thumbprints)
	thumbprint := sha1.New() // nolint:gosec // SHA-1 is required for certificate thumbprints
	if _, err := thumbprint.Write(cert.Raw); err != nil {
		return "", fmt.Errorf("failed to write certificate raw data to SHA-1 hash: %v", err)
	}

	// Get the SHA-1 hash and convert it to a string without colon separators
	thumbprintBytes := thumbprint.Sum(nil)
	thumbprintStr := fmt.Sprintf("%X", thumbprintBytes)

	return thumbprintStr, nil
}
