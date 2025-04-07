package tokenbridge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/hupe1980/tokenbridge/keyset"
)

// thumbprintValidatingTransport is a custom HTTP transport that validates JWKs by checking the
// thumbprints of the public keys. It intercepts HTTP requests and responses, particularly for
// JWKS and OIDC configuration endpoints.
type thumbprintValidatingTransport struct {
	// transport is the underlying HTTP RoundTripper that handles the actual HTTP requests.
	transport http.RoundTripper

	// thumbprints is a list of valid thumbprints used to filter the JWKs in the JWKS response.
	thumbprints []string
}

// RoundTrip executes the HTTP request and processes the response. It filters the JWKS response by
// validating the thumbprints of the public keys in the JWKS.
func (t *thumbprintValidatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Perform the HTTP request
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}

	// Handle specific paths: OpenID configuration and JWKS retrieval
	switch {
	case strings.HasSuffix(req.URL.Path, "/.well-known/openid-configuration"):
		// Return the OIDC configuration response without modification
		return resp, nil

	case strings.HasSuffix(req.URL.Path, "/keys"):
		// Handle the JWKS request and filter the keys based on thumbprints
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read JWKS response body: %w", err)
		}

		// Parse the JWKS JSON
		parsedJWKS, err := keyset.ParseJWKS(body)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JWKS: %w", err)
		}

		// Filter the keys by thumbprint validity
		filteredKeys := []keyset.JWK{}

		for _, key := range parsedJWKS.Keys {
			var thumbprint string

			// Calculate the thumbprint based on the key type (RSA or EC)
			switch key.Kty {
			case "RSA":
				// Handle RSA keys by calculating thumbprint from modulus and exponent
				nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
				if err != nil {
					return nil, fmt.Errorf("failed to decode modulus: %w", err)
				}

				eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
				if err != nil {
					return nil, fmt.Errorf("failed to decode exponent: %w", err)
				}

				publicKey := &rsa.PublicKey{
					N: new(big.Int).SetBytes(nBytes),
					E: int(new(big.Int).SetBytes(eBytes).Int64()),
				}

				// Calculate the thumbprint for the RSA public key
				thumbprint, err = calculateThumbprint(publicKey)
				if err != nil {
					return nil, fmt.Errorf("failed to calculate thumbprint: %w", err)
				}

			case "EC":
				// Handle EC keys by calculating thumbprint from x and y coordinates
				xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
				if err != nil {
					return nil, fmt.Errorf("failed to decode x-coordinate: %w", err)
				}

				yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
				if err != nil {
					return nil, fmt.Errorf("failed to decode y-coordinate: %w", err)
				}

				publicKey := &ecdsa.PublicKey{
					Curve: getEllipticCurve(key.Crv),
					X:     new(big.Int).SetBytes(xBytes),
					Y:     new(big.Int).SetBytes(yBytes),
				}

				// Calculate the thumbprint for the EC public key
				thumbprint, err = calculateThumbprint(publicKey)
				if err != nil {
					return nil, fmt.Errorf("failed to calculate thumbprint: %w", err)
				}

			default:
				return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
			}

			// Filter the key if its thumbprint matches one of the valid thumbprints
			if t.isThumbprintValid(thumbprint) {
				filteredKeys = append(filteredKeys, key)
			}
		}

		// Raise an error if no keys match the expected thumbprints
		if len(filteredKeys) == 0 {
			return nil, fmt.Errorf("no keys in JWKS match the expected thumbprints")
		}

		// Replace the JWKS response with the filtered keys
		filteredJWKS := keyset.JWKS{Keys: filteredKeys}

		// Encode the filtered JWKS back to JSON
		filteredJWKSBytes, err := json.Marshal(filteredJWKS)
		if err != nil {
			return nil, fmt.Errorf("failed to encode filtered JWKS: %w", err)
		}

		// Replace the response body with the filtered JWKS
		resp.Body = io.NopCloser(bytes.NewReader(filteredJWKSBytes))
		resp.ContentLength = int64(len(filteredJWKSBytes))
		resp.Header.Set("Content-Type", "application/json")

		return resp, nil

	default:
		// Handle unexpected paths
		return nil, fmt.Errorf("unexpected path: %s", req.URL.Path)
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

// calculateThumbprint calculates the thumbprint for a given public key (either RSA or EC).
// The thumbprint is calculated as the SHA-256 hash of the serialized key object (JWK),
// base64 URL-encoded.
func calculateThumbprint(publicKey any) (string, error) {
	var jwk map[string]string

	// Create the JWK (JSON Web Key) representation based on the public key type
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		// Create a JWK for RSA with "n" (modulus) and "e" (exponent)
		jwk = map[string]string{
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": "AQAB", // Default exponent for RSA keys
		}

	case *ecdsa.PublicKey:
		// Create a JWK for EC with "x" (x-coordinate) and "y" (y-coordinate)
		jwk = map[string]string{
			"x": base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
			"y": base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
		}

	default:
		return "", fmt.Errorf("unsupported key type: %T", publicKey)
	}

	// Serialize the JWK to JSON
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Calculate the SHA-256 hash of the JWK
	hash := sha256.Sum256(jwkBytes)

	// Return the base64 URL-encoded hash as the thumbprint
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// getEllipticCurve maps the curve name to the corresponding elliptic curve.
func getEllipticCurve(crv string) elliptic.Curve {
	switch crv {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}
