package tokenbridge

import (
	"encoding/json"
	"fmt"
)

// JWKS represents a JSON Web Key Set (JWKS), which contains an array of keys that can be used
// for validating JWTs. Each key in the set is a JWK.
type JWKS struct {
	// Keys is a list of JSON Web Keys (JWKs) included in the set.
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key, which contains parameters describing the key.
// It can be an RSA or EC key, and includes information such as key type, algorithm,
// key usage, key ID, and other parameters depending on the key type.
type JWK struct {
	// Kty (Key Type) indicates the algorithm family of the key (e.g., "RSA", "EC").
	Kty string `json:"kty"`

	// Alg (Algorithm) indicates the algorithm used with the key (e.g., "RS256").
	Alg string `json:"alg"`

	// Use (Key Use) indicates the intended use of the key (e.g., "sig" for signature).
	Use string `json:"use"`

	// Kid (Key ID) is a unique identifier for the key.
	Kid string `json:"kid"`

	// N is the modulus for RSA keys. This field is only set for RSA keys.
	N string `json:"n,omitempty"`

	// E is the exponent for RSA keys. This field is only set for RSA keys.
	E string `json:"e,omitempty"`

	// X is the x-coordinate for EC keys. This field is only set for EC keys.
	X string `json:"x,omitempty"`

	// Y is the y-coordinate for EC keys. This field is only set for EC keys.
	Y string `json:"y,omitempty"`

	// Crv (Curve) indicates the elliptic curve used for EC keys. This field is only set for EC keys.
	Crv string `json:"crv,omitempty"`
}

// ParseJWKS parses a JSON Web Key Set (JWKS) from a JSON-encoded byte slice.
//
// The data parameter should be a valid JWKS JSON string. This function will parse the
// string into a JWKS struct, which contains a list of JWKs.
//
// Returns:
// - *JWKS: The parsed JWKS struct.
// - error: An error, if any occurred during parsing.
func ParseJWKS(data []byte) (*JWKS, error) {
	var jwks JWKS
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwks, nil
}
