package tokenbridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hupe1980/tokenbridge/keyset"
)

// Signer is an interface that defines methods for signing JWT tokens, retrieving JWKS (JSON Web Key Sets),
// and providing the signing method and key ID for the signer.
type Signer interface {
	// SignToken signs the given JWT token using the signing algorithm and returns the signed string.
	SignToken(ctx context.Context, token *jwt.Token) (string, error)

	// GetJWKS returns the JWKS (JSON Web Key Set) associated with the signer, containing the public key.
	GetJWKS(ctx context.Context) (*keyset.JWKS, error)

	// SigningMethod returns the JWT signing method (e.g., HMAC or RSA).
	SigningMethod() jwt.SigningMethod

	// KeyID returns the Key ID used to identify the key.
	KeyID() string
}

// NewHMAC256Signer creates a new HMAC signer using the HS256 signing method.
func NewHMAC256Signer(secret, keyID string) Signer {
	return newHMACSigner(secret, keyID, jwt.SigningMethodHS256)
}

// NewHMAC384Signer creates a new HMAC signer using the HS384 signing method.
func NewHMAC384Signer(secret, keyID string) Signer {
	return newHMACSigner(secret, keyID, jwt.SigningMethodHS384)
}

// NewHMAC512Signer creates a new HMAC signer using the HS512 signing method.
func NewHMAC512Signer(secret, keyID string) Signer {
	return newHMACSigner(secret, keyID, jwt.SigningMethodHS512)
}

// hmacSigner is an implementation of the Signer interface that signs JWT tokens using the HMAC algorithm.
type hmacSigner struct {
	secret        []byte
	keyID         string // Key ID for identifying the key
	signingMethod jwt.SigningMethod
}

// newHMACSigner creates a new instance of hmacSigner with the provided secret, key ID, and signing method.
func newHMACSigner(secret, keyID string, signingMethod jwt.SigningMethod) Signer {
	return &hmacSigner{
		secret:        []byte(secret),
		keyID:         keyID,
		signingMethod: signingMethod,
	}
}

// SignToken signs the given JWT token using the HMAC secret and returns the signed token string.
func (s *hmacSigner) SignToken(_ context.Context, token *jwt.Token) (string, error) {
	return token.SignedString(s.secret)
}

// GetJWKS returns an error as HMAC keys do not support generating keyset.
func (s *hmacSigner) GetJWKS(_ context.Context) (*keyset.JWKS, error) {
	return nil, fmt.Errorf("hmac does not support JWKS")
}

// SigningMethod returns the HMAC signing method (e.g., HS256, HS384, HS512).
func (s *hmacSigner) SigningMethod() jwt.SigningMethod {
	return s.signingMethod
}

// KeyID returns the key ID for the HMAC key.
func (s *hmacSigner) KeyID() string {
	return s.keyID
}

// NewRSA256Signer creates a new RSA signer using the RS256 signing method.
func NewRSA256Signer(privateKey *rsa.PrivateKey, keyID string) Signer {
	return newRSASigner(privateKey, keyID, jwt.SigningMethodRS256)
}

// NewRSA384Signer creates a new RSA signer using the RS384 signing method.
func NewRSA384Signer(privateKey *rsa.PrivateKey, keyID string) Signer {
	return newRSASigner(privateKey, keyID, jwt.SigningMethodRS384)
}

// NewRSA512Signer creates a new RSA signer using the RS512 signing method.
func NewRSA512Signer(privateKey *rsa.PrivateKey, keyID string) Signer {
	return newRSASigner(privateKey, keyID, jwt.SigningMethodRS512)
}

// rsaSigner is an implementation of the Signer interface that signs JWT tokens using RSA private keys.
type rsaSigner struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	keyID         string
	signingMethod jwt.SigningMethod
}

// newRSASigner creates a new instance of rsaSigner with the provided private key, key ID, and signing method.
func newRSASigner(privateKey *rsa.PrivateKey, keyID string, signingMethod jwt.SigningMethod) Signer {
	return &rsaSigner{
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
		keyID:         keyID,
		signingMethod: signingMethod,
	}
}

// SignToken signs the given JWT token using the RSA private key and returns the signed token string.
func (s *rsaSigner) SignToken(_ context.Context, token *jwt.Token) (string, error) {
	return token.SignedString(s.privateKey)
}

// GetJWKS returns the JWKS containing the RSA public key for verification of the signed token.
func (s *rsaSigner) GetJWKS(_ context.Context) (*keyset.JWKS, error) {
	// Convert the RSA public key to JWK format (modulus and exponent)
	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes()) // Modulus
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})       // Exponent (65537 by default)

	// Create the JWK for the RSA public key
	jwk := keyset.JWK{
		Kty: "RSA", // Key type
		Alg: s.signingMethod.Alg(),
		Use: "sig", // Key usage (signature)
		Kid: s.keyID,
		N:   n,
		E:   e,
	}

	return &keyset.JWKS{Keys: []keyset.JWK{jwk}}, nil
}

// SigningMethod returns the RSA signing method (e.g., RS256, RS384, RS512).
func (s *rsaSigner) SigningMethod() jwt.SigningMethod {
	return s.signingMethod
}

// KeyID returns the key ID for the RSA key.
func (s *rsaSigner) KeyID() string {
	return s.keyID
}

// NewES256Signer creates a new EC signer using the ES256 signing method.
func NewES256Signer(privateKey *ecdsa.PrivateKey, keyID string) Signer {
	return newECSigner(privateKey, keyID, jwt.SigningMethodES256)
}

// NewES384Signer creates a new EC signer using the ES384 signing method.
func NewES384Signer(privateKey *ecdsa.PrivateKey, keyID string) Signer {
	return newECSigner(privateKey, keyID, jwt.SigningMethodES384)
}

// NewES512Signer creates a new EC signer using the ES512 signing method.
func NewES512Signer(privateKey *ecdsa.PrivateKey, keyID string) Signer {
	return newECSigner(privateKey, keyID, jwt.SigningMethodES512)
}

// ecSigner is an implementation of the Signer interface that signs JWT tokens using EC private keys.
type ecSigner struct {
	privateKey    *ecdsa.PrivateKey
	publicKey     *ecdsa.PublicKey
	keyID         string
	signingMethod jwt.SigningMethod
}

// newECSigner creates a new instance of ecSigner with the provided private key, key ID, and signing method.
func newECSigner(privateKey *ecdsa.PrivateKey, keyID string, signingMethod jwt.SigningMethod) Signer {
	return &ecSigner{
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
		keyID:         keyID,
		signingMethod: signingMethod,
	}
}

// SignToken signs the given JWT token using the EC private key and returns the signed token string.
func (s *ecSigner) SignToken(_ context.Context, token *jwt.Token) (string, error) {
	return token.SignedString(s.privateKey)
}

// GetJWKS returns the JWKS containing the EC public key for verification of the signed token.
func (s *ecSigner) GetJWKS(_ context.Context) (*keyset.JWKS, error) {
	// Convert the EC public key to JWK format (x and y coordinates)
	x := base64.RawURLEncoding.EncodeToString(s.publicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(s.publicKey.Y.Bytes())

	// Create the JWK for the EC public key
	jwk := keyset.JWK{
		Kty: "EC", // Key type
		Alg: s.signingMethod.Alg(),
		Use: "sig", // Key usage (signature)
		Kid: s.keyID,
		Crv: s.publicKey.Curve.Params().Name, // Curve name
		X:   x,                               // X coordinate
		Y:   y,                               // Y coordinate
	}

	return &keyset.JWKS{Keys: []keyset.JWK{jwk}}, nil
}

// SigningMethod returns the EC signing method (e.g., ES256, ES384, ES512).
func (s *ecSigner) SigningMethod() jwt.SigningMethod {
	return s.signingMethod
}

// KeyID returns the key ID for the EC key.
func (s *ecSigner) KeyID() string {
	return s.keyID
}
