package tokenbridge

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v5"
)

// KMSClient defines the methods that are needed from AWS KMS client for signing tokens and fetching public keys.
type KMSClient interface {
	// Sign signs a digest with the given key using KMS.
	Sign(ctx context.Context, input *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)

	// GetPublicKey retrieves the public key associated with the given key ID.
	GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// KMSOptions defines the configuration options for the KMS signer.
// It allows customization of the cache used for storing and retrieving public keys.
// The default cache is a no-op cache, which means it does not store any keys.
// You can provide a custom cache implementation that implements the Cache interface.
type KMSOptions struct {
	Cache         Cache    // Cache for storing and retrieving public keys
	RotatedKeyIDs []string // A list of key IDs that have been rotated out of active use but are still included in the JWKS
}

// KMS represents a signer that uses AWS Key Management Service (KMS) to sign JWT tokens.
type KMS struct {
	kmsClient     KMSClient                  // AWS KMS client
	keyID         string                     // The ID of the KMS key used for signing
	alg           types.SigningAlgorithmSpec // The signing algorithm to use
	cache         Cache                      // Cache for storing and retrieving public keys
	rotatedKeyIDs []string                   // A list of key IDs that have been rotated out of active use but are still included in the JWKS
}

// NewKMS creates a new instance of KMS with the given client, key ID, and signing algorithm.
// It also accepts optional configuration functions to customize the KMSOptions.
func NewKMS(kmsClient KMSClient, keyID string, alg types.SigningAlgorithmSpec, optFns ...func(o *KMSOptions)) Signer {
	opts := KMSOptions{
		Cache:         NewNoopCache(), // Default to a no-op cache
		RotatedKeyIDs: make([]string, 0),
	}

	// Apply custom options provided through optFns
	for _, fn := range optFns {
		fn(&opts)
	}

	return &KMS{
		kmsClient:     kmsClient,
		keyID:         keyID,
		alg:           alg,
		cache:         opts.Cache,
		rotatedKeyIDs: opts.RotatedKeyIDs,
	}
}

// SignToken signs a JWT token using the KMS service. It serializes the token, computes the hash, and then signs it using KMS.
//
// Parameters:
//   - ctx: The context to use for the signing request.
//   - token: The JWT token that needs to be signed.
//
// Returns:
//   - The signed JWT token as a string.
//   - An error if the signing process fails.
func (s *KMS) SignToken(ctx context.Context, token *jwt.Token) (string, error) {
	// Serialize the token into a string for signing
	tokenString, err := token.SigningString()
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %w", err)
	}

	// Compute the hash based on the selected signing algorithm
	var hash []byte

	switch s.alg { // nolint exhaustive
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecRsassaPssSha256, types.SigningAlgorithmSpecEcdsaSha256:
		h := sha256.Sum256([]byte(tokenString))
		hash = h[:]
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, types.SigningAlgorithmSpecRsassaPssSha384, types.SigningAlgorithmSpecEcdsaSha384:
		h := sha512.Sum384([]byte(tokenString))
		hash = h[:]
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, types.SigningAlgorithmSpecRsassaPssSha512, types.SigningAlgorithmSpecEcdsaSha512:
		h := sha512.Sum512([]byte(tokenString))
		hash = h[:]
	default:
		return "", fmt.Errorf("unsupported signing algorithm: %s", s.alg)
	}

	// Sign the hashed message using AWS KMS
	signInput := &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          hash,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: s.alg,
	}

	signOutput, err := s.kmsClient.Sign(ctx, signInput)
	if err != nil {
		return "", fmt.Errorf("failed to sign with KMS: %w", err)
	}

	// Combine the signed hash with the original token string and return it
	return fmt.Sprintf("%s.%s", tokenString, base64.RawURLEncoding.EncodeToString(signOutput.Signature)), nil
}

// GetJWKS retrieves the JSON Web Key Set (JWKS) containing the public keys used for verifying signed tokens.
//
// Parameters:
//   - ctx: The context to use for the public key retrieval request.
//
// Returns:
//   - A JWKS containing the public key(s) for verifying the token signature.
//   - An error if retrieving the public key or constructing the JWKS fails.
func (s *KMS) GetJWKS(ctx context.Context) (*JWKS, error) {
	// Map the KMS signing algorithm to the corresponding JWT signing method.
	signingMethod := getSigningMethod(s.alg)
	if signingMethod == nil {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", s.alg)
	}

	// Initialize the JWKS
	jwks := &JWKS{Keys: []JWK{}}

	// Add the active key to the JWKS
	activeKey, err := s.getPublicKeyJWK(ctx, s.keyID, signingMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve active key: %w", err)
	}

	jwks.Keys = append(jwks.Keys, activeKey)

	// Add rotated keys to the JWKS
	for _, rotatedKeyID := range s.rotatedKeyIDs {
		rotatedKey, err := s.getPublicKeyJWK(ctx, rotatedKeyID, signingMethod)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve rotated key %s: %w", rotatedKeyID, err)
		}

		jwks.Keys = append(jwks.Keys, rotatedKey)
	}

	// Return the constructed JWKS
	return jwks, nil
}

// getPublicKeyJWK retrieves the public key for a given key ID and constructs a JWK.
func (s *KMS) getPublicKeyJWK(ctx context.Context, keyID string, signingMethod jwt.SigningMethod) (JWK, error) {
	// Check if the public key is already in the cache
	if cachedKey, found := s.cache.Get(ctx, keyID); found {
		// Construct the JWK from the cached key
		return constructJWKFromPublicKey(cachedKey, signingMethod, keyID)
	}

	// Retrieve the public key from AWS KMS
	getPubKeyInput := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	}

	getPubKeyOutput, err := s.kmsClient.GetPublicKey(ctx, getPubKeyInput)
	if err != nil {
		return JWK{}, fmt.Errorf("failed to retrieve public key from KMS: %w", err)
	}

	// Parse the public key and store it in the cache
	publicKey, err := parsePublicKey(getPubKeyOutput.PublicKey, signingMethod)
	if err != nil {
		return JWK{}, fmt.Errorf("failed to parse public key: %w", err)
	}

	s.cache.Add(ctx, keyID, publicKey)

	// Construct the JWK from the retrieved public key
	return constructJWKFromPublicKey(publicKey, signingMethod, keyID)
}

// SigningMethod returns the JWT signing method corresponding to the KMS signing algorithm.
func (s *KMS) SigningMethod() jwt.SigningMethod {
	return getSigningMethod(s.alg)
}

// KeyID returns the ID of the KMS key used for signing.
func (s *KMS) KeyID() string {
	return s.keyID
}

// getSigningMethod maps the AWS KMS signing algorithm to a corresponding JWT signing method.
func getSigningMethod(alg types.SigningAlgorithmSpec) jwt.SigningMethod {
	// Return the appropriate signing method based on the algorithm
	switch alg { // nolint exhaustive
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		return jwt.SigningMethodRS256
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha384:
		return jwt.SigningMethodRS384
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha512:
		return jwt.SigningMethodRS512
	case types.SigningAlgorithmSpecRsassaPssSha256:
		return jwt.SigningMethodPS256
	case types.SigningAlgorithmSpecRsassaPssSha384:
		return jwt.SigningMethodPS384
	case types.SigningAlgorithmSpecRsassaPssSha512:
		return jwt.SigningMethodPS512
	case types.SigningAlgorithmSpecEcdsaSha256:
		return jwt.SigningMethodES256
	case types.SigningAlgorithmSpecEcdsaSha384:
		return jwt.SigningMethodES384
	case types.SigningAlgorithmSpecEcdsaSha512:
		return jwt.SigningMethodES512
	default:
		return nil // Unsupported algorithm
	}
}

// parsePublicKey parses a raw public key into a crypto.PublicKey based on the JWT signing method.
func parsePublicKey(rawKey []byte, signingMethod jwt.SigningMethod) (crypto.PublicKey, error) {
	switch signingMethod {
	case jwt.SigningMethodRS256, jwt.SigningMethodRS384, jwt.SigningMethodRS512,
		jwt.SigningMethodPS256, jwt.SigningMethodPS384, jwt.SigningMethodPS512:
		// Parse RSA public key
		block := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: rawKey,
		}
		pemEncodedKey := pem.EncodeToMemory(block)

		return jwt.ParseRSAPublicKeyFromPEM(pemEncodedKey)
	case jwt.SigningMethodES256, jwt.SigningMethodES384, jwt.SigningMethodES512:
		// Parse EC public key
		return jwt.ParseECPublicKeyFromPEM(rawKey)
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", signingMethod.Alg())
	}
}

// constructJWKFromPublicKey constructs a JWK from a given public key, signing method, and key ID.
func constructJWKFromPublicKey(publicKey crypto.PublicKey, signingMethod jwt.SigningMethod, keyID string) (JWK, error) {
	switch pubKey := publicKey.(type) {
	case *rsa.PublicKey:
		return JWK{
			Kty: "RSA",
			Alg: signingMethod.Alg(),
			Use: "sig",
			Kid: keyID,
			N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}, nil
	case *ecdsa.PublicKey:
		return JWK{
			Kty: "EC",
			Alg: signingMethod.Alg(),
			Use: "sig",
			Kid: keyID,
			Crv: pubKey.Curve.Params().Name, // Canonical curve name (e.g., P-256)
			X:   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
		}, nil
	default:
		return JWK{}, fmt.Errorf("unsupported public key type")
	}
}
