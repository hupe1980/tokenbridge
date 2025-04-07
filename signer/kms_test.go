package signer

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type mockKMSClient struct{}

func (m *mockKMSClient) Sign(_ context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	// Mock signature output
	return &kms.SignOutput{
		Signature: []byte("mock-signature"),
	}, nil
}

func (m *mockKMSClient) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	// Mock public key output with a valid PEM-encoded RSA public key
	return &kms.GetPublicKeyOutput{
		PublicKey: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmyljH/ptppF0bKdlK6rk
rxg1CDcUi8lSOkprHkLyjdWoRdB41si4FUhqfyJZpw46OXT+EdJkKwZt5DPWnDVP
GAuwHmYt8RQP6cwLhbIqSkcx+xYA4l7q9lTpbljqKBz6iq7JtkcYyDVkirLJRWGm
CumprwuWjQ8nD72JyVHsMSE3JE4LyVRAF4sRIfJR9/KfEnuS8TXdbM+PYZBIuLu3
wTJ+PXciAcYxES9y68HPR98hnsn/GWn3Pu3sVSKIGbGZR0ETRPC5o7T5aS2idbk2
hDRvAPwLsyRI/Qp8p/6Oyn10i7y+yMJA6/nXJoXMRAGNy38MhkV/eUIvK2FCuh5D
oQIDAQAB
-----END PUBLIC KEY-----`),
	}, nil
}

func TestKMSSigner(t *testing.T) {
	mockClient := &mockKMSClient{}
	keyID := "kms-key-id"
	alg := types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	kmsSigner := NewKMS(mockClient, keyID, alg)

	t.Run("SignToken", func(t *testing.T) {
		// Create a JWT token
		token := jwt.NewWithClaims(kmsSigner.SigningMethod(), jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(), // Token expires in 1 hour
		})

		// Add the Key ID (kid) to the token header
		token.Header["kid"] = kmsSigner.KeyID()

		// Sign the token
		tokenString, err := kmsSigner.SignToken(context.Background(), token)
		assert.NoError(t, err, "SignToken should not return an error")
		assert.NotEmpty(t, tokenString, "Signed token should not be empty")
	})

	t.Run("GetJWKS", func(t *testing.T) {
		// Retrieve the JWKS
		jwks, err := kmsSigner.GetJWKS(context.Background())
		assert.NoError(t, err, "GetJWKS should not return an error")
		assert.NotNil(t, jwks, "JWKS should not be nil")
		assert.Len(t, jwks.Keys, 1, "JWKS should contain exactly one key")

		// Validate the JWK
		jwk := jwks.Keys[0]
		assert.Equal(t, "RSA", jwk.Kty, "JWK key type should be 'RSA'")
		assert.Equal(t, "RS256", jwk.Alg, "JWK algorithm should be 'RS256'")
		assert.Equal(t, "sig", jwk.Use, "JWK use should be 'sig'")
		assert.Equal(t, keyID, jwk.Kid, "JWK key ID should match the configured key ID")
	})

	t.Run("SigningMethod", func(t *testing.T) {
		// Ensure the correct signing method is returned
		signingMethod := kmsSigner.SigningMethod()
		assert.Equal(t, jwt.SigningMethodRS256, signingMethod, "Signing method should be RS256")
	})

	t.Run("KeyID", func(t *testing.T) {
		// Ensure the correct key ID is returned
		assert.Equal(t, keyID, kmsSigner.KeyID(), "KeyID should match the configured key ID")
	})
}
