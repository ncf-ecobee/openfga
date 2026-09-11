package mocks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type mockOidcServer struct {
	issuerURL     string
	signingMethod jwt.SigningMethod
	privateKey    crypto.Signer
	jwk           map[string]string
	httpServer    *http.Server
}

const kidHeader = "1"

// NewMockOidcServer creates a mock OIDC server with the given issuer URL and a random RSA private
// key, signing tokens with RS256.
// You must call Stop afterward.
func NewMockOidcServer(issuerURL string) (*mockOidcServer, error) {
	return NewMockOidcServerWithAlgorithm(issuerURL, "RS256")
}

// NewMockOidcServerWithAlgorithm creates a mock OIDC server with the given issuer URL and a random
// private key for the given JWT signing algorithm. The published JWKS holds the matching public key.
// You must call Stop afterward.
func NewMockOidcServerWithAlgorithm(issuerURL, algorithm string) (*mockOidcServer, error) {
	signingMethod, privateKey, jwk, err := generateSigningKey(algorithm)
	if err != nil {
		return nil, err
	}

	mockServer := &mockOidcServer{
		issuerURL:     issuerURL,
		signingMethod: signingMethod,
		privateKey:    privateKey,
		jwk:           jwk,
	}

	mockServer.httpServer = createHTTPServer(issuerURL, jwk)
	go mockServer.start()
	return mockServer, nil
}

// NewAliasMockServer creates an alias server of a mock OIDC server that was created by NewMockOidcServer.
// You must call Stop afterward.
func (server *mockOidcServer) NewAliasMockServer(aliasURL string) *mockOidcServer {
	mockServer := &mockOidcServer{
		issuerURL:     aliasURL,
		signingMethod: server.signingMethod,
		privateKey:    server.privateKey,
		jwk:           server.jwk,
	}

	mockServer.httpServer = createHTTPServer(aliasURL, mockServer.jwk)
	go mockServer.start()
	return mockServer
}

// generateSigningKey returns the signing method, a freshly generated private key, and the JWK
// (RFC 7517) describing the matching public key, for the given JWT signing algorithm.
func generateSigningKey(algorithm string) (jwt.SigningMethod, crypto.Signer, map[string]string, error) {
	switch algorithm {
	case "RS256":
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, nil, err
		}
		publicKey := privateKey.Public().(*rsa.PublicKey)
		return jwt.SigningMethodRS256, privateKey, map[string]string{
			"kid": kidHeader,
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}, nil
	case "ES256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		publicKey := privateKey.Public().(*ecdsa.PublicKey)
		// RFC 7518 §6.2.1.2 requires each coordinate to be padded to the full byte length of the curve
		coordinateLength := (publicKey.Curve.Params().BitSize + 7) / 8
		return jwt.SigningMethodES256, privateKey, map[string]string{
			"kid": kidHeader,
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(publicKey.X.FillBytes(make([]byte, coordinateLength))),
			"y":   base64.RawURLEncoding.EncodeToString(publicKey.Y.FillBytes(make([]byte, coordinateLength))),
		}, nil
	default:
		return nil, nil, nil, fmt.Errorf("mock OIDC server does not support signing algorithm %q", algorithm)
	}
}

func createHTTPServer(issuerURL string, jwk map[string]string) *http.Server {
	addr := strings.Split(issuerURL, "http://")[1]

	mockHandler := http.NewServeMux()

	mockHandler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + "/jwks.json",
		})
		if err != nil {
			log.Fatalf("failed to json encode the openid configurations: %v", err)
		}
	})

	mockHandler.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{jwk},
		})
		if err != nil {
			log.Fatalf("failed to json encode the jwks keys: %v", err)
		}
	})

	return &http.Server{Addr: addr, Handler: mockHandler}
}

func (server *mockOidcServer) start() {
	if err := server.httpServer.ListenAndServe(); err != nil {
		if err != http.ErrServerClosed {
			log.Fatal("failed to start mock OIDC server", zap.Error(err))
		}
	}
	log.Println("mock OIDC server shut down.")
}

func (server *mockOidcServer) Stop() {
	if server.httpServer != nil {
		_ = server.httpServer.Shutdown(context.Background())
	}
}

func (server *mockOidcServer) GetToken(audience, subject string) (string, error) {
	token := jwt.NewWithClaims(server.signingMethod, jwt.RegisteredClaims{
		Issuer:    server.issuerURL,
		Audience:  []string{audience},
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
	})
	token.Header["kid"] = kidHeader
	return token.SignedString(server.privateKey)
}
