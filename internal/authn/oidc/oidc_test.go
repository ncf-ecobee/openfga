package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/openfga/openfga/internal/authn"
)

func TestRemoteOidcAuthenticator_Authenticate(t *testing.T) {
	t.Run("when_the_authorization_header_is_missing_from_the_gRPC_metadata_of_the_request,_returns_'missing_bearer_token'_error", func(t *testing.T) {
		authenticator := &RemoteOidcAuthenticator{}
		_, err := authenticator.Authenticate(context.Background())
		require.Equal(t, authn.ErrMissingBearerToken, err)
	})
	errorTestCases := []struct {
		testDescription string
		testSetup       func() (*RemoteOidcAuthenticator, context.Context, Config, error)
		expectedError   string
	}{
		{
			testDescription: "when_the_token_has_expired,_return_'invalid_bearer_token'",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_1",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"iss": "right_issuer",
						"aud": "right_audience",
						"sub": "openfga client",
						"exp": time.Now().Add(-10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
			expectedError: "invalid claims",
		},
		{
			testDescription: "when_no_expiration_set,_return_'invalid_bearer_token'",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_1",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"iss": "right_issuer",
						"aud": "right_audience",
						"sub": "openfga client",
					},
					privateKeyOverride: nil,
				})
			},
			expectedError: "invalid claims",
		},
		{
			testDescription: "when_the_JWT_contains_a_future_'iat',_return_'invalid_bearer_token'",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_1",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"iss": "right_issuer",
						"aud": "right_audience",
						"sub": "openfga client",
						"iat": time.Now().Add(10 * time.Minute).Unix(),
						"exp": time.Now().Add(100 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
			expectedError: "invalid claims",
		},
		{
			testDescription: "when_JWT_and_JWK_kid_don't_match,_returns_'invalid_bearer_token'",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_2",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"exp": time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
			expectedError: "invalid claims",
		},
		{
			testDescription: "when_token_is_signed_using_different_public/private_key_pairs,_returns__'invalid_bearer_token'",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				privateKey, _ := generateJWTSignatureKeys()
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_1",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"exp": time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: privateKey,
				})
			},
			expectedError: "invalid claims",
		},
		{
			testDescription: "when_token's_issuer_does_not_match_the_one_provided_in_the_server_configuration,_MUST_return_'invalid_issuer'_error",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_1",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"iss": "wrong_issuer",
						"aud": "right_audience",
						"exp": time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
			expectedError: "invalid claims",
		},
		{
			testDescription: "when_token's_audience_does_not_match_the_one_provided_in_the_server_configuration,_MUST_return_'invalid_audience'_error",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_1",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"iss": "right_issuer",
						"aud": "wrong_audience",
						"exp": time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
			expectedError: "invalid claims",
		},
		{
			testDescription: "when_the_subject_of_the_token_is_not_a_string,_MUST_return_'invalid_subject'_error",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_1",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"iss": "right_issuer",
						"aud": "right_audience",
						"sub": 12,
						"exp": time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
			expectedError: "invalid claims",
		},
		{
			testDescription: "when_the_subject_of_the_token_is_a_string_but_subject_is_not_valid,_MUST_return_'invalid_subject'_error",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_1",
					jwtKid:         "kid_1",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"valid-sub-1", "valid-sub-2"},
					clientIDClaims: []string{"azp"},
					jwtClaims: jwt.MapClaims{
						"iss": "right_issuer",
						"aud": "right_audience",
						"sub": "openfga client",
						"exp": time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
			expectedError: "invalid claims",
		},
	}

	for _, testC := range errorTestCases {
		t.Run(testC.testDescription, func(t *testing.T) {
			if testC.expectedError == "" {
				t.Fatal("this suite is to test error cases and this test didn't have an error expectation")
			}
			oidc, requestContext, _, _ := testC.testSetup()
			_, err := oidc.Authenticate(requestContext)
			require.Contains(t, err.Error(), testC.expectedError)
		})
	}

	// Success testcases

	azpClientIDClaims := []string{"azp"}
	clientID := "client-id"
	customClientIDClaims := []string{"custom-id"}
	customClientID := "custom-client-id"
	scopes := "offline_access read write delete"
	successTestCases := []struct {
		testDescription string
		testSetup       func() (*RemoteOidcAuthenticator, context.Context, Config, error)
	}{
		{
			testDescription: "when_the_token_is_valid,_it_MUST_return_the_token_subject_and_its_associated_scopes",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_2",
					jwtKid:         "kid_2",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       []string{"openfga client"},
					clientIDClaims: azpClientIDClaims,
					jwtClaims: jwt.MapClaims{
						"iss":   "right_issuer",
						"aud":   "right_audience",
						"sub":   "openfga client",
						"azp":   clientID,
						"scope": scopes,
						"exp":   time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
		},
		{
			testDescription: "when_the_token_is_valid_with_issuer_alias,_it_MUST_return_the_token_subject_and_its_associated_scopes",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_2",
					jwtKid:         "kid_2",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  []string{"issuer_alias"},
					subjects:       []string{"openfga client"},
					clientIDClaims: customClientIDClaims,
					jwtClaims: jwt.MapClaims{
						"iss":       "issuer_alias",
						"aud":       "right_audience",
						"sub":       "openfga client",
						"custom-id": customClientID,
						"scope":     scopes,
						"exp":       time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
		},
		{
			testDescription: "when_issuer_alias_set_token_is_valid_with_orig_issuer,_it_MUST_return_the_token_subject_and_its_associated_scopes",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_2",
					jwtKid:         "kid_2",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  []string{"issuer_alias"},
					subjects:       []string{"openfga client"},
					clientIDClaims: azpClientIDClaims,
					jwtClaims: jwt.MapClaims{
						"iss":   "right_issuer",
						"aud":   "right_audience",
						"sub":   "openfga client",
						"azp":   clientID,
						"scope": scopes,
						"exp":   time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
		},
		{
			testDescription: "when_validation_subjects_is_empty_and_pass_any_sub,_it_MUST_return_the_token_subject_and_its_associated_scopes",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_2",
					jwtKid:         "kid_2",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       nil,
					clientIDClaims: azpClientIDClaims,
					jwtClaims: jwt.MapClaims{
						"iss":   "right_issuer",
						"aud":   "right_audience",
						"sub":   "some-user",
						"azp":   clientID,
						"scope": scopes,
						"exp":   time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
		},
		{
			testDescription: "when_client_id_claims_is_empty_use_azp_for_client_id",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_2",
					jwtKid:         "kid_2",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       nil,
					clientIDClaims: nil,
					jwtClaims: jwt.MapClaims{
						"iss":   "right_issuer",
						"aud":   "right_audience",
						"sub":   "some-user",
						"azp":   clientID,
						"scope": scopes,
						"exp":   time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
		},
		{
			testDescription: "when_client_id_claims_is_empty_and_azp_is_missing_use_client_id_for_client_id",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_2",
					jwtKid:         "kid_2",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       nil,
					clientIDClaims: nil,
					jwtClaims: jwt.MapClaims{
						"iss":       "right_issuer",
						"aud":       "right_audience",
						"sub":       "some-user",
						"client_id": clientID,
						"scope":     scopes,
						"exp":       time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
		},
		{
			testDescription: "when_client_id_claims_is_set_use_first_existing_claim_as_client_id",
			testSetup: func() (*RemoteOidcAuthenticator, context.Context, Config, error) {
				return quickConfigSetup(Config{
					jwkKid:         "kid_2",
					jwtKid:         "kid_2",
					issuerURL:      "right_issuer",
					audience:       "right_audience",
					issuerAliases:  nil,
					subjects:       nil,
					clientIDClaims: []string{"custom_claim", "custom_claim_2"},
					jwtClaims: jwt.MapClaims{
						"iss":            "right_issuer",
						"aud":            "right_audience",
						"sub":            "some-user",
						"custom_claim_2": customClientID,
						"scope":          scopes,
						"exp":            time.Now().Add(10 * time.Minute).Unix(),
					},
					privateKeyOverride: nil,
				})
			},
		},
	}

	for _, testC := range successTestCases {
		t.Run(testC.testDescription, func(t *testing.T) {
			oidc, requestContext, config, err := testC.testSetup()
			if err != nil {
				t.Fatal(err)
			}
			authClaims, err := oidc.Authenticate(requestContext)
			require.NoError(t, err)

			// only verify subjects when authn.oidc.subjects is not empty
			// when it is empty, it indicates any 'sub' should pass
			if len(oidc.Subjects) != 0 {
				require.Equal(t, "openfga client", authClaims.Subject)
			}

			// only verify default clientIDClaims when clientIDClaims are not set,
			// or are set to the defaults
			if config.clientIDClaims == nil || config.clientIDClaims[0] == azpClientIDClaims[0] {
				require.Equal(t, clientID, authClaims.ClientID)
			} else {
				require.Equal(t, customClientID, authClaims.ClientID)
			}

			scopesList := strings.Split(scopes, " ")
			require.Len(t, authClaims.Scopes, len(scopesList))
			for _, scope := range scopesList {
				_, ok := authClaims.Scopes[scope]
				require.True(t, ok)
			}
		})
	}
}

func TestNewRemoteOidcAuthenticator_RequiresIssuerAndAudience(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		audience    string
		expectedErr error
	}{
		{
			name:        "empty_issuer_returns_error",
			issuer:      "",
			audience:    "some-audience",
			expectedErr: ErrMissingIssuer,
		},
		{
			name:        "empty_audience_returns_error",
			issuer:      "https://issuer.example.com",
			audience:    "",
			expectedErr: ErrMissingAudience,
		},
		{
			name:        "both_empty_returns_issuer_error_first",
			issuer:      "",
			audience:    "",
			expectedErr: ErrMissingIssuer,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRemoteOidcAuthenticator(tc.issuer, nil, tc.audience, nil, nil)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}

	t.Run("valid_issuer_and_audience_constructs_successfully", func(t *testing.T) {
		orig := fetchJWKs
		t.Cleanup(func() { fetchJWKs = orig })
		_, publicKey := generateJWTSignatureKeys()
		fetchJWKs = fetchKeysMock(publicKey, "kid_1")
		_, err := NewRemoteOidcAuthenticator("https://issuer.example.com", nil, "some-audience", nil, nil)
		require.NoError(t, err)
	})

	// whitespace is a valid StringOrURI per RFC 7519 §4.1.1 and §4.1.3; whitespace-only issuer and audience must be accepted
	t.Run("whitespace_issuer_is_valid", func(t *testing.T) {
		orig := fetchJWKs
		t.Cleanup(func() { fetchJWKs = orig })
		_, publicKey := generateJWTSignatureKeys()
		fetchJWKs = fetchKeysMock(publicKey, "kid_1")
		_, err := NewRemoteOidcAuthenticator("   ", nil, "some-audience", nil, nil)
		require.NoError(t, err)
	})

	t.Run("whitespace_audience_is_valid", func(t *testing.T) {
		orig := fetchJWKs
		t.Cleanup(func() { fetchJWKs = orig })
		_, publicKey := generateJWTSignatureKeys()
		fetchJWKs = fetchKeysMock(publicKey, "kid_1")
		_, err := NewRemoteOidcAuthenticator("https://issuer.example.com", nil, "   ", nil, nil)
		require.NoError(t, err)
	})
}

func TestValidateSigningAlgorithms(t *testing.T) {
	tests := []struct {
		name              string
		signingAlgorithms []string
		expectedErr       error
		expectedMessage   string
	}{
		{
			name:              "empty_means_the_default_applies",
			signingAlgorithms: nil,
		},
		{
			name:              "RS256_is_supported",
			signingAlgorithms: []string{"RS256"},
		},
		{
			name:              "ES256_is_supported",
			signingAlgorithms: []string{"ES256"},
		},
		{
			name:              "RS256_and_ES256_can_be_combined",
			signingAlgorithms: []string{"RS256", "ES256"},
		},
		{
			name:              "every_supported_algorithm_is_accepted",
			signingAlgorithms: SupportedSigningAlgorithms(),
		},
		// a symmetric algorithm would let anyone holding a key from the issuer's JWKS forge tokens,
		// so the error says why rather than leaving it to look like an unimplemented algorithm
		{
			name:              "HS256_is_rejected",
			signingAlgorithms: []string{"HS256"},
			expectedErr:       ErrUnsupportedSigningAlgorithm,
			expectedMessage:   "only asymmetric algorithms can be trusted",
		},
		{
			name:              "none_is_rejected",
			signingAlgorithms: []string{"none"},
			expectedErr:       ErrUnsupportedSigningAlgorithm,
			expectedMessage:   "only asymmetric algorithms can be trusted",
		},
		{
			name:              "an_unknown_algorithm_is_rejected",
			signingAlgorithms: []string{"not-an-algorithm"},
			expectedErr:       ErrUnsupportedSigningAlgorithm,
			expectedMessage:   "expected one of",
		},
		{
			name:              "algorithm_names_are_case_sensitive",
			signingAlgorithms: []string{"es256"},
			expectedErr:       ErrUnsupportedSigningAlgorithm,
		},
		// nothing trims the entries, so `RS256, ES256` in a config file or environment variable
		// yields a second entry of " ES256", which must be reported rather than quietly ignored
		{
			name:              "an_entry_with_surrounding_whitespace_is_rejected",
			signingAlgorithms: []string{"RS256", " ES256"},
			expectedErr:       ErrUnsupportedSigningAlgorithm,
		},
		{
			name:              "one_unsupported_algorithm_rejects_the_whole_list",
			signingAlgorithms: []string{"RS256", "HS256"},
			expectedErr:       ErrUnsupportedSigningAlgorithm,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSigningAlgorithms(tc.signingAlgorithms)
			if tc.expectedErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.expectedErr)
			if tc.expectedMessage != "" {
				require.Contains(t, err.Error(), tc.expectedMessage)
			}
		})
	}
}

func TestNewRemoteOidcAuthenticator_SigningAlgorithms(t *testing.T) {
	tests := []struct {
		name               string
		options            []RemoteOidcAuthenticatorOption
		expectedAlgorithms []string
	}{
		{
			name:               "defaults_to_RS256_when_unset",
			expectedAlgorithms: []string{"RS256"},
		},
		{
			name:               "an_empty_option_value_leaves_the_default_in_place",
			options:            []RemoteOidcAuthenticatorOption{WithSigningAlgorithms(nil)},
			expectedAlgorithms: []string{"RS256"},
		},
		{
			name:               "configured_algorithms_are_kept",
			options:            []RemoteOidcAuthenticatorOption{WithSigningAlgorithms([]string{"RS256", "ES256"})},
			expectedAlgorithms: []string{"RS256", "ES256"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withMockedJWKS(t)

			authenticator, err := NewRemoteOidcAuthenticator("https://issuer.example.com", nil, "some-audience", nil, nil, tc.options...)
			require.NoError(t, err)
			require.Equal(t, tc.expectedAlgorithms, authenticator.SigningAlgorithms)
		})
	}

	t.Run("an_unsupported_algorithm_fails_without_fetching_keys", func(t *testing.T) {
		orig := fetchJWKs
		t.Cleanup(func() { fetchJWKs = orig })
		fetched := false
		fetchJWKs = func(oidc *RemoteOidcAuthenticator) error {
			fetched = true
			return nil
		}

		_, err := NewRemoteOidcAuthenticator("https://issuer.example.com", nil, "some-audience", nil, nil,
			WithSigningAlgorithms([]string{"HS256"}))
		require.ErrorIs(t, err, ErrUnsupportedSigningAlgorithm)
		require.False(t, fetched, "keys must not be fetched when the configuration is invalid")
	})
}

func TestRemoteOidcAuthenticator_Authenticate_SigningAlgorithms(t *testing.T) {
	tests := []struct {
		testDescription   string
		jwkAlgorithm      string
		tokenAlgorithm    string
		signingAlgorithms []string
		expectAuthorized  bool
	}{
		{
			testDescription:   "an_ES256_token_is_accepted_when_ES256_is_configured",
			jwkAlgorithm:      "ES256",
			tokenAlgorithm:    "ES256",
			signingAlgorithms: []string{"ES256"},
			expectAuthorized:  true,
		},
		{
			testDescription:   "an_ES256_token_is_accepted_when_RS256_and_ES256_are_configured",
			jwkAlgorithm:      "ES256",
			tokenAlgorithm:    "ES256",
			signingAlgorithms: []string{"RS256", "ES256"},
			expectAuthorized:  true,
		},
		{
			testDescription:   "an_RS256_token_is_accepted_when_RS256_and_ES256_are_configured",
			jwkAlgorithm:      "RS256",
			tokenAlgorithm:    "RS256",
			signingAlgorithms: []string{"RS256", "ES256"},
			expectAuthorized:  true,
		},
		{
			testDescription:   "an_ES256_token_is_rejected_when_only_RS256_is_configured",
			jwkAlgorithm:      "ES256",
			tokenAlgorithm:    "ES256",
			signingAlgorithms: []string{"RS256"},
			expectAuthorized:  false,
		},
		{
			testDescription:   "an_RS256_token_is_rejected_when_only_ES256_is_configured",
			jwkAlgorithm:      "RS256",
			tokenAlgorithm:    "RS256",
			signingAlgorithms: []string{"ES256"},
			expectAuthorized:  false,
		},
	}

	for _, testC := range tests {
		t.Run(testC.testDescription, func(t *testing.T) {
			authenticator, requestContext := signingAlgorithmSetup(t, testC.jwkAlgorithm, testC.tokenAlgorithm, testC.signingAlgorithms)

			authClaims, err := authenticator.Authenticate(requestContext)
			if !testC.expectAuthorized {
				require.ErrorIs(t, err, errInvalidClaims)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "openfga client", authClaims.Subject)
		})
	}

	// the verification key is public, so an HMAC-signed token must never be trusted, per
	// https://www.rfc-editor.org/rfc/rfc8725#section-2.1
	t.Run("an_HS256_token_signed_with_the_issuer's_public_key_is_rejected", func(t *testing.T) {
		publicKey := withMockedJWKS(t)

		authenticator, err := NewRemoteOidcAuthenticator("right_issuer", nil, "right_audience", nil, nil,
			WithSigningAlgorithms([]string{"RS256", "ES256"}))
		require.NoError(t, err)

		_, err = authenticator.Authenticate(generateContext(forgeHS256Token(t, publicKey)))
		require.ErrorIs(t, err, errInvalidClaims)
	})

	// An authenticator built without the constructor has no signing algorithms set, which makes jwt
	// skip its algorithm check. The JWKS here publishes no "alg" either, as many real issuers do,
	// so this pins the behavior down to the authenticator itself.
	t.Run("an_authenticator_with_no_signing_algorithms_set_still_rejects_an_HS256_token", func(t *testing.T) {
		_, publicKey := generateJWTSignatureKeys()

		authenticator := &RemoteOidcAuthenticator{
			MainIssuer: "right_issuer",
			Audience:   "right_audience",
		}
		require.NoError(t, fetchKeysMockForAlgorithm(publicKey, "kid_1", "")(authenticator))
		require.Empty(t, authenticator.SigningAlgorithms)

		_, err := authenticator.Authenticate(generateContext(forgeHS256Token(t, publicKey)))
		require.ErrorIs(t, err, errInvalidClaims)
	})

	// The two cases above forge a token from a key the JWKS publishes as asymmetric, so HMAC
	// verification is handed an *rsa.PublicKey and fails on the key type alone, whatever the
	// accepted algorithms say. An issuer publishing an "oct" JWK removes that accident: keyfunc
	// decodes it to a byte slice, which HMAC verification accepts, so only the accepted-algorithms
	// list stands between the token and a successful verification.
	t.Run("an_HS256_token_signed_with_a_symmetric_key_from_the_JWKS_is_rejected", func(t *testing.T) {
		issuerURL, token := withSymmetricJWKS(t)

		authenticator, err := NewRemoteOidcAuthenticator(issuerURL, nil, "right_audience", nil, nil)
		require.NoError(t, err)
		t.Cleanup(authenticator.Close)
		require.Equal(t, DefaultSigningAlgorithms(), authenticator.SigningAlgorithms)

		_, err = authenticator.Authenticate(generateContext(token))
		require.ErrorIs(t, err, errInvalidClaims)
	})

	// Authenticate re-applies the default when SigningAlgorithms is empty. Drop that and this token
	// is accepted, because jwt skips the algorithm check for a nil list and the JWKS supplies a
	// working HMAC key.
	t.Run("an_authenticator_with_no_signing_algorithms_set_rejects_a_symmetric_JWKS_token", func(t *testing.T) {
		issuerURL, token := withSymmetricJWKS(t)

		authenticator := &RemoteOidcAuthenticator{
			MainIssuer: issuerURL,
			Audience:   "right_audience",
			httpClient: http.DefaultClient,
		}
		require.NoError(t, fetchJWK(authenticator))
		t.Cleanup(authenticator.Close)
		require.Empty(t, authenticator.SigningAlgorithms)

		_, err := authenticator.Authenticate(generateContext(token))
		require.ErrorIs(t, err, errInvalidClaims)
	})
}

// withSymmetricJWKS stands up an issuer whose JWKS publishes a single symmetric ("oct") key, and
// returns the issuer URL along with an HS256 token signed with that key whose claims are otherwise
// valid. The JWKS omits "alg", as many real issuers do, so keyfunc applies no algorithm check of its
// own and the authenticator's accepted-algorithms list is the only thing under test.
func withSymmetricJWKS(t *testing.T) (issuerURL, signedToken string) {
	t.Helper()
	withRealFetchJWK(t)

	const kid = "symmetric_kid"

	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "oct",
			"use": "sig",
			"kid": kid,
			"k":   base64.RawURLEncoding.EncodeToString(secret),
		}}})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   server.URL,
			"jwks_uri": server.URL + "/jwks",
		})
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	claims := validClaims()
	claims["iss"] = server.URL

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = kid
	signedToken, err = token.SignedString(secret)
	require.NoError(t, err)

	return server.URL, signedToken
}

// signingAlgorithmSetup builds an authenticator that trusts signingAlgorithms, whose issuer
// publishes a key for jwkAlgorithm, along with a request context carrying a token signed with
// tokenAlgorithm by that same key.
func signingAlgorithmSetup(t *testing.T, jwkAlgorithm, tokenAlgorithm string, signingAlgorithms []string) (*RemoteOidcAuthenticator, context.Context) {
	t.Helper()

	const kid = "kid_1"

	var privateKey crypto.Signer
	var publicKey any
	switch jwkAlgorithm {
	case "RS256":
		rsaPrivateKey, rsaPublicKey := generateJWTSignatureKeys()
		privateKey, publicKey = rsaPrivateKey, rsaPublicKey
	case "ES256":
		ecdsaPrivateKey, ecdsaPublicKey := generateES256SignatureKeys()
		privateKey, publicKey = ecdsaPrivateKey, ecdsaPublicKey
	default:
		t.Fatalf("unsupported JWK algorithm %q", jwkAlgorithm)
	}

	orig := fetchJWKs
	t.Cleanup(func() { fetchJWKs = orig })
	fetchJWKs = fetchKeysMockForAlgorithm(publicKey, kid, jwkAlgorithm)

	authenticator, err := NewRemoteOidcAuthenticator("right_issuer", nil, "right_audience", nil, nil,
		WithSigningAlgorithms(signingAlgorithms))
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.GetSigningMethod(tokenAlgorithm), validClaims())
	token.Header["kid"] = kid
	signedToken, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return authenticator, generateContext(signedToken)
}

type Config struct {
	jwkKid             string
	jwtKid             string
	issuerURL          string
	audience           string
	issuerAliases      []string
	subjects           []string
	clientIDClaims     []string
	jwtClaims          jwt.MapClaims
	privateKeyOverride *rsa.PrivateKey
}

// quickConfigSetup sets up a basic configuration for testing purposes.
func quickConfigSetup(c Config) (*RemoteOidcAuthenticator, context.Context, Config, error) {
	// Generate JWT signature keys
	privateKey, publicKey := generateJWTSignatureKeys()
	if c.privateKeyOverride != nil {
		privateKey = c.privateKeyOverride
	}
	// assign mocked JWKS fetching function to global function
	fetchJWKs = fetchKeysMock(publicKey, c.jwkKid)

	// Initialize RemoteOidcAuthenticator
	oidc, err := NewRemoteOidcAuthenticator(c.issuerURL, c.issuerAliases, c.audience, c.subjects, c.clientIDClaims)
	if err != nil {
		return nil, nil, c, err
	}

	// Generate JWT token
	token := generateJWT(privateKey, c.jwtKid, c.jwtClaims)

	// Generate context with JWT token
	requestContext := generateContext(token)

	return oidc, requestContext, c, nil
}

func generateContext(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

// generateJWTSignatureKeys generates a private key for signing JWT tokens
// and a corresponding public key for verifying JWT token signatures.
func generateJWTSignatureKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Private key cannot be created.", err.Error())
	}
	return privateKey, &privateKey.PublicKey
}

// generateES256SignatureKeys generates an ECDSA P-256 private key for signing ES256 JWT tokens
// and a corresponding public key for verifying ES256 JWT token signatures.
func generateES256SignatureKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Private key cannot be created.", err.Error())
	}
	return privateKey, &privateKey.PublicKey
}

// fetchKeysMock returns a function that sets up a mock JWKS.
func fetchKeysMock(publicKey *rsa.PublicKey, kid string) func(oidc *RemoteOidcAuthenticator) error {
	return fetchKeysMockForAlgorithm(publicKey, kid, "RS256")
}

// withMockedJWKS points the package-level key fetcher at a freshly generated RSA key for the
// duration of the test, and returns the matching public key.
func withMockedJWKS(t *testing.T) *rsa.PublicKey {
	t.Helper()

	orig := fetchJWKs
	t.Cleanup(func() { fetchJWKs = orig })
	_, publicKey := generateJWTSignatureKeys()
	fetchJWKs = fetchKeysMock(publicKey, "kid_1")

	return publicKey
}

// validClaims returns claims that satisfy every check the authenticator makes other than the
// signature, so that a test asserts on signing algorithms alone.
func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "right_issuer",
		"aud": "right_audience",
		"sub": "openfga client",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}
}

// forgeHS256Token signs a token with the issuer's public key used as an HMAC secret. It imitates a
// caller who knows the public key, because the issuer publishes it in its JWKS, and tries to pass
// off a symmetric signature as the issuer's own.
func forgeHS256Token(t *testing.T, publicKey *rsa.PublicKey) string {
	t.Helper()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
	token.Header["kid"] = "kid_1"
	forgedToken, err := token.SignedString(publicKeyBytes)
	require.NoError(t, err)

	return forgedToken
}

// fetchKeysMockForAlgorithm returns a function that sets up a mock JWKS holding the given public
// key for the given signing algorithm.
func fetchKeysMockForAlgorithm(publicKey any, kid, algorithm string) func(oidc *RemoteOidcAuthenticator) error {
	givenKeys := keyfunc.NewGivenCustom(publicKey, keyfunc.GivenKeyOptions{
		Algorithm: algorithm,
	})
	// Return a function that sets up the mock JWKS with the provided kid
	return func(oidc *RemoteOidcAuthenticator) error {
		jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
			kid: givenKeys,
		})
		oidc.JWKs = jwks
		return nil
	}
}

// generateJWT generates Json Web Tokens signed with the provided privateKey.
func generateJWT(privateKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("Failed to sign JWT token:", err)
	}
	return signedToken
}

// TestRemoteOidcAuthenticator_RefreshUnknownKID verifies that when the issuer
// rotates signing keys, a JWT signed by a kid that wasn't present at startup
// is accepted after the JWKS cache refreshes.
func TestRemoteOidcAuthenticator_RefreshUnknownKID(t *testing.T) {
	withRealFetchJWK(t)

	privKey1, pubKey1 := generateJWTSignatureKeys()
	privKey2, pubKey2 := generateJWTSignatureKeys()

	server := newJWKSTestServer(map[string]*rsa.PublicKey{"kid_1": pubKey1})
	defer server.close()

	oidc, err := NewRemoteOidcAuthenticator(server.server.URL, nil, "aud", nil, nil)
	require.NoError(t, err)
	defer oidc.Close()

	// Sanity: a token signed by the originally-known key validates.
	token1 := generateJWT(privKey1, "kid_1", jwt.MapClaims{
		"iss": server.server.URL,
		"aud": "aud",
		"sub": "some-user",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	_, err = oidc.Authenticate(generateContext(token1))
	require.NoError(t, err)

	hitsBeforeRotation := server.hits()

	// Issuer rotates: add kid_2 to the JWKS endpoint.
	server.setKey("kid_2", pubKey2)

	token2 := generateJWT(privKey2, "kid_2", jwt.MapClaims{
		"iss": server.server.URL,
		"aud": "aud",
		"sub": "some-user",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	})

	// keyfunc refreshes asynchronously when an unknown kid is seen, so the
	// first Authenticate may still fail; subsequent calls should succeed
	// once the background refresh lands.
	require.Eventually(t, func() bool {
		_, err := oidc.Authenticate(generateContext(token2))
		return err == nil
	}, 5*time.Second, 50*time.Millisecond, "expected JWKS refresh to pick up rotated kid_2")

	require.Greater(t, server.hits(), hitsBeforeRotation,
		"JWKS endpoint should have been re-fetched after an unknown kid was presented")
}

// TestRemoteOidcAuthenticator_RefreshRateLimit verifies that a burst of JWTs
// with different unknown kids triggers at most one JWKS refresh within the
// rate-limit window.
func TestRemoteOidcAuthenticator_RefreshRateLimit(t *testing.T) {
	withRealFetchJWK(t)

	originalLimit := jwkRefreshRateLimit
	jwkRefreshRateLimit = 2 * time.Second
	t.Cleanup(func() { jwkRefreshRateLimit = originalLimit })

	_, pubKey1 := generateJWTSignatureKeys()

	server := newJWKSTestServer(map[string]*rsa.PublicKey{"kid_1": pubKey1})
	defer server.close()

	oidc, err := NewRemoteOidcAuthenticator(server.server.URL, nil, "aud", nil, nil)
	require.NoError(t, err)
	defer oidc.Close()

	// Use a single RSA key for the whole burst. The signature is never
	// validated (none of these kids are in the JWKS), so key material is
	// irrelevant — only the distinct `kid` header matters. Generating one
	// key keeps the burst tight inside the jwkRefreshRateLimit window.
	const burst = 5
	privKey, _ := generateJWTSignatureKeys()

	hitsBeforeBurst := server.hits()

	// Burst several JWTs with distinct unknown kids in quick succession.
	for i := 0; i < burst; i++ {
		token := generateJWT(privKey, fmt.Sprintf("unknown_kid_%d", i), jwt.MapClaims{
			"iss": server.server.URL,
			"aud": "aud",
			"sub": "some-user",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
		})
		_, _ = oidc.Authenticate(generateContext(token))
	}

	// Wait for the (single) in-flight refresh to land.
	require.Eventually(t, func() bool {
		return server.hits() > hitsBeforeBurst
	}, 2*time.Second, 25*time.Millisecond, "expected at least one refresh after burst of unknown kids")

	// Give a brief grace window to catch any extra refreshes that might fire.
	time.Sleep(200 * time.Millisecond)

	extras := server.hits() - hitsBeforeBurst
	require.Equal(t, int32(1), extras,
		"RefreshRateLimit should bound extra JWKS refreshes to one within the window, got %d", extras)
}

// rsaPublicKeyToJWK encodes an RSA public key as a JWK (RFC 7517) entry.
func rsaPublicKeyToJWK(kid string, pub *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// jwksTestServer serves /.well-known/openid-configuration and a JWKS endpoint
// backed by a mutable key set. It counts hits to the JWKS endpoint so tests
// can assert on refresh behavior.
type jwksTestServer struct {
	mu       sync.Mutex
	keys     map[string]*rsa.PublicKey
	jwksHits int32
	server   *httptest.Server
}

func newJWKSTestServer(initial map[string]*rsa.PublicKey) *jwksTestServer {
	j := &jwksTestServer{keys: make(map[string]*rsa.PublicKey)}
	for k, v := range initial {
		j.keys[k] = v
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&j.jwksHits, 1)
		j.mu.Lock()
		defer j.mu.Unlock()
		jwkList := make([]map[string]string, 0, len(j.keys))
		for kid, pk := range j.keys {
			jwkList = append(jwkList, rsaPublicKeyToJWK(kid, pk))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": jwkList})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   j.server.URL,
			"jwks_uri": j.server.URL + "/jwks",
		})
	})

	j.server = httptest.NewServer(mux)
	return j
}

func (j *jwksTestServer) setKey(kid string, pk *rsa.PublicKey) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.keys[kid] = pk
}

func (j *jwksTestServer) hits() int32 {
	return atomic.LoadInt32(&j.jwksHits)
}

func (j *jwksTestServer) close() {
	j.server.Close()
}

// withRealFetchJWK ensures the package-level fetchJWKs is the real one for
// this test, even if a prior test mutated it.
func withRealFetchJWK(t *testing.T) {
	t.Helper()
	prev := fetchJWKs
	fetchJWKs = fetchJWK
	t.Cleanup(func() { fetchJWKs = prev })
}
