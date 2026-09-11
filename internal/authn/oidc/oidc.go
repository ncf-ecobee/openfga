package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	grpcauth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/hashicorp/go-retryablehttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/openfga/openfga/internal/authn"
	"github.com/openfga/openfga/pkg/authclaims"
)

type RemoteOidcAuthenticator struct {
	MainIssuer        string
	IssuerAliases     []string
	Audience          string
	Subjects          []string
	ClientIDClaims    []string
	SigningAlgorithms []string

	JwksURI string
	JWKs    *keyfunc.JWKS

	httpClient *http.Client
}

// RemoteOidcAuthenticatorOption configures optional behavior of a RemoteOidcAuthenticator.
type RemoteOidcAuthenticatorOption func(*RemoteOidcAuthenticator)

// WithSigningAlgorithms sets the JWT signing algorithms the authenticator accepts. An empty
// slice leaves the default in place.
func WithSigningAlgorithms(signingAlgorithms []string) RemoteOidcAuthenticatorOption {
	return func(oidc *RemoteOidcAuthenticator) {
		oidc.SigningAlgorithms = slices.Clone(signingAlgorithms)
	}
}

var (
	jwkRefreshInterval  = 48 * time.Hour
	jwkRefreshRateLimit = 1 * time.Minute

	errInvalidClaims = status.Error(codes.Code(openfgav1.AuthErrorCode_invalid_claims), "invalid claims")
	fetchJWKs        = fetchJWK
)

var (
	ErrMissingIssuer               = errors.New("oidc: issuer must be set")
	ErrMissingAudience             = errors.New("oidc: audience must be set")
	ErrUnsupportedSigningAlgorithm = errors.New("oidc: unsupported signing algorithm")
)

// supportedSigningAlgorithms lists the JWT signing algorithms an operator may configure. The set is
// every signing method golang-jwt registers, minus the symmetric ones and "none", so it is what this
// codebase can actually verify rather than a curated selection. Each entry is a registered JWS "alg"
// value (RFC 7518 §3.1, plus RFC 8037 for EdDSA) and names a scheme FIPS 186-5 approves.
//
// Excluding the HS family departs from RFC 7518 §3.1, which marks HS256 Required, and does so
// deliberately. The verification key here comes from the issuer's public JWKS, and keyfunc decodes a
// symmetric ("oct") JWK to a byte slice, which is exactly what HMAC verification accepts. An issuer
// publishing such a key would therefore let anyone able to read the JWKS sign tokens that verify.
// See RFC 8725 §2.1 and §3.1.
var supportedSigningAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// refusedSigningAlgorithms are the registered signing methods deliberately left out of
// supportedSigningAlgorithms. They are named so that configuring one draws an explanation rather
// than an error that reads like an unimplemented feature.
var refusedSigningAlgorithms = []string{"HS256", "HS384", "HS512", "none"}

// DefaultSigningAlgorithms returns the signing algorithms accepted when the operator configures
// none. It stays limited to RS256 so that upgrading does not widen the set of signatures an
// existing deployment trusts.
func DefaultSigningAlgorithms() []string {
	return []string{"RS256"}
}

// SupportedSigningAlgorithms returns the signing algorithms an operator may configure.
func SupportedSigningAlgorithms() []string {
	return slices.Clone(supportedSigningAlgorithms)
}

// ValidateSigningAlgorithms returns an error unless every given algorithm is one OpenFGA accepts
// for OIDC token verification. An empty slice is valid and means DefaultSigningAlgorithms applies.
//
// Entries are compared verbatim. Nothing here trims whitespace, matching how the neighbouring OIDC
// settings treat it as significant, so `RS256, ES256` in a config file or environment variable is
// reported as an unsupported algorithm rather than quietly accepted.
func ValidateSigningAlgorithms(signingAlgorithms []string) error {
	for _, signingAlgorithm := range signingAlgorithms {
		if slices.Contains(supportedSigningAlgorithms, signingAlgorithm) {
			continue
		}

		if slices.Contains(refusedSigningAlgorithms, signingAlgorithm) {
			return fmt.Errorf("%w %q: the verification key is fetched from the issuer's public JWKS, so only asymmetric algorithms can be trusted, one of %v",
				ErrUnsupportedSigningAlgorithm, signingAlgorithm, supportedSigningAlgorithms)
		}

		return fmt.Errorf("%w %q, expected one of %v", ErrUnsupportedSigningAlgorithm, signingAlgorithm, supportedSigningAlgorithms)
	}

	return nil
}

var _ authn.Authenticator = (*RemoteOidcAuthenticator)(nil)
var _ authn.OIDCAuthenticator = (*RemoteOidcAuthenticator)(nil)

func NewRemoteOidcAuthenticator(mainIssuer string, issuerAliases []string, audience string, subjects []string, clientIDClaims []string, opts ...RemoteOidcAuthenticatorOption) (*RemoteOidcAuthenticator, error) {
	// both issuer and audience are StringOrURI values (RFC 7519 §4.1.1, §4.1.3); whitespace is valid, so only reject strictly empty
	if mainIssuer == "" {
		return nil, ErrMissingIssuer
	}
	if audience == "" {
		return nil, ErrMissingAudience
	}

	client := retryablehttp.NewClient()
	client.Logger = nil
	oidc := &RemoteOidcAuthenticator{
		MainIssuer:        mainIssuer,
		IssuerAliases:     issuerAliases,
		Audience:          audience,
		Subjects:          subjects,
		httpClient:        client.StandardClient(),
		ClientIDClaims:    clientIDClaims,
		SigningAlgorithms: DefaultSigningAlgorithms(),
	}

	for _, opt := range opts {
		opt(oidc)
	}

	if len(oidc.SigningAlgorithms) == 0 {
		oidc.SigningAlgorithms = DefaultSigningAlgorithms()
	}

	// validate before fetching keys so that a misconfigured algorithm fails without a network call
	if err := ValidateSigningAlgorithms(oidc.SigningAlgorithms); err != nil {
		return nil, err
	}

	// Client ID is:
	// 1. If the user has set it in configuration, use that
	// 2, If the user has not set it in configuration, use the following as default:
	// 2.a. Use `azp`: the OpenID standard https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	// 3.b. Use `client_id` in RFC9068 https://www.rfc-editor.org/rfc/rfc9068.html#name-data-structure
	if len(oidc.ClientIDClaims) == 0 {
		oidc.ClientIDClaims = []string{"azp", "client_id"}
	}

	err := fetchJWKs(oidc)
	if err != nil {
		return nil, err
	}
	return oidc, nil
}

func (oidc *RemoteOidcAuthenticator) Authenticate(requestContext context.Context) (*authclaims.AuthClaims, error) {
	authHeader, err := grpcauth.AuthFromMD(requestContext, "Bearer")
	if err != nil {
		return nil, authn.ErrMissingBearerToken
	}

	// never hand an empty list to jwt.WithValidMethods: the parser skips the algorithm check
	// entirely when the list is nil, and keyfunc decodes a symmetric ("oct") JWK to a byte slice.
	// An issuer whose JWKS carries such a key would hand HMAC verification the very key type it
	// accepts, so an HS256 token would verify. Re-applying the default is what prevents that.
	signingAlgorithms := oidc.SigningAlgorithms
	if len(signingAlgorithms) == 0 {
		signingAlgorithms = DefaultSigningAlgorithms()
	}

	options := []jwt.ParserOption{
		jwt.WithValidMethods(signingAlgorithms),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	}

	// constructor enforces non-empty Audience; unconditional to make the invariant explicit
	options = append(options, jwt.WithAudience(oidc.Audience))

	jwtParser := jwt.NewParser(options...)

	token, err := jwtParser.Parse(authHeader, func(token *jwt.Token) (any, error) {
		return oidc.JWKs.Keyfunc(token)
	})
	if err != nil || !token.Valid {
		return nil, errInvalidClaims
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errInvalidClaims
	}

	validIssuers := []string{
		oidc.MainIssuer,
	}
	validIssuers = append(validIssuers, oidc.IssuerAliases...)

	ok = slices.ContainsFunc(validIssuers, func(issuer string) bool {
		v := jwt.NewValidator(jwt.WithIssuer(issuer))
		err := v.Validate(claims)
		return err == nil
	})

	if !ok {
		return nil, errInvalidClaims
	}

	if len(oidc.Subjects) > 0 {
		ok = slices.ContainsFunc(oidc.Subjects, func(subject string) bool {
			v := jwt.NewValidator(jwt.WithSubject(subject))
			err := v.Validate(claims)
			return err == nil
		})
		if !ok {
			return nil, errInvalidClaims
		}
	}

	// optional subject
	var subject = ""
	if subjectClaim, ok := claims["sub"]; ok {
		if subject, ok = subjectClaim.(string); !ok {
			return nil, errInvalidClaims
		}
	}

	clientID := ""
	for _, claimString := range oidc.ClientIDClaims {
		clientID, ok = claims[claimString].(string)
		if ok {
			break
		}
	}

	principal := &authclaims.AuthClaims{
		Subject:  subject,
		Scopes:   make(map[string]bool),
		ClientID: clientID,
	}

	// optional scopes
	if scopeKey, ok := claims["scope"]; ok {
		if scope, ok := scopeKey.(string); ok {
			scopes := strings.Split(scope, " ")
			for _, s := range scopes {
				principal.Scopes[s] = true
			}
		}
	}

	return principal, nil
}

func fetchJWK(oidc *RemoteOidcAuthenticator) error {
	oidcConfig, err := oidc.GetConfiguration()
	if err != nil {
		return fmt.Errorf("error fetching OIDC configuration: %w", err)
	}

	oidc.JwksURI = oidcConfig.JWKsURI
	jwks, err := oidc.GetKeys()
	if err != nil {
		return fmt.Errorf("error fetching OIDC keys: %w", err)
	}

	oidc.JWKs = jwks

	return nil
}

func (oidc *RemoteOidcAuthenticator) GetKeys() (*keyfunc.JWKS, error) {
	jwks, err := keyfunc.Get(oidc.JwksURI, keyfunc.Options{
		Client:            oidc.httpClient,
		RefreshInterval:   jwkRefreshInterval,
		RefreshUnknownKID: true,
		RefreshRateLimit:  jwkRefreshRateLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching keys from %v: %w", oidc.JwksURI, err)
	}
	return jwks, nil
}

func (oidc *RemoteOidcAuthenticator) GetConfiguration() (*authn.OidcConfig, error) {
	wellKnown := strings.TrimSuffix(oidc.MainIssuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("error forming request to get OIDC: %w", err)
	}

	res, err := oidc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting OIDC: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code getting OIDC: %v", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	oidcConfig := &authn.OidcConfig{}
	if err := json.Unmarshal(body, oidcConfig); err != nil {
		return nil, fmt.Errorf("failed parsing document: %w", err)
	}

	if oidcConfig.Issuer == "" {
		return nil, errors.New("missing issuer value")
	}

	if oidcConfig.JWKsURI == "" {
		return nil, errors.New("missing jwks_uri value")
	}
	return oidcConfig, nil
}

func (oidc *RemoteOidcAuthenticator) Close() {
	oidc.JWKs.EndBackground()
}
