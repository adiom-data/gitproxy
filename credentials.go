package gitproxy

import (
	"context"
	"errors"
	"net/http"
)

var (
	ErrUnauthenticated = errors.New("gitproxy: unauthenticated")
	ErrForbidden       = errors.New("gitproxy: forbidden")
)

// Credentials are user/password material captured from the client or supplied
// for the upstream Git server.
type Credentials struct {
	Username string
	Password string
}

// BasicAuthRequest is passed to an Authenticator with Basic auth credentials
// the Git client presented to the proxy.
type BasicAuthRequest struct {
	HasCredentials bool
	Credentials    Credentials
}

// UpstreamAuthMode controls how the proxy handles Authorization on the upstream
// request after authentication and policy have succeeded.
type UpstreamAuthMode string

const (
	// UpstreamAuthReplace replaces inbound credentials with AuthResult.UpstreamCredentials.
	UpstreamAuthReplace UpstreamAuthMode = "replace"
	// UpstreamAuthNone forwards no Authorization credentials upstream.
	UpstreamAuthNone UpstreamAuthMode = "none"
	// UpstreamAuthPassThrough leaves the inbound Authorization header unchanged.
	UpstreamAuthPassThrough UpstreamAuthMode = "pass-through"
)

// AuthResult is returned by an Authenticator after it has verified the client,
// attached an application-defined session, and chosen how upstream
// Authorization should be handled.
type AuthResult[S any] struct {
	Session             S
	UpstreamAuthMode    UpstreamAuthMode
	UpstreamCredentials Credentials
}

// WithSession returns a copy of result with session attached for target and
// policy hooks.
func (r AuthResult[S]) WithSession(session S) AuthResult[S] {
	r.Session = session
	return r
}

// Authenticator verifies client credentials and returns replacement upstream
// credentials.
//
// Applications own the lookup policy: exchange a short-lived token, consult a
// database, mint a scoped upstream token, attach a session for policy checks,
// or reject the request.
type Authenticator[S any] interface {
	AuthenticateGit(context.Context, BasicAuthRequest) (AuthResult[S], error)
}

type AuthenticatorFunc[S any] func(context.Context, BasicAuthRequest) (AuthResult[S], error)

func (f AuthenticatorFunc[S]) AuthenticateGit(ctx context.Context, req BasicAuthRequest) (AuthResult[S], error) {
	return f(ctx, req)
}

// HTTPAuthRequest is passed to an HTTPAuthenticator for non-Basic or
// header-aware auth flows.
type HTTPAuthRequest struct {
	Request   *http.Request
	Repo      string
	Operation Operation
}

// HTTPAuthenticator can inspect the full inbound HTTP request before choosing
// upstream auth behavior.
type HTTPAuthenticator[S any] interface {
	AuthenticateGitHTTP(context.Context, HTTPAuthRequest) (AuthResult[S], error)
}

type HTTPAuthenticatorFunc[S any] func(context.Context, HTTPAuthRequest) (AuthResult[S], error)

func (f HTTPAuthenticatorFunc[S]) AuthenticateGitHTTP(ctx context.Context, req HTTPAuthRequest) (AuthResult[S], error) {
	return f(ctx, req)
}

type httpAuthenticatorAdapter[S any] struct {
	auth HTTPAuthenticator[S]
}

func (a httpAuthenticatorAdapter[S]) AuthenticateGit(ctx context.Context, req BasicAuthRequest) (AuthResult[S], error) {
	return AuthResult[S]{}, ErrUnauthenticated
}

func (a httpAuthenticatorAdapter[S]) AuthenticateGitHTTP(ctx context.Context, req HTTPAuthRequest) (AuthResult[S], error) {
	return a.auth.AuthenticateGitHTTP(ctx, req)
}

// HeaderAuth adapts a lower-level HTTPAuthenticator for custom schemes such as
// Bearer tokens supplied via http.extraHeader.
func HeaderAuth[S any](auth HTTPAuthenticator[S]) Authenticator[S] {
	if auth == nil {
		return AuthenticatorFunc[S](func(context.Context, BasicAuthRequest) (AuthResult[S], error) {
			return AuthResult[S]{}, ErrUnauthenticated
		})
	}
	return httpAuthenticatorAdapter[S]{auth: auth}
}

// PassThroughAuth performs no authentication and forwards the inbound
// Authorization header unchanged.
func PassThroughAuth[S any]() Authenticator[S] {
	return AuthenticatorFunc[S](func(context.Context, BasicAuthRequest) (AuthResult[S], error) {
		return PassThroughCredentials[S](), nil
	})
}

// StaticCredentials always returns the same upstream credentials.
func StaticCredentials[S any](username, password string) Authenticator[S] {
	return AuthenticatorFunc[S](func(context.Context, BasicAuthRequest) (AuthResult[S], error) {
		return ReplaceCredentials[S](username, password), nil
	})
}

// ReplaceCredentials replaces the inbound Authorization header with upstream
// Basic auth credentials.
func ReplaceCredentials[S any](username, password string) AuthResult[S] {
	return AuthResult[S]{
		UpstreamAuthMode:    UpstreamAuthReplace,
		UpstreamCredentials: Credentials{Username: username, Password: password},
	}
}

// NoCredentials forwards no Authorization credentials upstream.
func NoCredentials[S any]() AuthResult[S] {
	return AuthResult[S]{UpstreamAuthMode: UpstreamAuthNone}
}

// PassThroughCredentials leaves the inbound Authorization header unchanged.
func PassThroughCredentials[S any]() AuthResult[S] {
	return AuthResult[S]{UpstreamAuthMode: UpstreamAuthPassThrough}
}
