package gitproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProxyReplacesBasicAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Fatal("missing upstream basic auth")
		}
		if user != "upstream-user" || pass != "upstream-token" {
			t.Fatalf("upstream basic auth = %q/%q", user, pass)
		}
		if r.URL.Path != "/org/repo.git/info/refs" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, AuthenticatorFunc[string](func(_ context.Context, req BasicAuthRequest) (AuthResult[string], error) {
		if req.Credentials.Username != "client-user" || req.Credentials.Password != "client-pass" {
			t.Fatalf("client credentials = %q/%q", req.Credentials.Username, req.Credentials.Password)
		}
		if !req.HasCredentials {
			t.Fatal("expected client credentials")
		}
		return ReplaceCredentials[string]("upstream-user", "upstream-token").WithSession("alice"), nil
	}), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Session != "alice" {
			t.Fatalf("session = %q", req.Session)
		}
		if req.Operation != OperationFetch {
			t.Fatalf("operation = %q", req.Operation)
		}
		if req.Repo != "org/repo.git" {
			t.Fatalf("repo = %q", req.Repo)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("client-user", "client-pass")
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyMapsRepositoryPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/real/repo.git/info/refs" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := TargetResolverFunc[string](func(ctx context.Context, req TargetRequest[string]) (Target, error) {
		if req.Repo != "proxy/repo.git" {
			t.Fatalf("repo = %q", req.Repo)
		}
		return Target{BaseURL: upstreamURL, Repo: "real/repo.git"}, nil
	})

	proxy, err := New(StaticCredentials[string]("u", "p"), target, AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Repo != "proxy/repo.git" {
			t.Fatalf("repo = %q", req.Repo)
		}
		if req.Target.Repo != "real/repo.git" {
			t.Fatalf("upstream repo = %q", req.Target.Repo)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/proxy/repo.git/info/refs?service=git-upload-pack", nil)
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyCanReplaceCredentialsWithoutClientAuth(t *testing.T) {
	upstreamAuth := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, AuthenticatorFunc[string](func(_ context.Context, req BasicAuthRequest) (AuthResult[string], error) {
		if req.HasCredentials {
			t.Fatal("did not expect client credentials")
		}
		return ReplaceCredentials[string]("service-user", "service-token"), nil
	}), AllowAll[string]())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-upload-pack", nil)
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if upstreamAuth == "" {
		t.Fatal("missing injected upstream auth")
	}
}

func TestProxyReturnsBasicChallengeWhenAuthFails(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, AuthenticatorFunc[string](func(_ context.Context, req BasicAuthRequest) (AuthResult[string], error) {
		return AuthResult[string]{}, ErrUnauthenticated
	}), AllowAll[string]())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-upload-pack", nil)
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("WWW-Authenticate"); got != `Basic realm="gitproxy"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestProxyAuthenticatesBeforeInspectingPushBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, AuthenticatorFunc[string](func(_ context.Context, req BasicAuthRequest) (AuthResult[string], error) {
		return AuthResult[string]{}, ErrUnauthenticated
	}), AllowAll[string]())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader("not pkt-line data"))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("WWW-Authenticate"); got != `Basic realm="gitproxy"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestProxyDoesNotReturnBasicChallengeForHeaderAuthFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, HeaderAuth[string](HTTPAuthenticatorFunc[string](func(_ context.Context, req HTTPAuthRequest) (AuthResult[string], error) {
		return AuthResult[string]{}, ErrUnauthenticated
	})), AllowAll[string]())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if got := res.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestProxyCanUseNoCredentialsAfterAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("authorization header = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, AuthenticatorFunc[string](func(_ context.Context, req BasicAuthRequest) (AuthResult[string], error) {
		if !req.HasCredentials {
			t.Fatal("expected client credentials")
		}
		return NoCredentials[string](), nil
	}), AllowAll[string]())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("client-user", "client-pass")
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyCanPassThroughCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Fatal("missing upstream basic auth")
		}
		if user != "client-user" || pass != "client-pass" {
			t.Fatalf("upstream basic auth = %q/%q", user, pass)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, AuthenticatorFunc[string](func(_ context.Context, req BasicAuthRequest) (AuthResult[string], error) {
		return PassThroughCredentials[string](), nil
	}), AllowAll[string]())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("client-user", "client-pass")
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyCanUseHeaderAuthForCustomSchemes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer client-token" {
			t.Fatalf("authorization header = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, HeaderAuth[string](HTTPAuthenticatorFunc[string](func(_ context.Context, req HTTPAuthRequest) (AuthResult[string], error) {
		if got := req.Request.Header.Get("Authorization"); got != "Bearer client-token" {
			t.Fatalf("authorization header = %q", got)
		}
		if req.Repo != "org/repo.git" {
			t.Fatalf("repo = %q", req.Repo)
		}
		return AuthResult[string]{
			UpstreamAuthMode: UpstreamAuthPassThrough,
		}.WithSession("bearer-user"), nil
	})), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Session != "bearer-user" {
			t.Fatalf("session = %q", req.Session)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer client-token")
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyDefaultsToPassThroughAuthWhenAuthenticatorIsNil(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Fatal("missing upstream basic auth")
		}
		if user != "client-user" || pass != "client-pass" {
			t.Fatalf("upstream basic auth = %q/%q", user, pass)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, nil, AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Session != "" {
			t.Fatalf("session = %q", req.Session)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("client-user", "client-pass")
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyRejectsUnauthorizedPushBranch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Repo != "org/repo.git" {
			return ErrForbidden
		}
		return allowOnlyPushBranch(req, "main")
	}))
	if err != nil {
		t.Fatal(err)
	}

	body := receivePackLine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/dev\x00 report-status\n") + "0000"
	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader(body))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyAllowsPushDiscoveryWithoutInspectingBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/org/repo.git/info/refs" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("service") != "git-receive-pack" {
			t.Fatalf("service = %q", r.URL.Query().Get("service"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Operation != OperationPush {
			t.Fatalf("operation = %q", req.Operation)
		}
		if len(req.Refs) != 0 {
			t.Fatalf("refs = %#v", req.Refs)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/org/repo.git/info/refs?service=git-receive-pack", nil)
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyRejectsMalformedPushBeforePolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		t.Fatal("policy should not be called")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	body := receivePackLine("not a receive-pack command\n") + "0000"
	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader(body))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyLogsMalformedPushInspectionError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called")
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AllowAll[string]())
	if err != nil {
		t.Fatal(err)
	}
	var logged error
	proxy.ErrorLog = func(r *http.Request, err error) {
		logged = err
	}

	body := receivePackLine("not a receive-pack command\n") + "0000"
	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader(body))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	if logged == nil || !strings.Contains(logged.Error(), "inspect git request") {
		t.Fatalf("logged error = %v", logged)
	}
}

func TestProxyAllowsFlushOnlyPushCommandSection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "0000" {
			t.Fatalf("body = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Operation != OperationPush {
			t.Fatalf("operation = %q", req.Operation)
		}
		if len(req.Refs) != 0 {
			t.Fatalf("refs = %#v", req.Refs)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader("0000"))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyAllowsShallowPushCommandSection(t *testing.T) {
	body := receivePackLine("shallow cccccccccccccccccccccccccccccccccccccccc\n") +
		receivePackLine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/main\x00 report-status shallow\n") +
		"0000PACK trailing packfile bytes"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != body {
			t.Fatalf("body = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if len(req.Refs) != 1 {
			t.Fatalf("refs = %#v", req.Refs)
		}
		ref := req.Refs[0]
		if ref.Name != "refs/heads/main" || ref.Action != RefActionUpdate {
			t.Fatalf("ref = %#v", ref)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader(body))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyPreservesBodyAfterInspectingPush(t *testing.T) {
	body := receivePackLine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/main\x00 report-status\n") + "0000PACK trailing packfile bytes"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != body {
			t.Fatalf("body = %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Repo != "org/repo.git" {
			return ErrForbidden
		}
		return allowOnlyPushBranch(req, "main")
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader(body))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyPassesPushRefsToPolicy(t *testing.T) {
	body := receivePackLine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/main\x00 report-status\n") + "0000"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if len(req.Refs) != 1 {
			t.Fatalf("refs = %#v", req.Refs)
		}
		ref := req.Refs[0]
		if ref.Name != "refs/heads/main" || ref.Kind != RefKindBranch || ref.ShortName != "main" {
			t.Fatalf("ref = %#v", ref)
		}
		if ref.Action != RefActionUpdate || ref.OldSHA != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || ref.NewSHA != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
			t.Fatalf("ref update = %#v", ref)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader(body))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestProxyPassesPushRefActionsToPolicy(t *testing.T) {
	body := receivePackLine("0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/new\x00 report-status\n") +
		receivePackLine("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccccccccccc refs/heads/main\n") +
		receivePackLine("dddddddddddddddddddddddddddddddddddddddd 0000000000000000000000000000000000000000 refs/heads/old\n") +
		"0000"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy, err := newStaticProxy(t, upstream.URL, StaticCredentials[string]("u", "p"), AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if len(req.Refs) != 3 {
			t.Fatalf("refs = %#v", req.Refs)
		}

		expected := map[string]RefAction{
			"new":  RefActionCreate,
			"main": RefActionUpdate,
			"old":  RefActionDelete,
		}
		for _, ref := range req.Refs {
			if ref.Action != expected[ref.ShortName] {
				t.Fatalf("ref = %#v", ref)
			}
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/org/repo.git/git-receive-pack", strings.NewReader(body))
	res := httptest.NewRecorder()

	proxy.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func receivePackLine(payload string) string {
	return fmt.Sprintf("%04x%s", len(payload)+4, payload)
}

func allowOnlyPushBranch(req PolicyRequest[string], branch string) error {
	if req.Operation != OperationPush {
		return nil
	}
	if len(req.Refs) == 0 {
		return ErrForbidden
	}
	for _, ref := range req.Refs {
		if ref.Kind != RefKindBranch || ref.ShortName != branch {
			return ErrForbidden
		}
	}
	return nil
}

func newStaticProxy(t *testing.T, upstream string, auth Authenticator[string], authorizer Authorizer[string]) (*Proxy[string], error) {
	t.Helper()
	target, err := StaticTarget[string](upstream)
	if err != nil {
		return nil, err
	}
	return New(auth, target, authorizer)
}
