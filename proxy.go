package gitproxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
)

// Proxy is an HTTP smart-Git reverse proxy. It reads client credentials from
// Basic auth, lets the application authenticate the client and choose upstream
// credentials, applies policy, then forwards the request with the upstream
// Authorization behavior chosen by auth.
type Proxy[S any] struct {
	Auth               Authenticator[S]
	TargetResolver     TargetResolver[S]
	Authorizer         Authorizer[S]
	MaxPushHeaderBytes int64
	Transport          http.RoundTripper
	ErrorLog           func(*http.Request, error)
}

func New[S any](auth Authenticator[S], targetResolver TargetResolver[S], authorizer Authorizer[S]) (*Proxy[S], error) {
	if auth == nil {
		auth = PassThroughAuth[S]()
	}
	if targetResolver == nil {
		return nil, fmt.Errorf("gitproxy: target resolver is required")
	}
	if authorizer == nil {
		authorizer = AllowAll[S]()
	}

	return &Proxy[S]{Auth: auth, TargetResolver: targetResolver, Authorizer: authorizer}, nil
}

func (p *Proxy[S]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.TargetResolver == nil || p.Auth == nil {
		http.Error(w, "git proxy is not configured", http.StatusInternalServerError)
		return
	}

	repo := repoFromPath(r.URL.Path)
	op := operationFromRequest(r)
	user, pass, hasBasicAuth := r.BasicAuth()
	var authResult AuthResult[S]
	var err error
	_, usesHTTPAuth := p.Auth.(HTTPAuthenticator[S])
	if httpAuth, ok := p.Auth.(HTTPAuthenticator[S]); ok {
		authResult, err = httpAuth.AuthenticateGitHTTP(r.Context(), HTTPAuthRequest{
			Request:   r,
			Repo:      repo,
			Operation: op,
		})
	} else {
		authResult, err = p.Auth.AuthenticateGit(r.Context(), BasicAuthRequest{
			HasCredentials: hasBasicAuth,
			Credentials:    Credentials{Username: user, Password: pass},
		})
	}
	if err != nil {
		if !usesHTTPAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="gitproxy"`)
		}
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	target, err := p.TargetResolver.ResolveGitTarget(r.Context(), TargetRequest[S]{
		Repo:      repo,
		Session:   authResult.Session,
		Operation: op,
	})
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if target.Repo == "" {
		target.Repo = repo
	}
	if target.BaseURL == nil || target.BaseURL.Scheme == "" || target.BaseURL.Host == "" || target.Repo == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	refs, header, err := p.inspectRefs(r, op)
	if err != nil {
		if p.ErrorLog != nil {
			p.ErrorLog(r, fmt.Errorf("inspect git request: %w", err))
		}
		http.Error(w, "could not inspect git request", http.StatusBadRequest)
		return
	}
	if header != nil {
		r.Body = readCloser{
			Reader: io.MultiReader(bytes.NewReader(header), r.Body),
			Closer: r.Body,
		}
	}

	policyReq := PolicyRequest[S]{
		Session:   authResult.Session,
		Repo:      repo,
		Target:    target,
		Operation: op,
		Refs:      refs,
		Request:   r,
	}
	if err := p.Authorizer.AuthorizeGit(r.Context(), policyReq); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target.BaseURL)
	originalDirector := proxy.Director
	proxy.Director = func(out *http.Request) {
		originalDirector(out)
		out.Host = target.BaseURL.Host
		out.URL.Path = joinURLPath(target.BaseURL.Path, rewriteRepoPath(r.URL.Path, target.Repo))
		out.URL.RawPath = ""
		out.URL.RawQuery = r.URL.RawQuery
		switch authResult.UpstreamAuthMode {
		case UpstreamAuthPassThrough:
		case UpstreamAuthNone:
			out.Header.Del("Authorization")
		case UpstreamAuthReplace:
			creds := authResult.UpstreamCredentials
			out.SetBasicAuth(creds.Username, creds.Password)
		default:
			creds := authResult.UpstreamCredentials
			if creds.Username == "" && creds.Password == "" {
				out.Header.Del("Authorization")
			} else {
				out.SetBasicAuth(creds.Username, creds.Password)
			}
		}
	}
	if p.Transport != nil {
		proxy.Transport = p.Transport
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if p.ErrorLog != nil {
			p.ErrorLog(r, err)
		}
		http.Error(w, "upstream git server error", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

func (p *Proxy[S]) inspectRefs(r *http.Request, op Operation) ([]Ref, []byte, error) {
	if op != OperationPush || r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/git-receive-pack") || r.Body == nil {
		return nil, nil, nil
	}

	header, err := readReceivePackHeader(r.Body, p.MaxPushHeaderBytes)
	if err != nil {
		return nil, nil, err
	}
	refs, err := parseReceivePackRefs(header)
	if err != nil {
		return nil, nil, err
	}
	return refs, header, nil
}

func joinURLPath(basePath, reqPath string) string {
	switch {
	case basePath == "" || basePath == "/":
		return reqPath
	case reqPath == "":
		return basePath
	default:
		return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(reqPath, "/")
	}
}

type readCloser struct {
	io.Reader
	io.Closer
}
