# gitproxy

`gitproxy` is a small Go library for building a credential-masking HTTP smart-Git proxy.

The common use case is giving an untrusted Git client a proxy URL such as `https://client-user:client-pass@proxy.example.com/proxy/repo.git` while keeping the real upstream Git credentials inside your service. Git sends `client-user:client-pass` as HTTP Basic auth, `gitproxy` lets your application authenticate that pair, and the proxy forwards the request to the upstream Git server with credentials chosen by your code.

The proxy has three application-defined stages:

- Authenticate the client credentials and return a typed session plus the upstream auth behavior.
- Resolve the client-facing repo path to an upstream base URL and repo path.
- Authorize the session against request facts such as repo, operation, and pushed refs.

```go
package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"slices"

	"github.com/adiom-data/gitproxy"
)

type Session struct {
	ID            string
	UpstreamUser  string
	UpstreamToken string
	RepoMap       map[string]string
	PushBranches  map[string][]string
}

func main() {
	auth := gitproxy.AuthenticatorFunc[Session](func(ctx context.Context, req gitproxy.BasicAuthRequest) (gitproxy.AuthResult[Session], error) {
		if !req.HasCredentials {
			return gitproxy.AuthResult[Session]{}, gitproxy.ErrUnauthenticated
		}

		session := Session{
			ID:            "grant-123",
			UpstreamUser:  "upstream-user",
			UpstreamToken: "upstream-token",
			RepoMap:       map[string]string{"proxy/repo.git": "real-org/repo.git"},
			PushBranches:  map[string][]string{"proxy/repo.git": []string{"main"}},
		}

		return gitproxy.ReplaceCredentials[Session](session.UpstreamUser, session.UpstreamToken).WithSession(session), nil
	})

	githubURL, err := url.Parse("https://github.com")
	if err != nil {
		log.Fatal(err)
	}

	target := gitproxy.TargetResolverFunc[Session](func(ctx context.Context, req gitproxy.TargetRequest[Session]) (gitproxy.Target, error) {
		upstreamRepo := req.Session.RepoMap[req.Repo]
		if upstreamRepo == "" {
			return gitproxy.Target{}, gitproxy.ErrForbidden
		}
		return gitproxy.Target{BaseURL: githubURL, Repo: upstreamRepo}, nil
	})

	authz := gitproxy.AuthorizerFunc[Session](func(ctx context.Context, req gitproxy.PolicyRequest[Session]) error {
		if req.Operation == gitproxy.OperationFetch {
			return nil
		}
		if req.Operation != gitproxy.OperationPush {
			return gitproxy.ErrForbidden
		}
		if len(req.Refs) == 0 {
			return nil
		}

		allowed := req.Session.PushBranches[req.Repo]
		for _, ref := range req.Refs {
			if ref.Kind != gitproxy.RefKindBranch || ref.Action != gitproxy.RefActionUpdate || !slices.Contains(allowed, ref.ShortName) {
				return gitproxy.ErrForbidden
			}
		}
		return nil
	})

	proxy, err := gitproxy.New(auth, target, authz)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.ListenAndServe(":8080", proxy))
}
```

With the example above, a client request for `/proxy/repo.git` is forwarded to `https://github.com/real-org/repo.git`. Fetches and push discovery are allowed. Push updates are allowed only when every pushed ref is an update to `refs/heads/main`; branch creation, branch deletion, tags, and other refs are rejected.

## Authentication

`BasicAuthRequest` contains only the HTTP Basic credentials presented by the Git client. `HasCredentials` tells you whether credentials were present at all, so an empty username/password can still be distinguished from no Basic auth header.

An `Authenticator` returns an `AuthResult` with an application-defined session and one of these upstream auth behaviors:

```go
gitproxy.ReplaceCredentials[Session]("upstream-user", "upstream-token")
gitproxy.NoCredentials[Session]()
gitproxy.PassThroughCredentials[Session]()
```

`ReplaceCredentials` is the usual credential-masking path: the client presents proxy credentials, while upstream sees only credentials chosen by the proxy. `NoCredentials` strips any inbound `Authorization` header before forwarding. `PassThroughCredentials` forwards the inbound `Authorization` header unchanged, which is mostly useful for trusted, testing, or non-masking deployments.

Attach the session with `WithSession`:

```go
return gitproxy.ReplaceCredentials[Session]("upstream-user", "upstream-token").WithSession(session), nil
```

If `New` receives a nil authenticator, the proxy uses `PassThroughAuth`: it performs no authentication, associates the zero-value session, and forwards the inbound Authorization header unchanged.

For non-Basic schemes, wrap a lower-level header-aware authenticator with `HeaderAuth`:

```go
auth := gitproxy.HeaderAuth[Session](gitproxy.HTTPAuthenticatorFunc[Session](func(ctx context.Context, req gitproxy.HTTPAuthRequest) (gitproxy.AuthResult[Session], error) {
	header := req.Request.Header.Get("Authorization")
	_ = header

	return gitproxy.PassThroughCredentials[Session]().WithSession(session), nil
}))
```

Header authenticators should not read `HTTPAuthRequest.Request.Body`; the proxy may still need to inspect or forward it.

## Target Resolution

The `TargetResolver` receives the authenticated session, the client-facing repo path, and the inferred operation. It returns the upstream base URL and repo path to use for forwarding.

```go
target := gitproxy.TargetResolverFunc[Session](func(ctx context.Context, req gitproxy.TargetRequest[Session]) (gitproxy.Target, error) {
	return gitproxy.Target{BaseURL: githubURL, Repo: req.Session.RepoMap[req.Repo]}, nil
})
```

`PolicyRequest.Repo` remains the client-facing path. `PolicyRequest.Target` is the resolved upstream target.

## Authorization

The `Authorizer` receives the typed session and request facts, not upstream credentials. Use `PolicyRequest.Session`, `Repo`, `Target`, `Operation`, and `Refs` to make authorization decisions.

Push refs are parsed from `git-receive-pack` command pkt-lines and exposed as `Ref` values. `RefKindBranch` covers `refs/heads/*`, `RefKindTag` covers `refs/tags/*`, and everything else is `RefKindOther`. For pushes, each ref also includes `Action`, `OldSHA`, and `NewSHA`, so policy can distinguish branch creation, updates, and deletion. Real pushes include a discovery request before the receive-pack POST, so `OperationPush` with no refs should usually be allowed. A common policy is to allow fetches and push discovery, then reject a whole push POST if any pushed ref is not an allowed branch update for the authenticated session.

Authorizers should not read `PolicyRequest.Request.Body`; the proxy may still need to forward it upstream.

## Scope Notes

Repository and operation checks are available for every HTTP Git request. Push ref checks are available for smart HTTP push requests. Fetch branch scoping is intentionally left to custom authorizers and future protocol-specific filtering because normal Git fetch requests often ask for object IDs rather than branch names.

## Testing

Run the unit tests with:

```sh
go test ./...
```

There is also an integration test that runs the real `git` CLI through the proxy against an upstream served by `git http-backend`:

```sh
go test -tags integration ./...
```

## License

Apache-2.0. See [LICENSE](LICENSE).
