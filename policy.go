package gitproxy

import (
	"context"
	"net/http"
	"strings"
)

type Operation string

const (
	OperationUnknown Operation = "unknown"
	OperationFetch   Operation = "fetch"
	OperationPush    Operation = "push"
)

type RefKind string

const (
	RefKindBranch RefKind = "branch"
	RefKindTag    RefKind = "tag"
	RefKindOther  RefKind = "other"
)

type RefAction string

const (
	RefActionUnknown RefAction = "unknown"
	RefActionCreate  RefAction = "create"
	RefActionUpdate  RefAction = "update"
	RefActionDelete  RefAction = "delete"
)

type Ref struct {
	Name      string
	Kind      RefKind
	ShortName string
	Action    RefAction
	OldSHA    string
	NewSHA    string
}

// PolicyRequest describes what the proxy could infer from an HTTP Git request.
type PolicyRequest[S any] struct {
	Session   S
	Repo      string
	Target    Target
	Operation Operation
	Refs      []Ref
	Request   *http.Request
}

// Authorizer decides whether an authenticated request may reach the upstream
// Git server.
type Authorizer[S any] interface {
	AuthorizeGit(context.Context, PolicyRequest[S]) error
}

type AuthorizerFunc[S any] func(context.Context, PolicyRequest[S]) error

func (f AuthorizerFunc[S]) AuthorizeGit(ctx context.Context, req PolicyRequest[S]) error {
	return f(ctx, req)
}

// AllowAll allows every request.
func AllowAll[S any]() Authorizer[S] {
	return AuthorizerFunc[S](func(context.Context, PolicyRequest[S]) error {
		return nil
	})
}

func operationFromRequest(r *http.Request) Operation {
	switch {
	case strings.HasSuffix(r.URL.Path, "/git-upload-pack"):
		return OperationFetch
	case strings.HasSuffix(r.URL.Path, "/git-receive-pack"):
		return OperationPush
	}

	switch r.URL.Query().Get("service") {
	case "git-upload-pack":
		return OperationFetch
	case "git-receive-pack":
		return OperationPush
	default:
		return OperationUnknown
	}
}

func repoFromPath(path string) string {
	repo, _ := splitRepoPath(path)
	return repo
}

func rewriteRepoPath(path, upstreamRepo string) string {
	_, suffix := splitRepoPath(path)
	upstreamRepo = strings.Trim(upstreamRepo, "/")
	if suffix == "" {
		return "/" + upstreamRepo
	}
	return "/" + upstreamRepo + suffix
}

func splitRepoPath(path string) (string, string) {
	trimmed := strings.TrimPrefix(path, "/")
	for _, suffix := range []string{"/git-upload-pack", "/git-receive-pack", "/info/refs"} {
		if strings.HasSuffix(trimmed, suffix) {
			return strings.TrimSuffix(trimmed, suffix), suffix
		}
	}
	return strings.TrimSuffix(trimmed, "/"), ""
}

func parseRef(name string) Ref {
	switch {
	case strings.HasPrefix(name, "refs/heads/"):
		return Ref{Name: name, Kind: RefKindBranch, ShortName: strings.TrimPrefix(name, "refs/heads/")}
	case strings.HasPrefix(name, "refs/tags/"):
		return Ref{Name: name, Kind: RefKindTag, ShortName: strings.TrimPrefix(name, "refs/tags/")}
	default:
		return Ref{Name: name, Kind: RefKindOther, ShortName: name}
	}
}
