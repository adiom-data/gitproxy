package gitproxy

import (
	"context"
	"fmt"
	"net/url"
)

type Target struct {
	BaseURL *url.URL
	Repo    string
}

type TargetResolver[S any] interface {
	ResolveGitTarget(context.Context, TargetRequest[S]) (Target, error)
}

type TargetRequest[S any] struct {
	Repo      string
	Session   S
	Operation Operation
}

type TargetResolverFunc[S any] func(context.Context, TargetRequest[S]) (Target, error)

func (f TargetResolverFunc[S]) ResolveGitTarget(ctx context.Context, req TargetRequest[S]) (Target, error) {
	return f(ctx, req)
}

func StaticTarget[S any](upstream string) (TargetResolver[S], error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("gitproxy: upstream must include scheme and host")
	}

	return TargetResolverFunc[S](func(context.Context, TargetRequest[S]) (Target, error) {
		return Target{BaseURL: cloneURL(u), Repo: ""}, nil
	}), nil
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	clone := *u
	return &clone
}
