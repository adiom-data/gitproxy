//go:build integration

package gitproxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestIntegrationGitCLIThroughProxy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not found")
	}

	tmp := t.TempDir()
	upstreamRoot := filepath.Join(tmp, "upstream")
	bareRepo := filepath.Join(upstreamRoot, "org", "repo.git")
	if err := os.MkdirAll(filepath.Dir(bareRepo), 0o755); err != nil {
		t.Fatal(err)
	}

	runGit(t, "", "init", "--bare", bareRepo)
	runGit(t, bareRepo, "config", "http.receivepack", "true")

	seedRepo := filepath.Join(tmp, "seed")
	runGit(t, "", "init", seedRepo)
	runGit(t, seedRepo, "config", "user.name", "Integration Test")
	runGit(t, seedRepo, "config", "user.email", "integration@example.com")
	writeFile(t, filepath.Join(seedRepo, "README.md"), "hello\n")
	runGit(t, seedRepo, "add", "README.md")
	runGit(t, seedRepo, "commit", "-m", "initial")
	writeFile(t, filepath.Join(seedRepo, "README.md"), "hello before proxy\n")
	runGit(t, seedRepo, "add", "README.md")
	runGit(t, seedRepo, "commit", "-m", "second")
	runGit(t, seedRepo, "branch", "-M", "allowed")
	runGit(t, seedRepo, "remote", "add", "origin", bareRepo)
	runGit(t, seedRepo, "push", "origin", "allowed")
	initialAllowedSHA := strings.TrimSpace(runGit(t, "", "--git-dir", bareRepo, "rev-parse", "refs/heads/allowed"))
	if initialAllowedSHA == "" {
		t.Fatal("expected upstream refs/heads/allowed to exist")
	}

	upstream := httptest.NewServer(gitHTTPBackend(t, upstreamRoot))
	defer upstream.Close()

	auth := AuthenticatorFunc[string](func(ctx context.Context, req BasicAuthRequest) (AuthResult[string], error) {
		if !req.HasCredentials || req.Credentials.Username != "client-user" || req.Credentials.Password != "client-pass" {
			return AuthResult[string]{}, ErrUnauthenticated
		}
		return NoCredentials[string]().WithSession("client-user"), nil
	})
	target, err := StaticTarget[string](upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	authz := AuthorizerFunc[string](func(ctx context.Context, req PolicyRequest[string]) error {
		if req.Session != "client-user" || req.Repo != "org/repo.git" {
			return ErrForbidden
		}
		if req.Operation == OperationFetch {
			return nil
		}
		if req.Operation != OperationPush {
			return ErrForbidden
		}
		if len(req.Refs) == 0 {
			return nil
		}
		for _, ref := range req.Refs {
			if ref.Kind != RefKindBranch || ref.ShortName != "allowed" || ref.Action != RefActionUpdate {
				return ErrForbidden
			}
		}
		return nil
	})
	proxy, err := New(auth, target, authz)
	if err != nil {
		t.Fatal(err)
	}

	proxyServer := httptest.NewServer(proxy)
	defer proxyServer.Close()

	proxyRepoURL := strings.Replace(proxyServer.URL, "http://", "http://client-user:client-pass@", 1) + "/org/repo.git"
	lsRemote := runGit(t, "", "ls-remote", "--heads", proxyRepoURL, "refs/heads/allowed")
	if strings.TrimSpace(lsRemote) != initialAllowedSHA+"\trefs/heads/allowed" {
		t.Fatalf("ls-remote output = %q", lsRemote)
	}

	cloneDir := filepath.Join(tmp, "clone")
	runGit(t, "", "clone", "--depth", "1", "--branch", "allowed", proxyRepoURL, cloneDir)
	if got := strings.TrimSpace(runGit(t, cloneDir, "rev-parse", "--is-shallow-repository")); got != "true" {
		t.Fatalf("expected shallow clone, got %q", got)
	}
	runGit(t, cloneDir, "config", "user.name", "Integration Test")
	runGit(t, cloneDir, "config", "user.email", "integration@example.com")
	writeFile(t, filepath.Join(cloneDir, "README.md"), "hello through proxy\n")
	runGit(t, cloneDir, "add", "README.md")
	runGit(t, cloneDir, "commit", "-m", "update through proxy")
	runGit(t, cloneDir, "push", "origin", "HEAD:refs/heads/allowed", "--force")
	updatedAllowedSHA := strings.TrimSpace(runGit(t, "", "--git-dir", bareRepo, "rev-parse", "refs/heads/allowed"))
	if updatedAllowedSHA == "" || updatedAllowedSHA == initialAllowedSHA {
		t.Fatalf("expected upstream refs/heads/allowed to advance, before=%q after=%q", initialAllowedSHA, updatedAllowedSHA)
	}
	if got := runGit(t, "", "--git-dir", bareRepo, "show", "allowed:README.md"); got != "hello through proxy\n" {
		t.Fatalf("upstream README.md = %q", got)
	}
	runGit(t, cloneDir, "push", "origin", "HEAD:refs/heads/allowed", "--force")

	runGit(t, cloneDir, "checkout", "-b", "dev")
	writeFile(t, filepath.Join(cloneDir, "dev.txt"), "blocked\n")
	runGit(t, cloneDir, "add", "dev.txt")
	runGit(t, cloneDir, "commit", "-m", "blocked branch")
	out, err := runGitErr(cloneDir, "push", "origin", "dev")
	if err == nil {
		t.Fatalf("expected dev push to fail, output = %s", out)
	}
}

func gitHTTPBackend(t *testing.T, projectRoot string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		var stdout, stderr bytes.Buffer
		cmd := exec.CommandContext(r.Context(), "git", "http-backend")
		cmd.Env = append(os.Environ(),
			"GIT_PROJECT_ROOT="+projectRoot,
			"GIT_HTTP_EXPORT_ALL=1",
			"PATH_INFO="+r.URL.Path,
			"QUERY_STRING="+r.URL.RawQuery,
			"REQUEST_METHOD="+r.Method,
			"CONTENT_TYPE="+r.Header.Get("Content-Type"),
			"HTTP_GIT_PROTOCOL="+r.Header.Get("Git-Protocol"),
		)
		if r.ContentLength >= 0 {
			cmd.Env = append(cmd.Env, fmt.Sprintf("CONTENT_LENGTH=%d", r.ContentLength))
		}
		cmd.Stdin = r.Body
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			http.Error(w, stderr.String(), http.StatusInternalServerError)
			return
		}

		status, header, body, err := parseCGIResponse(&stdout)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for key, values := range header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(status)
		_, _ = io.Copy(w, body)
	}
}

func parseCGIResponse(r io.Reader) (int, http.Header, io.Reader, error) {
	status := http.StatusOK
	header := http.Header{}
	reader := bufio.NewReader(r)
	tp := textproto.NewReader(reader)

	for {
		line, err := tp.ReadLine()
		if err != nil {
			return 0, nil, nil, err
		}
		if line == "" {
			return status, header, reader, nil
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return 0, nil, nil, fmt.Errorf("invalid CGI header line %q", line)
		}
		value = strings.TrimSpace(value)
		if strings.EqualFold(key, "Status") {
			code, err := strconv.Atoi(strings.Fields(value)[0])
			if err != nil {
				return 0, nil, nil, err
			}
			status = code
			continue
		}
		header.Add(key, value)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := runGitErr(dir, args...)
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func runGitErr(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
