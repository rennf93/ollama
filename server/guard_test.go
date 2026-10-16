package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func guardRouter(t *testing.T, cfg string) *gin.Engine {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OLLAMA_MODELS", t.TempDir())
	if cfg != "" {
		path := filepath.Join(t.TempDir(), "guard.json")
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("OLLAMA_GUARD_CONFIG", path)
	} else {
		t.Setenv("OLLAMA_GUARD_CONFIG", "")
	}
	handler, err := (&Server{}).GenerateRoutes()
	if err != nil {
		t.Fatal(err)
	}
	return handler.(*gin.Engine)
}

func guardGet(r http.Handler, peer, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	req.RemoteAddr = peer + ":1234"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestGuardDisabledAddsNoMiddleware(t *testing.T) {
	off := guardRouter(t, "")
	on := guardRouter(t, `{}`)
	if len(on.Handlers) != len(off.Handlers)+1 {
		t.Fatalf("handlers: disabled %d, enabled %d, want exactly one more", len(off.Handlers), len(on.Handlers))
	}
	for i := 0; i < 300; i++ {
		if w := guardGet(off, "192.0.2.10", "/api/version", nil); w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d with guard disabled", i, w.Code)
		}
	}
}

func TestGuardRateLimitAndCORSOnRejection(t *testing.T) {
	r := guardRouter(t, `{"rate_limit": 3, "rate_limit_window": 60}`)
	hdr := map[string]string{"Origin": "http://localhost"}
	for i := 0; i < 3; i++ {
		if w := guardGet(r, "192.0.2.10", "/api/version", hdr); w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200", i, w.Code)
		}
	}
	w := guardGet(r, "192.0.2.10", "/api/version", hdr)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost" {
		t.Fatalf("Access-Control-Allow-Origin on 429 = %q", got)
	}
	// Another client is unaffected.
	if w := guardGet(r, "192.0.2.11", "/api/version", nil); w.Code != http.StatusOK {
		t.Fatalf("other client: status %d, want 200", w.Code)
	}
}

func TestGuardAllowedIPs(t *testing.T) {
	r := guardRouter(t, `{"allowed_ips": ["192.0.2.0/28"]}`)
	if w := guardGet(r, "192.0.2.5", "/api/version", nil); w.Code != http.StatusOK {
		t.Fatalf("allowed client: status %d, want 200", w.Code)
	}
	if w := guardGet(r, "198.51.100.7", "/api/version", nil); w.Code != http.StatusForbidden {
		t.Fatalf("other client: status %d, want 403", w.Code)
	}
}

func TestGuardIgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	r := guardRouter(t, `{"allowed_ips": ["192.0.2.1"], "rate_limit": 2, "rate_limit_window": 60}`)
	// An untrusted peer cannot borrow an allowed identity.
	spoof := map[string]string{"X-Forwarded-For": "192.0.2.1"}
	if w := guardGet(r, "198.51.100.7", "/api/version", spoof); w.Code != http.StatusForbidden {
		t.Fatalf("spoofed XFF from untrusted peer: status %d, want 403", w.Code)
	}
	// A loopback proxy is trusted, so the forwarded client identity applies.
	if w := guardGet(r, "127.0.0.1", "/api/version", spoof); w.Code != http.StatusOK {
		t.Fatalf("XFF from loopback proxy: status %d, want 200", w.Code)
	}
}

func TestGuardRotatingForwardedForDoesNotEvadeRateLimit(t *testing.T) {
	r := guardRouter(t, `{"rate_limit": 2, "rate_limit_window": 60}`)
	var last int
	for i := 0; i < 5; i++ {
		hdr := map[string]string{"X-Forwarded-For": fmt.Sprintf("203.0.113.%d", i+1)}
		last = guardGet(r, "198.51.100.7", "/api/version", hdr).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429 despite rotating XFF", last)
	}
}

func TestGuardScansPathAndQueryOnlyWhenEnabled(t *testing.T) {
	attack := "/api/version?q=%3Cscript%3Ealert(1)%3C/script%3E"
	if w := guardGet(guardRouter(t, `{}`), "192.0.2.10", attack, nil); w.Code != http.StatusOK {
		t.Fatalf("scan_requests off: status %d, want 200", w.Code)
	}
	if w := guardGet(guardRouter(t, `{"scan_requests": true}`), "192.0.2.10", attack, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("scan_requests on: status %d, want 400", w.Code)
	}
}

func TestGuardBlobUploadNotInspectedOrBuffered(t *testing.T) {
	r := guardRouter(t, `{"scan_requests": true}`)
	// 8 MiB of data that looks like an attack payload: bodies are never scanned.
	data := bytes.Repeat([]byte("<script>alert(1)</script>' OR 1=1 --"), 8<<20/36)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/blobs/"+digest, bytes.NewReader(data))
	req.RemoteAddr = "192.0.2.10:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("blob upload: status %d, body %q", w.Code, w.Body.String())
	}
	if w := guardGet(r, "192.0.2.10", "/api/version", nil); w.Code != http.StatusOK {
		t.Fatalf("after upload: status %d", w.Code)
	}
}

func TestGuardDoesNotBufferStreamingResponses(t *testing.T) {
	t.Setenv("OLLAMA_GUARD_CONFIG", filepath.Join(t.TempDir(), "guard.json"))
	if err := os.WriteFile(os.Getenv("OLLAMA_GUARD_CONFIG"), []byte(`{"scan_requests": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	guard, err := guardMiddleware(os.Getenv("OLLAMA_GUARD_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	r := gin.New()
	r.Use(guard)
	r.POST("/stream", func(c *gin.Context) {
		io.Copy(io.Discard, c.Request.Body)
		c.Writer.WriteString("first\n")
		c.Writer.Flush()
		<-release
		c.Writer.WriteString("second\n")
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/stream", "application/json", strings.NewReader(`{"prompt":"hello"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 6)
	got := make(chan string, 1)
	go func() { io.ReadFull(resp.Body, buf); got <- string(buf) }()
	select {
	case s := <-got:
		if s != "first\n" {
			t.Fatalf("first chunk = %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first chunk was not delivered before the handler finished")
	}
	close(release)
}

func TestGuardRejectsBadConfig(t *testing.T) {
	for name, cfg := range map[string]string{
		"unknown field": `{"alowed_ips": ["192.0.2.1"]}`,
		"bad ip":        `{"allowed_ips": ["not-an-ip"]}`,
		"not json":      `allow all`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "guard.json")
			if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := guardMiddleware(path); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := guardMiddleware(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestGuardRateLimitZeroDisablesRateLimiting(t *testing.T) {
	r := guardRouter(t, `{"rate_limit": 0}`)
	for i := 0; i < 300; i++ {
		if w := guardGet(r, "192.0.2.10", "/api/version", nil); w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, w.Code)
		}
	}
}
