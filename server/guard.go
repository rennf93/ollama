package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	guardgin "github.com/rennf93/gin-guard"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// guardFile is the JSON document read from OLLAMA_GUARD_CONFIG. Every field
// is optional; an empty document enables the guard with its defaults
// (per-IP rate limit of 100 requests per 60 seconds, loopback-only trusted
// proxies, no body inspection).
type guardFile struct {
	// AllowedIPs, when non-empty, rejects every client not listed (IPs or CIDRs).
	AllowedIPs []string `json:"allowed_ips"`
	// BlockedIPs rejects the listed clients (IPs or CIDRs).
	BlockedIPs []string `json:"blocked_ips"`
	// TrustedProxies lists peers whose X-Forwarded-For is honored. Defaults to loopback.
	TrustedProxies []string `json:"trusted_proxies"`
	// RateLimit is the number of requests allowed per client per RateLimitWindow seconds.
	RateLimit       int `json:"rate_limit"`
	RateLimitWindow int `json:"rate_limit_window"`
	// BanThreshold is the number of violations that bans a client for BanDuration seconds.
	BanThreshold int `json:"ban_threshold"`
	BanDuration  int `json:"ban_duration"`
	// ScanRequests enables attack-pattern detection on the path, query and headers.
	// Request bodies (prompts, chats, blobs) are never inspected.
	ScanRequests bool `json:"scan_requests"`
}

// guardMiddleware loads the guard configuration at path and returns the gin middleware.
func guardMiddleware(path string) (gin.HandlerFunc, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("guard: %w", err)
	}

	f := guardFile{
		TrustedProxies:  []string{"127.0.0.1", "::1"},
		RateLimit:       100,
		RateLimitWindow: 60,
		BanThreshold:    guardcore.DefaultAutoBanThreshold,
		BanDuration:     guardcore.DefaultAutoBanDuration,
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("guard: parse %s: %w", path, err)
	}

	scanBody := false
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.EnableRedis = false
		c.SecurityHeaders = nil
		c.Whitelist = f.AllowedIPs
		c.Blacklist = f.BlockedIPs
		c.TrustedProxies = f.TrustedProxies
		c.EnableRateLimiting = f.RateLimit > 0
		c.RateLimit = max(f.RateLimit, 1) // the engine rejects 0 even when limiting is off
		c.RateLimitWindow = f.RateLimitWindow
		c.EnableIPBanning = true
		c.EnableRateLimitAutoBan = true
		c.AutoBanThreshold = f.BanThreshold
		c.AutoBanDuration = f.BanDuration
		c.EnablePenetrationDetection = f.ScanRequests
		c.DetectionScanBody = &scanBody
	})
	if err != nil {
		return nil, fmt.Errorf("guard: %w", err)
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		return nil, fmt.Errorf("guard: %w", err)
	}
	if err := engine.Initialize(); err != nil {
		return nil, fmt.Errorf("guard: %w", err)
	}
	return guardgin.New(engine)
}
