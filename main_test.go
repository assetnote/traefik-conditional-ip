package traefik_conditional_ip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func hashKey(key string) string {
	h := sha256.New()
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}

func TestCreateConfig(t *testing.T) {
	cfg := CreateConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.HeaderName == "" {
		t.Errorf("expected non nil header name")
	}
	if cfg.KeyIPMap == nil {
		t.Error("expected non-nil KeyIPMap")
	}
}

func TestNew_EmptyHeaderName(t *testing.T) {
	cfg := &Config{HeaderName: "", KeyIPMap: map[string][]string{}}
	_, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err == nil {
		t.Fatal("expected error for empty header name")
	}
}

func TestNew_NilKeyIPMap(t *testing.T) {
	cfg := &Config{HeaderName: "X-Key", KeyIPMap: nil}
	_, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err == nil {
		t.Fatal("expected error for nil keyIpMap")
	}
}

func TestNew_InvalidIP(t *testing.T) {
	cfg := &Config{
		HeaderName: "X-Key",
		KeyIPMap:   map[string][]string{"key1": {"not-an-ip"}},
	}
	_, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestNew_Valid(t *testing.T) {
	cfg := &Config{
		HeaderName: "X-Key",
		KeyIPMap:   map[string][]string{"abc": {"10.0.0.1"}},
	}
	h, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestServeHTTP_NoAPIKey(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	m := &Middleware{
		next:       next,
		headerName: "X-Key",
		keyIpMap:   map[string][]string{},
		name:       "test",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestServeHTTP_KeyNotInMap(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	m := &Middleware{
		next:       next,
		headerName: "X-Key",
		keyIpMap:   map[string][]string{},
		name:       "test",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Key", "unknown-key")
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called for unknown key")
	}
}

func TestServeHTTP_KeyInMap_IPAllowed(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	apiKey := "my-secret-key"
	hashed := hashKey(apiKey)

	m := &Middleware{
		next:       next,
		headerName: "X-Key",
		keyIpMap:   map[string][]string{hashed: {"192.0.2.1"}},
		name:       "test",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Key", apiKey)
	req.RemoteAddr = "192.0.2.1:12345"
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called for allowed IP")
	}
}

func TestServeHTTP_KeyInMap_IPNotAllowed(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	apiKey := "my-secret-key"
	hashed := hashKey(apiKey)

	m := &Middleware{
		next:       next,
		headerName: "X-Key",
		keyIpMap:   map[string][]string{hashed: {"10.0.0.1"}},
		name:       "test",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Key", apiKey)
	req.RemoteAddr = "192.0.2.99:12345"
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if called {
		t.Error("next handler should not be called for disallowed IP")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestServeHTTP_KeyInMap_CIDRAllowed(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	apiKey := "cidr-key"
	hashed := hashKey(apiKey)

	m := &Middleware{
		next:       next,
		headerName: "X-Key",
		keyIpMap:   map[string][]string{hashed: {"10.0.0.0/24"}},
		name:       "test",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Key", apiKey)
	req.RemoteAddr = "10.0.0.42:9999"
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called for IP within CIDR")
	}
}

func TestParseIPs_CIDR(t *testing.T) {
	nets, err := parseIPs([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
	if !nets[0].Contains(net.ParseIP("10.0.0.1")) {
		t.Error("expected 10.0.0.1 to be in 10.0.0.0/24")
	}
}

func TestParseIPs_SingleIPv4(t *testing.T) {
	nets, err := parseIPs([]string{"192.168.1.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
	ones, bits := nets[0].Mask.Size()
	if ones != 32 || bits != 32 {
		t.Errorf("expected /32 mask, got /%d (bits=%d)", ones, bits)
	}
}

func TestParseIPs_SingleIPv6(t *testing.T) {
	nets, err := parseIPs([]string{"2001:db8::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 1 {
		t.Fatalf("expected 1 net, got %d", len(nets))
	}
	ones, bits := nets[0].Mask.Size()
	if ones != 128 || bits != 128 {
		t.Errorf("expected /128 mask, got /%d (bits=%d)", ones, bits)
	}
}

func TestParseIPs_Invalid(t *testing.T) {
	_, err := parseIPs([]string{"not-valid"})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestParseIPs_Empty(t *testing.T) {
	nets, err := parseIPs([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 0 {
		t.Errorf("expected 0 nets, got %d", len(nets))
	}
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:8080"
	ip := getClientIP(req)
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5, got %v", ip)
	}
}

func TestGetClientIP_RemoteAddrNoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5"
	ip := getClientIP(req)
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5, got %v", ip)
	}
}

func TestGetClientIP_InvalidRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-an-ip:1234"
	ip := getClientIP(req)
	if ip != nil {
		t.Errorf("expected nil, got %v", ip)
	}
}

func TestGetClientIP_CFConnectingIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("CF-Connecting-IP", "198.51.100.1")
	ip := getClientIP(req)
	if ip == nil || ip.String() != "198.51.100.1" {
		t.Errorf("expected 198.51.100.1, got %v", ip)
	}
}

func TestGetClientIP_CFConnectingIP_Invalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("CF-Connecting-IP", "bad-ip")
	// Should fall through to X-Forwarded-For or RemoteAddr
	ip := getClientIP(req)
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %v", ip)
	}
}

func TestGetClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.2, 10.0.0.2")
	ip := getClientIP(req)
	if ip == nil || ip.String() != "198.51.100.2" {
		t.Errorf("expected 198.51.100.2, got %v", ip)
	}
}

func TestGetClientIP_XForwardedFor_AllInvalid(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "bad, also-bad")
	ip := getClientIP(req)
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("expected fallback to 10.0.0.1, got %v", ip)
	}
}

func TestGetClientIP_IPv4MappedIPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::ffff:192.0.2.1]:1234"
	ip := getClientIP(req)
	if ip == nil || ip.String() != "192.0.2.1" {
		t.Errorf("expected normalized 192.0.2.1, got %v", ip)
	}
}

func TestIPAllowed_Match(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	if !ipAllowed(net.ParseIP("10.1.2.3"), []*net.IPNet{cidr}) {
		t.Error("expected 10.1.2.3 to be allowed in 10.0.0.0/8")
	}
}

func TestIPAllowed_NoMatch(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	if ipAllowed(net.ParseIP("192.168.1.1"), []*net.IPNet{cidr}) {
		t.Error("expected 192.168.1.1 to not be allowed in 10.0.0.0/8")
	}
}

func TestIPAllowed_EmptyList(t *testing.T) {
	if ipAllowed(net.ParseIP("10.0.0.1"), nil) {
		t.Error("expected no match on empty list")
	}
}

func TestFlattenMap(t *testing.T) {
	m := map[string][]string{
		"a": {"1", "2"},
		"b": {"3"},
	}
	result := flattenMap(m)
	if len(result) != 3 {
		t.Errorf("expected 3 elements, got %d", len(result))
	}
}

func TestFlattenMap_Empty(t *testing.T) {
	result := flattenMap(map[string][]string{})
	if len(result) != 0 {
		t.Errorf("expected 0 elements, got %d", len(result))
	}
}
