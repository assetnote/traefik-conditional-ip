package traefik_conditional_ip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Config struct {
	HeaderName string              `yaml:"headerName,omitempty"`
	KeyIPMap   map[string][]string `yaml:"keyIpMap,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		HeaderName: "X-Api-Key",
		KeyIPMap:   make(map[string][]string),
	}
}

type Middleware struct {
	next       http.Handler
	headerName string
	keyIpMap   map[string][]string
	name       string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.HeaderName == "" {
		return nil, errors.New("headerName cannot be empty")
	}
	if config.KeyIPMap == nil {
		return nil, errors.New("keyIpMap cannot be nil")
	}
	// Guarantee that IPs given in map are valid
	if _, err := parseIPs(flattenMap(config.KeyIPMap)); err != nil {
		return nil, err
	}
	return &Middleware{
		next:       next,
		headerName: config.HeaderName,
		keyIpMap:   config.KeyIPMap,
		name:       name,
	}, nil
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	apiKey := req.Header.Get(m.headerName)

	// If no API key provided, we allow the request through normally
	if apiKey == "" {
		m.next.ServeHTTP(rw, req)
		return
	}

	// Hashed API key
	hasher := sha256.New()
	hasher.Write([]byte(apiKey))
	hashBytes := hasher.Sum(nil)
	hashedKeyStr := hex.EncodeToString(hashBytes)

	// Check if API key is in the key map and if not allow the request
	ipList, exists := m.keyIpMap[hashedKeyStr]
	if !exists {
		m.next.ServeHTTP(rw, req)
		return
	}

	clientIP := getClientIP(req)
	// We can ignore error here since it's safe to assume the IP list is valid
	parsedIPs, _ := parseIPs(ipList)
	if ipAllowed(clientIP, parsedIPs) {
		m.next.ServeHTTP(rw, req)
		return
	}
	http.Error(rw, "IP not allowed", http.StatusForbidden)
}

func parseIPs(list []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet

	for _, s := range list {
		// CIDR case
		if ip, ipnet, err := net.ParseCIDR(s); err == nil {
			ipnet.IP = ip
			nets = append(nets, ipnet)
			continue
		}

		// Single IP case
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR: %s", s)
		}

		// Normalize IPv4-mapped IPv6 → pure IPv4
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			nets = append(nets, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(32, 32),
			})
			continue
		}

		// IPv6
		nets = append(nets, &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		})
	}

	return nets, nil
}

func getClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return nil
	}

	// Normalize IPv4-mapped IPv6 → pure IPv4
	if v4 := remoteIP.To4(); v4 != nil {
		remoteIP = v4
	}

	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		if ip := net.ParseIP(strings.TrimSpace(cf)); ip != nil {
			return ip
		}
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, p := range parts {
			ip := net.ParseIP(strings.TrimSpace(p))
			if ip != nil {
				return ip
			}
		}
	}
	return remoteIP
}

func ipAllowed(ip net.IP, allowed []*net.IPNet) bool {
	for _, net := range allowed {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func flattenMap(m map[string][]string) []string {
	var result []string
	for _, slice := range m {
		result = append(result, slice...)
	}
	return result
}
