package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type NetEmulation struct {
	Enabled               bool    `json:"enabled"`
	BaseLatencyMs         int     `json:"base_latency_ms"`
	JitterMs              int     `json:"jitter_ms"`
	PacketLossProbability float64 `json:"packet_loss_probability"`
}

type RuntimeConfig struct {
	XrayBin          string       `json:"xray_bin"`
	ProbeURL         string       `json:"probe_url"`
	L7TimeoutSec     float64      `json:"l7_timeout_sec"`
	NetworkEmulation NetEmulation `json:"network_emulation"`
}

func applyNetworkEmulation(cfg NetEmulation) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.PacketLossProbability > 0 && rand.Float64() < cfg.PacketLossProbability {
		return fmt.Errorf("synthetic packet loss")
	}
	extra := cfg.BaseLatencyMs
	if cfg.JitterMs > 0 {
		extra += rand.Intn((cfg.JitterMs*2)+1) - cfg.JitterMs
	}
	if extra > 0 {
		time.Sleep(time.Duration(extra) * time.Millisecond)
	}
	return nil
}

func buildXrayConfig(vlessLink string, localPort int) ([]byte, error) {
	u, err := url.Parse(vlessLink)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "vless" {
		return nil, fmt.Errorf("link is not vless")
	}
	uuid := u.User.Username()
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	q := u.Query()
	security := q.Get("security")
	if security == "" {
		security = "none"
	}
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	sni := q.Get("sni")

	streamSettings := map[string]any{
		"network":  network,
		"security": security,
	}
	if security == "tls" {
		streamSettings["tlsSettings"] = map[string]any{"serverName": sni}
	}
	if security == "reality" {
		streamSettings["realitySettings"] = map[string]any{
			"serverName":  sni,
			"fingerprint": fallback(q.Get("fp"), "chrome"),
			"publicKey":   q.Get("pbk"),
			"shortId":     q.Get("sid"),
			"spiderX":     "",
		}
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []map[string]any{ {
			"listen":   "127.0.0.1",
			"port":     localPort,
			"protocol": "socks",
		}},
		"outbounds": []map[string]any{ {
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []map[string]any{{
					"address": host,
					"port":    mustInt(port),
					"users": []map[string]any{{
						"id":         uuid,
						"encryption": "none",
					}},
				}},
			},
			"streamSettings": streamSettings,
		}},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func fallback(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func mustInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func waitForSocks(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("socks not ready")
}

func probeThroughProxy(localPort int, target string, timeout time.Duration, emu NetEmulation) (int, error) {
	if err := applyNetworkEmulation(emu); err != nil {
		return 0, err
	}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), nil, proxy.Direct)
	if err != nil {
		return 0, err
	}
	transport := &http.Transport{}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.Dial(network, addr)
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	start := time.Now()
	resp, err := client.Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return int(time.Since(start).Milliseconds()), nil
}

func classify(err error) string {
	if err == nil {
		return "ok"
	}
	e := strings.ToLower(err.Error())
	switch {
	case strings.Contains(e, "packet loss"):
		return "synthetic_loss"
	case strings.Contains(e, "unexpected status"):
		return "provider_block_suspected"
	case strings.Contains(e, "timeout"), strings.Contains(e, "deadline"):
		return "provider_block_suspected"
	default:
		return "unknown"
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	link := flag.String("link", "", "vless link")
	cfgPath := flag.String("config", "client/config_test.json", "json config path")
	flag.Parse()
	if strings.TrimSpace(*link) == "" {
		fmt.Println("usage: go run ./core/go -link 'vless://...'")
		os.Exit(2)
	}

	rc := RuntimeConfig{XrayBin: "/usr/local/bin/xray", ProbeURL: "https://www.gstatic.com/generate_204", L7TimeoutSec: 5}
	if b, err := os.ReadFile(*cfgPath); err == nil {
		_ = json.Unmarshal(b, &rc)
	}

	cfgData, err := buildXrayConfig(*link, 19090)
	if err != nil {
		fmt.Printf("build config error: %v\n", err)
		os.Exit(1)
	}

	tmpPath := filepath.Join(os.TempDir(), "xray-go-check.json")
	if err := os.WriteFile(tmpPath, cfgData, 0o600); err != nil {
		fmt.Printf("write config error: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpPath)

	cmd := exec.Command(rc.XrayBin, "run", "-c", tmpPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		fmt.Printf("xray start error: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	if err := waitForSocks(19090, 5*time.Second); err != nil {
		fmt.Printf("xray runtime error: %v\n", err)
		os.Exit(1)
	}

	latency, err := probeThroughProxy(19090, rc.ProbeURL, time.Duration(rc.L7TimeoutSec*float64(time.Second)), rc.NetworkEmulation)
	fmt.Printf("classification=%s latency_ms=%d err=%v\n", classify(err), latency, err)
	if err != nil {
		os.Exit(1)
	}
}
