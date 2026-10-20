package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ValidateProxmoxTailnetConfig admits only the native, confidential, fixed-lease
// path. Direct authKey/seed bootstrap and implicit underlay fallback are not used.
func ValidateProxmoxTailnetConfig(cfg Config) error {
	if !cfg.Tailscale.Enabled {
		return nil
	}
	endpoint, err := url.Parse(cfg.Proxmox.APIURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || cfg.Proxmox.InsecureTLS {
		return Exit(2, "Proxmox Tailnet provisioning requires strictly verified HTTPS without URL credentials, query or fragment")
	}
	if cfg.Network != NetworkTailscale || cfg.TargetOS != targetLinux {
		return Exit(2, "Proxmox Tailnet provisioning requires --network tailscale, target=linux and SSH port 22")
	}
	if strings.TrimSpace(cfg.Tailscale.AuthKey) != "" || cfg.Tailscale.ExitNode != "" || cfg.Tailscale.ExitNodeAllowLANAccess {
		return Exit(2, "Proxmox Tailnet provisioning requires the per-lease broker, not a direct auth key or exit node")
	}
	if !filepath.IsAbs(cfg.Proxmox.TailscaleBroker) {
		return Exit(3, "proxmox.tailscaleBroker must be a trusted absolute executable path (user config or CRABBOX_PROXMOX_TAILSCALE_BROKER)")
	}
	if err := validateNetworkConfig(cfg); err != nil {
		return err
	}
	return validateProxmoxTailnetTags(cfg.Tailscale.Tags)
}

// Keep admission aligned with the prepared helper before clone or key issuance.
func validateProxmoxTailnetTags(tags []string) error {
	if len(tags) == 0 || len(tags) > 32 {
		return Exit(2, "Proxmox Tailnet enrollment requires 1–32 unique tags")
	}
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		name := strings.TrimPrefix(tag, "tag:")
		if !strings.HasPrefix(tag, "tag:") || !validProxmoxTailnetName(name, 63) || seen[tag] {
			return Exit(2, "Proxmox Tailnet enrollment requires unique tags with alphanumeric names and hyphens")
		}
		seen[tag] = true
	}
	return nil
}

func validProxmoxTailnetName(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for i, ch := range []byte(value) {
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || i > 0 && ch == '-' {
			continue
		}
		return false
	}
	return true
}

// ValidateProxmoxTailnetIdentity validates the exact final rendering, not a
// template estimate. Call after slug allocation and before reserving a VMID.
func ValidateProxmoxTailnetIdentity(cfg Config, leaseID, slug string) error {
	if !cfg.Tailscale.Enabled {
		return nil
	}
	if err := validateProxmoxTailnetTags(cfg.Tailscale.Tags); err != nil {
		return err
	}
	if !validProxmoxTailnetName(RenderTailscaleHostname(cfg.Tailscale.HostnameTemplate, leaseID, slug, "proxmox"), 63) {
		return Exit(2, "Proxmox Tailnet rendered hostname must be 1–63 lowercase alphanumeric or hyphen characters, starting with alphanumeric")
	}
	return nil
}

// Native descriptions are not cloud label sets: keep structured tag syntax
// intact instead of the lossy generic cloud-label sanitizer.
func ProxmoxTailnetIdentityLabels(cfg Config, leaseID, slug string) map[string]string {
	if !cfg.Tailscale.Enabled {
		return nil
	}
	server := Server{}
	applyTailscaleMetadataToServer(&server, TailscaleMetadata{
		Enabled: true, State: "requested", Tags: cfg.Tailscale.Tags,
		Hostname: RenderTailscaleHostname(cfg.Tailscale.HostnameTemplate, leaseID, slug, "proxmox"),
	})
	return server.Labels
}

func proxmoxTailnetIPv4(value string) bool {
	ip := net.ParseIP(value).To4()
	return ip != nil && ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127
}

// ValidateProxmoxTailnetAccess also applies when the current invocation omits
// --tailscale: persisted lease policy cannot be downgraded by run/inspect/replay.
func ValidateProxmoxTailnetAccess(cfg Config, server Server) error {
	required := server.Labels["tailscale"] == "true"
	if cfg.Network == NetworkTailscale && !required {
		return Exit(5, "network=tailscale requested but Proxmox lease has no managed Tailnet identity")
	}
	if required && (cfg.Network == NetworkPublic || !proxmoxTailnetIPv4(server.PublicNet.IPv4.IP) || server.Labels["tailscale_ipv4"] != server.PublicNet.IPv4.IP) {
		return Exit(5, "Proxmox Tailnet lease requires a current tailscale0 CGNAT IPv4; no underlay fallback")
	}
	return nil
}

type proxmoxTailnetBrokerRequest struct {
	Version    int      `json:"version"`
	Operation  string   `json:"operation"`
	Endpoint   string   `json:"endpoint"`
	Node       string   `json:"node"`
	LeaseID    string   `json:"leaseId"`
	VMID       string   `json:"vmid"`
	Generation string   `json:"generation"`
	Hostname   string   `json:"hostname"`
	Tags       []string `json:"tags"`
}

type proxmoxTailnetCredential struct {
	AuthKey   string    `json:"authKey"`
	ExpiresAt time.Time `json:"expiresAt"`
	Ephemeral bool      `json:"ephemeral"`
	Reusable  *bool     `json:"reusable"`
}

// PVE normalizes QGA booleans to 0/1; accept the underlying QGA JSON form too.
type proxmoxAgentBool bool

func (value *proxmoxAgentBool) UnmarshalJSON(data []byte) error {
	switch string(bytes.TrimSpace(data)) {
	case "true", "1":
		*value = true
	case "false", "0":
		*value = false
	default:
		return errors.New("invalid Proxmox guest-agent boolean")
	}
	return nil
}

// broker credentials are inherited through the service's protected environment,
// never argv or the lease record. Its stdout is private protocol, not diagnostics.
var proxmoxRunTailnetBroker = runProxmoxTailnetBroker

func runProxmoxTailnetBroker(ctx context.Context, program string, request proxmoxTailnetBrokerRequest) (proxmoxTailnetCredential, error) {
	var result proxmoxTailnetCredential
	if !filepath.IsAbs(program) {
		return result, errors.New("Proxmox Tailnet broker is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	input, err := json.Marshal(request)
	if err != nil {
		return result, errors.New("encode Proxmox Tailnet broker request")
	}
	cmd := exec.CommandContext(ctx, program)
	cmd.Stdin = bytes.NewReader(input)
	out := newSynchronizedBuffer(16 << 10)
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, errors.New("Proxmox Tailnet broker failed (output suppressed)")
	}
	data, truncated := out.boundedString()
	if truncated {
		return result, errors.New("Proxmox Tailnet broker response exceeds limit")
	}
	if request.Operation == "release" {
		// An explicit acknowledgment is required; an empty/crashed wrapper is not cleanup.
		var ack struct {
			Released bool `json:"released"`
		}
		if json.Unmarshal([]byte(data), &ack) != nil || !ack.Released {
			return result, errors.New("Proxmox Tailnet broker did not confirm release")
		}
		return result, nil
	}
	if json.Unmarshal([]byte(data), &result) != nil {
		return proxmoxTailnetCredential{}, errors.New("invalid Proxmox Tailnet broker response")
	}
	now := time.Now()
	if !strings.HasPrefix(result.AuthKey, "tskey-auth-") || len(result.AuthKey) > 4096 || strings.ContainsAny(result.AuthKey, "\r\n\x00") || !result.Ephemeral || (result.Reusable == nil || *result.Reusable) || !result.ExpiresAt.After(now) || result.ExpiresAt.After(now.Add(10*time.Minute)) {
		return proxmoxTailnetCredential{}, errors.New("Proxmox Tailnet broker must issue a short-lived nonreusable ephemeral key")
	}
	return result, nil
}

func proxmoxTailnetRequest(cfg Config, server Server, operation string) (proxmoxTailnetBrokerRequest, error) {
	if server.Provider != "proxmox" || !IsCanonicalLeaseID(server.Labels["lease"]) || server.CloudID == "" || server.HostID == "" || proxmoxGenerationID(server.ImmutableID) == "" || server.Labels["tailscale"] != "true" {
		return proxmoxTailnetBrokerRequest{}, errors.New("Proxmox Tailnet operation requires a bound lease, VMID, node and generation")
	}
	return proxmoxTailnetBrokerRequest{Version: 1, Operation: operation, Endpoint: strings.TrimSuffix(strings.TrimRight(cfg.Proxmox.APIURL, "/"), "/api2/json"), Node: server.HostID, LeaseID: server.Labels["lease"], VMID: server.CloudID, Generation: server.ImmutableID, Hostname: server.Labels["tailscale_hostname"], Tags: splitCommaList(server.Labels["tailscale_tags"])}, nil
}

// ReleaseProxmoxTailnet is idempotent at the broker and runs before a fixed
// claim becomes terminal, including retries where the VM is already absent.
func ReleaseProxmoxTailnet(ctx context.Context, cfg Config, server Server) error {
	request, err := proxmoxTailnetRequest(cfg, server, "release")
	if err != nil {
		return err
	}
	_, err = proxmoxRunTailnetBroker(ctx, cfg.Proxmox.TailscaleBroker, request)
	return err
}

func (c *ProxmoxClient) provisionTailnet(ctx context.Context, cfg Config, server Server) error {
	ctx, cancel := context.WithTimeout(ctx, BootstrapWaitTimeout(cfg))
	defer cancel()
	request, err := proxmoxTailnetRequest(cfg, server, "acquire")
	if err != nil {
		return err
	}
	if !validProxmoxTailnetName(request.Hostname, 63) {
		return Exit(2, "invalid Proxmox Tailnet rendered hostname")
	}
	if err := validateProxmoxTailnetTags(request.Tags); err != nil {
		return err
	}
	// Check the exact isolated capability before issuing a key. This check never
	// grants permissions or falls back to the controller/CI principal.
	var permissions map[string]map[string]proxmoxInt
	permissionPath := "/vms/" + server.CloudID
	if err := c.doRequired(ctx, http.MethodGet, "/access/permissions?path="+url.QueryEscape(permissionPath), nil, &permissions); err != nil {
		return err
	}
	if _, ok := permissions[permissionPath]["VM.GuestAgent.Unrestricted"]; !ok {
		return errors.New("Proxmox Tailnet enrollment requires VM.GuestAgent.Unrestricted on " + permissionPath + "; operator must approve this isolated runtime capability")
	}
	vmid, err := strconv.Atoi(server.CloudID)
	if err != nil || vmid <= 0 {
		return errors.New("invalid Proxmox Tailnet VMID")
	}
	// Wait for QGA, without waiting for (or using) an underlay SSH address.
	for {
		_, err = c.guestIPv4ForNetwork(ctx, vmid, false)
		if err == nil {
			break
		}
		if err = proxmoxTailnetWait(ctx); err != nil {
			return err
		}
	}
	// Re-read generation immediately before issuing any credential.
	current, err := c.getServer(ctx, server.CloudID, true)
	if err != nil {
		return err
	}
	if current.ImmutableID != server.ImmutableID || current.Labels["lease"] != request.LeaseID || current.Labels["fixed_intent_sha256"] != server.Labels["fixed_intent_sha256"] {
		return errors.New("Proxmox Tailnet guest identity changed before enrollment")
	}
	credential, err := proxmoxRunTailnetBroker(ctx, cfg.Proxmox.TailscaleBroker, request)
	if err != nil {
		return err
	}
	input, err := json.Marshal(struct {
		AuthKey  string   `json:"authKey"`
		Hostname string   `json:"hostname"`
		Tags     []string `json:"tags"`
	}{credential.AuthKey, request.Hostname, request.Tags})
	if err != nil {
		return errors.New("encode Proxmox Tailnet enrollment input")
	}
	// PVE's REST API accepts raw input-data and base64-encodes it for QGA.
	path := fmt.Sprintf("/nodes/%s/qemu/%s/agent/exec", url.PathEscape(server.HostID), url.PathEscape(server.CloudID))
	var process struct {
		PID int `json:"pid"`
	}
	if err := c.tailnetAgentRequest(ctx, http.MethodPost, path, url.Values{"command": {"/usr/local/libexec/crabbox-enroll"}, "input-data": {string(input)}}, &process); err != nil {
		return err
	}
	if process.PID <= 0 {
		return errors.New("Proxmox Tailnet helper did not return a PID")
	}
	for {
		var status struct {
			Exited   proxmoxAgentBool `json:"exited"`
			ExitCode *int             `json:"exitcode"`
			Signal   *int             `json:"signal"`
		}
		if err := c.tailnetAgentRequest(ctx, http.MethodGet, path+"-status?pid="+strconv.Itoa(process.PID), nil, &status); err != nil {
			return err
		}
		if status.Exited {
			if status.ExitCode == nil || *status.ExitCode != 0 || status.Signal != nil {
				return errors.New("Proxmox Tailnet helper failed (output suppressed)")
			}
			return nil
		}
		if err := proxmoxTailnetWait(ctx); err != nil {
			return err
		}
	}
}

func proxmoxTailnetWait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Second):
		return nil
	}
}

// Never promote secret-bearing request/response bodies or helper output into
// errors, even if a proxy echoes input-data. Do not follow credential redirects.
func (c *ProxmoxClient) tailnetAgentRequest(ctx context.Context, method, path string, form url.Values, out any) error {
	scoped := *c
	client := *c.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	scoped.Client = &client
	if err := scoped.doRequired(ctx, method, path, form, out); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("Proxmox Tailnet guest-agent request failed (body suppressed); requires VM.GuestAgent.Unrestricted on the worker VM")
	}
	return nil
}
