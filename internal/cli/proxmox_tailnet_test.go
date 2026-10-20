package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const tailnetTestKey = "tskey-auth-not-a-real-enrollment-key"
const tailnetTestGeneration = "8be39656-32b0-4c47-b68c-0a9e1d3ef901"

func tailnetTestConfig() Config {
	cfg := baseConfig()
	cfg.Provider, cfg.TargetOS, cfg.Network = "proxmox", targetLinux, NetworkTailscale
	cfg.SSHPort = "22"
	cfg.Tailscale = TailscaleConfig{Enabled: true, Tags: []string{"tag:worker"}, HostnameTemplate: "cbx-{id}"}
	broker, _ := filepath.Abs(filepath.Join("trusted", "broker"))
	cfg.Proxmox = ProxmoxConfig{APIURL: "https://pve.example.test:8006", Node: "pve1", TemplateID: 9400, TailscaleBroker: broker}
	return cfg
}

func tailnetTestServer() Server {
	return Server{Provider: "proxmox", CloudID: "417", ID: 417, HostID: "pve1", ImmutableID: tailnetTestGeneration, Labels: map[string]string{
		"crabbox": "true", "provider": "proxmox", "lease": "cbx_123456abcdef", "fixed_intent_sha256": "bound-intent", "tailscale": "true", "tailscale_tags": "tag:worker", "tailscale_hostname": "cbx-test", "state": "leased",
	}}
}

func TestProxmoxTailnetTrustedConfigAndAdmission(t *testing.T) {
	cfg := tailnetTestConfig()
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"valid", func(*Config) {}, ""},
		{"http", func(c *Config) { c.Proxmox.APIURL = "http://pve.example.test" }, "HTTPS"},
		{"tls bypass", func(c *Config) { c.Proxmox.InsecureTLS = true }, "HTTPS"},
		{"userinfo", func(c *Config) { c.Proxmox.APIURL = "https://user:password@pve.example.test" }, "HTTPS"},
		{"query", func(c *Config) { c.Proxmox.APIURL += "?secret=value" }, "HTTPS"},
		{"public", func(c *Config) { c.Network = NetworkPublic }, "network tailscale"},
		{"auto", func(c *Config) { c.Network = NetworkAuto }, "network tailscale"},
		{"target", func(c *Config) { c.TargetOS = targetWindows }, "target=linux"},
		{"key", func(c *Config) { c.Tailscale.AuthKey = tailnetTestKey }, "per-lease broker"},
		{"exit", func(c *Config) { c.Tailscale.ExitNode = "100.100.1.1" }, "exit node"},
		{"broker", func(c *Config) { c.Proxmox.TailscaleBroker = "relative" }, "absolute"},
		{"tags", func(c *Config) { c.Tailscale.Tags = nil }, "at least one tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			tc.change(&c)
			err := ValidateProxmoxTailnetConfig(c)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err=%v want=%s", err, tc.want)
			}
		})
	}
	cfg.Tailscale.Enabled = false
	cfg.Proxmox.InsecureTLS = true
	if err := ValidateProxmoxTailnetConfig(cfg); err != nil {
		t.Fatal("direct mode changed", err)
	}
	var file fileProxmoxConfig
	if err := json.Unmarshal([]byte(`{"tailscaleBroker":"/untrusted/program"}`), &file); err != nil {
		t.Fatal(err)
	}
	cfg = baseConfig()
	if err := applyProxmoxFileConfig(&cfg, &file, configInputRepo, credentialSourceForFile(false)); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxmox.TailscaleBroker != "" {
		t.Fatal("repository can select executable")
	}
	if err := applyProxmoxFileConfig(&cfg, &file, configInputUser, credentialSourceTrustedFile); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxmox.TailscaleBroker != "/untrusted/program" {
		t.Fatal("user opt-in missing")
	}
	t.Setenv("CRABBOX_PROXMOX_TAILSCALE_BROKER", "/trusted/from-env")
	if err := applyProxmoxEnvironmentConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxmox.TailscaleBroker != "/trusted/from-env" {
		t.Fatal("environment opt-in missing")
	}
}

func TestProxmoxTailnetSelectsOnlyTailscale0(t *testing.T) {
	for _, tc := range []struct{ name, interfaces, want string }{
		{"underlay first", `[{"name":"eth0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"10.77.1.32"}]},{"name":"tailscale0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"100.101.2.3"}]}]`, "100.101.2.3"},
		{"no interface", `[{"name":"eth0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"100.101.2.3"}]}]`, ""},
		{"wrong case", `[{"name":"Tailscale0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"100.101.2.3"}]}]`, ""},
		{"not cgnat", `[{"name":"tailscale0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"10.77.1.32"}]}]`, ""},
		{"below range", `[{"name":"tailscale0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"100.63.255.255"}]}]`, ""},
		{"above range", `[{"name":"tailscale0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"100.128.0.0"}]}]`, ""},
		{"ipv6", `[{"name":"tailscale0","ip-addresses":[{"ip-address-type":"ipv6","ip-address":"fd7a:115c:a1e0::1"}]}]`, ""},
		{"deterministic", `[{"name":"tailscale0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"100.70.0.2"},{"ip-address-type":"ipv4","ip-address":"100.70.0.1"}]}]`, "100.70.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var interfaces []proxmoxAgentInterface
			if err := json.Unmarshal([]byte(tc.interfaces), &interfaces); err != nil {
				t.Fatal(err)
			}
			got, err := proxmoxInterfaceIPv4(interfaces, true)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("got=%s err=%v", got, err)
			}
		})
	}
}

func TestProxmoxTailnetNativeEnrollmentAndFailClosedRouting(t *testing.T) {
	for _, problem := range []string{"", "boolean flags", "numeric running", "denied", "generation", "exec echo", "status echo", "helper failure", "no pid", "cancel", "no tailscale0", "changed hostname", "changed tags"} {
		t.Run(problem, func(t *testing.T) {
			cfg, server := tailnetTestConfig(), tailnetTestServer()
			server.Labels["tailscale_fqdn"] = "10.77.1.32"
			server.Labels["tailscale_device_id"] = "forged-description-device"
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var issued, execs, statuses int
			previous := proxmoxRunTailnetBroker
			proxmoxRunTailnetBroker = func(_ context.Context, _ string, request proxmoxTailnetBrokerRequest) (proxmoxTailnetCredential, error) {
				issued++
				if request.LeaseID != server.Labels["lease"] || request.VMID != "417" || request.Generation != server.ImmutableID || request.Operation != "acquire" {
					t.Errorf("incorrect broker identity %+v", request)
				}
				return proxmoxTailnetCredential{AuthKey: tailnetTestKey}, nil
			}
			t.Cleanup(func() { proxmoxRunTailnetBroker = previous })
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/api2/json")
				var data any
				switch {
				case path == "/access/permissions":
					permissions := map[string]int{"VM.GuestAgent.Unrestricted": 1}
					if problem == "denied" {
						permissions = map[string]int{"VM.GuestAgent.FileWrite": 1}
					}
					data = map[string]any{"/vms/417": permissions}
				case strings.HasSuffix(path, "/agent/network-get-interfaces"):
					interfaces := []map[string]any{{"name": "eth0", "ip-addresses": []map[string]string{{"ip-address-type": "ipv4", "ip-address": "10.77.1.32"}}}}
					if execs > 0 && problem != "no tailscale0" {
						interfaces = append(interfaces, map[string]any{"name": "tailscale0", "ip-addresses": []map[string]string{{"ip-address-type": "ipv4", "ip-address": "100.100.1.2"}}})
					}
					data = map[string]any{"result": interfaces}
				case strings.HasSuffix(path, "/status/current"):
					data = map[string]any{"vmid": 417, "name": "crabbox-test", "status": "running"}
				case strings.HasSuffix(path, "/config"):
					generation := tailnetTestGeneration
					if problem == "generation" {
						generation = "9be39656-32b0-4c47-b68c-0a9e1d3ef901"
					}
					labels := make(map[string]string, len(server.Labels))
					for k, v := range server.Labels {
						labels[k] = v
					}
					if problem == "changed hostname" {
						labels["tailscale_hostname"] = "changed-worker"
					}
					if problem == "changed tags" {
						labels["tailscale_tags"] = "tag:other"
					}
					data = map[string]any{"vmgenid": generation, "description": proxmoxDescription(labels)}
				case strings.HasSuffix(path, "/agent/exec"):
					execs++
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					if r.Form.Get("command") != "/usr/local/libexec/crabbox-enroll" || len(r.Form["command"]) != 1 {
						t.Error("unexpected helper command")
					}
					if strings.Contains(r.URL.String(), tailnetTestKey) {
						t.Error("key in URL")
					}
					var input map[string]any
					if json.Unmarshal([]byte(r.Form.Get("input-data")), &input) != nil || input["authKey"] != tailnetTestKey || input["hostname"] != "cbx-test" {
						t.Error("missing confidential stdin")
					}
					if problem == "exec echo" {
						w.WriteHeader(500)
						fmt.Fprint(w, tailnetTestKey)
						return
					}
					pid := 42
					if problem == "no pid" {
						pid = 0
					}
					data = map[string]int{"pid": pid}
				case strings.HasSuffix(path, "/agent/exec-status"):
					statuses++
					if r.URL.Query().Get("pid") != "42" {
						t.Error("wrong pid")
					}
					if problem == "status echo" {
						w.WriteHeader(500)
						fmt.Fprint(w, tailnetTestKey)
						return
					}
					if problem == "cancel" {
						cancel()
						data = map[string]int{"exited": 0}
					} else {
						exit := 0
						if problem == "helper failure" {
							exit = 1
						}
						data = map[string]any{"exited": 1, "exitcode": exit, "out-data": tailnetTestKey, "err-data": tailnetTestKey}
						if problem == "boolean flags" {
							data.(map[string]any)["exited"] = true
						}
						if problem == "numeric running" && statuses == 1 {
							data.(map[string]any)["exited"] = 0
						}
					}
				default:
					t.Errorf("unexpected %s", path)
					w.WriteHeader(500)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
			}))
			defer api.Close()
			cfg.Proxmox.APIURL = api.URL
			client := &ProxmoxClient{BaseURL: api.URL, Node: "pve1", Client: api.Client()}
			err := client.provisionTailnet(ctx, cfg, server)
			if problem == "" || problem == "no tailscale0" || problem == "boolean flags" || problem == "numeric running" {
				if err != nil {
					t.Fatal(err)
				}
				live, err := client.GetServer(t.Context(), "417")
				if err != nil {
					t.Fatal(err)
				}
				if problem == "no tailscale0" {
					if live.PublicNet.IPv4.IP != "" {
						t.Fatal("LAN fallback")
					}
					if ValidateProxmoxTailnetAccess(cfg, live) == nil {
						t.Fatal("missing interface admitted")
					}
				} else {
					if live.PublicNet.IPv4.IP != "100.100.1.2" || live.Labels["tailscale_ipv4"] != "100.100.1.2" || live.Labels["tailscale_fqdn"] != "" || live.Labels["tailscale_device_id"] != "" {
						t.Fatalf("wrong routing %+v", live)
					}
					if err := ValidateProxmoxTailnetAccess(cfg, live); err != nil {
						t.Fatal(err)
					}
					cfg.Network = NetworkPublic
					if ValidateProxmoxTailnetAccess(cfg, live) == nil {
						t.Fatal("public downgraded lease policy")
					}
				}
			} else if err == nil {
				t.Fatal("expected failure")
			} else if strings.Contains(err.Error(), tailnetTestKey) {
				t.Fatal("credential leaked in error")
			}
			if (problem == "denied" || problem == "generation" || problem == "changed hostname" || problem == "changed tags") && (issued != 0 || execs != 0) {
				t.Fatal("issued key before capability/identity validation")
			}
			if problem == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation=%v", err)
			}
			if problem == "" && (issued != 1 || execs != 1 || statuses != 1) {
				t.Fatalf("calls %d/%d/%d", issued, execs, statuses)
			}
		})
	}
}

func TestProxmoxTailnetBrokerPrivateProtocol(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable fixture")
	}
	for _, problem := range []string{"", "reusable", "not ephemeral", "expired", "long ttl", "bad json", "oversize", "stderr", "release", "bad release"} {
		t.Run(problem, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "broker")
			captured := filepath.Join(dir, "request")
			credential := proxmoxTailnetCredential{AuthKey: tailnetTestKey, ExpiresAt: time.Now().Add(5 * time.Minute), Ephemeral: true, Reusable: new(bool)}
			switch problem {
			case "reusable":
				*credential.Reusable = true
			case "not ephemeral":
				credential.Ephemeral = false
			case "expired":
				credential.ExpiresAt = time.Now().Add(-time.Minute)
			case "long ttl":
				credential.ExpiresAt = time.Now().Add(time.Hour)
			}
			data, _ := json.Marshal(credential)
			if problem == "bad json" {
				data = []byte(tailnetTestKey)
			}
			if problem == "oversize" {
				data = []byte(strings.Repeat("x", 17000))
			}
			operation := "acquire"
			if problem == "release" || problem == "bad release" {
				operation = "release"
				data = []byte(`{"released":true}`)
				if problem == "bad release" {
					data = []byte(`{}`)
				}
			}
			script := "#!/bin/sh\ncat >" + shellQuote(captured) + "\nprintf '%s' " + shellQuote(string(data)) + "\n"
			if problem == "stderr" {
				script += "printf '%s' " + shellQuote(tailnetTestKey) + " >&2\nexit 1\n"
			}
			if err := os.WriteFile(path, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			request, _ := proxmoxTailnetRequest(tailnetTestConfig(), tailnetTestServer(), operation)
			result, err := runProxmoxTailnetBroker(t.Context(), path, request)
			if problem == "" || problem == "release" {
				if err != nil {
					t.Fatal(err)
				}
				if problem == "" && result.AuthKey != tailnetTestKey {
					t.Fatal("private key missing")
				}
			} else if err == nil {
				t.Fatal("invalid broker result admitted")
			}
			if err != nil && strings.Contains(err.Error(), tailnetTestKey) {
				t.Fatal("secret-bearing diagnostic")
			}
			got, err := os.ReadFile(captured)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(got), tailnetTestKey) {
				t.Fatal("key in broker request")
			}
			var identity proxmoxTailnetBrokerRequest
			if json.Unmarshal(got, &identity) != nil || identity.Generation != tailnetTestGeneration || identity.LeaseID != "cbx_123456abcdef" {
				t.Fatal("binding lost")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := runProxmoxTailnetBroker(ctx, "/does/not/exist", proxmoxTailnetBrokerRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

func TestProxmoxTailnetSuppressesRedirectAndTransportErrors(t *testing.T) {
	var redirected bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer source.Close()
	c := &ProxmoxClient{BaseURL: source.URL, Client: source.Client()}
	var result any
	err := c.tailnetAgentRequest(t.Context(), http.MethodPost, "/exec", url.Values{"input-data": {tailnetTestKey}}, &result)
	if err == nil || redirected {
		t.Fatal("confidential request followed redirect")
	}
}

func TestProxmoxTailnetCloneEnrollBootstrapNativeFlow(t *testing.T) {
	for _, problem := range []string{"", "generation after join", "missing interface", "SSH bootstrap", "hostname after bind", "tags after bind"} {
		t.Run(problem, func(t *testing.T) {
			cfg := tailnetTestConfig()
			cfg.Proxmox.TokenID, cfg.Proxmox.TokenSecret = "runner@pve!worker", "fixture-provider-token"
			var events []string
			var description, bootstrap string
			joined, bound := false, false
			previousBroker, previousProbe, previousInput := proxmoxRunTailnetBroker, proxmoxRunSSHQuietWithOptions, proxmoxRunSSHInput
			t.Cleanup(func() {
				proxmoxRunTailnetBroker, proxmoxRunSSHQuietWithOptions, proxmoxRunSSHInput = previousBroker, previousProbe, previousInput
			})
			proxmoxRunTailnetBroker = func(_ context.Context, _ string, request proxmoxTailnetBrokerRequest) (proxmoxTailnetCredential, error) {
				if !bound || request.Generation != tailnetTestGeneration || request.Hostname != RenderTailscaleHostname(cfg.Tailscale.HostnameTemplate, "cbx_123456abcdef", "native", "proxmox") || strings.Join(request.Tags, ",") != "tag:worker" {
					t.Error("issuer preceded durable generation binding")
				}
				events = append(events, "issue")
				return proxmoxTailnetCredential{AuthKey: tailnetTestKey}, nil
			}
			proxmoxRunSSHQuietWithOptions = func(_ context.Context, target SSHTarget, _ string, _ string, _ string) error {
				if !joined || target.Host != "100.100.1.2" || target.Port != "22" || len(target.FallbackPorts) != 0 {
					t.Errorf("unsafe SSH target %+v", target)
				}
				return nil
			}
			proxmoxRunSSHInput = func(_ context.Context, _ SSHTarget, _ string, input io.Reader, _ io.Writer, _ io.Writer) error {
				data, err := io.ReadAll(input)
				bootstrap = string(data)
				events = append(events, "SSH")
				if problem == "SSH bootstrap" {
					return errors.New("fixture SSH failure")
				}
				return err
			}
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/api2/json")
				var data any
				switch {
				case strings.HasSuffix(path, "/clone"):
					form := readForm(t, r)
					description = form.Get("description")
					events = append(events, "clone")
					if form.Get("newid") != "417" || description == "" {
						t.Error("missing fixed clone identity")
					}
					data = "UPID:pve1:clone"
				case strings.Contains(path, "/tasks/"):
					data = map[string]string{"status": "stopped", "exitstatus": "OK"}
				case path == "/access/permissions":
					data = map[string]any{"/vms/417": map[string]int{"VM.GuestAgent.Unrestricted": 1}}
				case strings.HasSuffix(path, "/config") && r.Method == http.MethodPost:
					form := readForm(t, r)
					if strings.Contains(form.Encode(), tailnetTestKey) {
						t.Error("key in persistent guest config")
					}
					if form.Get("ipconfig0") != "ip=dhcp" || !strings.Contains(form.Get("sshkeys"), "ssh-ed25519") {
						t.Error("normal cloud-init key/DHCP path changed")
					}
					description = form.Get("description")
					events = append(events, "configure")
					data = "UPID:pve1:config"
				case strings.HasSuffix(path, "/status/start"):
					events = append(events, "start")
					data = "UPID:pve1:start"
					if problem == "hostname after bind" || problem == "tags after bind" {
						labels := proxmoxDescriptionLabels(description)
						if problem == "hostname after bind" {
							labels["tailscale_hostname"] = "changed-worker"
						} else {
							labels["tailscale_tags"] = "tag:other"
						}
						description = proxmoxDescription(labels)
					}
				case strings.HasSuffix(path, "/status/current"):
					data = map[string]any{"vmid": 417, "name": "crabbox-test", "status": "running"}
				case strings.HasSuffix(path, "/config"):
					generation := tailnetTestGeneration
					if joined && problem == "generation after join" {
						generation = "9be39656-32b0-4c47-b68c-0a9e1d3ef901"
					}
					data = map[string]string{"description": description, "vmgenid": generation}
				case strings.HasSuffix(path, "/agent/network-get-interfaces"):
					interfaces := []any{map[string]any{"name": "eth0", "ip-addresses": []any{map[string]string{"ip-address-type": "ipv4", "ip-address": "10.77.1.32"}}}}
					if joined && problem != "missing interface" {
						interfaces = append(interfaces, map[string]any{"name": "tailscale0", "ip-addresses": []any{map[string]string{"ip-address-type": "ipv4", "ip-address": "100.100.1.2"}}})
					}
					data = map[string]any{"result": interfaces}
				case strings.HasSuffix(path, "/agent/exec"):
					form := readForm(t, r)
					if form.Get("command") != "/usr/local/libexec/crabbox-enroll" || !strings.Contains(form.Get("input-data"), tailnetTestKey) {
						t.Error("bad QGA stdin handoff")
					}
					events = append(events, "enroll")
					joined = true
					data = map[string]int{"pid": 42}
				case strings.HasSuffix(path, "/agent/exec-status"):
					data = map[string]any{"exited": 1, "exitcode": 0}
				default:
					t.Errorf("unexpected native mutation %s %s", r.Method, path)
					w.WriteHeader(500)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
			}))
			defer api.Close()
			cfg.Proxmox.APIURL = api.URL
			client, err := NewProxmoxClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			client.Client = api.Client()
			ctx := t.Context()
			var cancel context.CancelFunc
			if problem == "missing interface" {
				ctx, cancel = context.WithTimeout(ctx, 250*time.Millisecond)
				defer cancel()
			}
			live, err := client.CreateServerWithVMID(ctx, cfg, "ssh-ed25519 AAAA fixture", "cbx_123456abcdef", "native", true, 417, map[string]string{"fixed_intent_sha256": "bound-intent"}, func(server Server) error {
				bound = true
				events = append(events, "bind")
				if server.ImmutableID != tailnetTestGeneration {
					t.Error("missing generation")
				}
				return nil
			})
			if problem == "" {
				if err != nil || live.PublicNet.IPv4.IP != "100.100.1.2" {
					t.Fatalf("live=%+v err=%v", live, err)
				}
				if strings.Join(events, ",") != "clone,bind,configure,start,issue,enroll,SSH" {
					t.Fatalf("ordering %v", events)
				}
				if !strings.Contains(bootstrap, "crabbox-ready") || strings.Contains(bootstrap, tailnetTestKey) {
					t.Fatal("bootstrap contract or key isolation changed")
				}
			} else if err == nil {
				t.Fatal("unsafe provisioning admitted")
			}
			if problem == "hostname after bind" || problem == "tags after bind" {
				for _, event := range events {
					if event == "issue" || event == "enroll" {
						t.Fatal("mutable policy reached issuer or helper")
					}
				}
			}
			if (problem == "generation after join" || problem == "missing interface") && bootstrap != "" {
				t.Fatal("SSH ran without current stable tailnet identity")
			}
		})
	}
}

func TestProxmoxTailnetNativeStatusBoolean(t *testing.T) {
	for _, input := range []string{"0", "1", "false", "true"} {
		var flag proxmoxAgentBool
		if err := json.Unmarshal([]byte(input), &flag); err != nil {
			t.Fatalf("native flag %s: %v", input, err)
		}
		if bool(flag) != (input == "1" || input == "true") {
			t.Fatal("incorrect status flag")
		}
	}
	for _, input := range []string{"2", "null", "\"1\"", "{}"} {
		var flag proxmoxAgentBool
		if err := json.Unmarshal([]byte(input), &flag); err == nil {
			t.Fatalf("invalid flag %s admitted", input)
		}
	}
}

func TestProxmoxTailnetRejectsHelperBoundsBeforeNativeClone(t *testing.T) {
	for _, problem := range []string{"hostname", "tags"} {
		t.Run(problem, func(t *testing.T) {
			cfg := tailnetTestConfig()
			cfg.Proxmox.TokenID, cfg.Proxmox.TokenSecret = "runner@pve!worker", "fixture-provider-token"
			if problem == "hostname" {
				cfg.Tailscale.HostnameTemplate = "prefix-{slug}"
			} else {
				for i := 0; i < 32; i++ {
					cfg.Tailscale.Tags = append(cfg.Tailscale.Tags, fmt.Sprintf("tag:worker-%d", i))
				}
			}
			calls, issued := 0, 0
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
			defer api.Close()
			cfg.Proxmox.APIURL = api.URL
			client, err := NewProxmoxClient(cfg)
			if err != nil {
				t.Fatal(err)
			}
			client.Client = api.Client()
			previous := proxmoxRunTailnetBroker
			proxmoxRunTailnetBroker = func(context.Context, string, proxmoxTailnetBrokerRequest) (proxmoxTailnetCredential, error) {
				issued++
				return proxmoxTailnetCredential{}, nil
			}
			t.Cleanup(func() { proxmoxRunTailnetBroker = previous })
			_, err = client.CreateServerWithVMID(t.Context(), cfg, "ssh-ed25519 AAAA fixture", "cbx_123456abcdef", strings.Repeat("a", 60), true, 417, map[string]string{"fixed_intent_sha256": "bound-intent"}, func(Server) error { return nil })
			if err == nil || calls != 0 || issued != 0 {
				t.Fatalf("late admission: calls=%d issued=%d err=%v", calls, issued, err)
			}
		})
	}
}
