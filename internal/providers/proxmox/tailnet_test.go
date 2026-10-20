package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	core "github.com/openclaw/crabbox/internal/cli"
)

type tailnetFixedClient struct {
	*fixedProxmoxClient
	cancelAfterBind bool
}

func (c *tailnetFixedClient) CreateServerWithVMID(ctx context.Context, cfg core.Config, key, leaseID, slug string, keep bool, vmid int, labels map[string]string, bind func(core.Server) error) (core.Server, error) {
	server, err := c.fixedProxmoxClient.CreateServerWithVMID(ctx, cfg, key, leaseID, slug, keep, vmid, labels, bind)
	if err != nil {
		return server, err
	}
	if c.cancelAfterBind {
		return core.Server{}, context.Canceled
	}
	server.PublicNet.IPv4.IP = "100.100.1.2"
	server.Labels = maps.Clone(server.Labels)
	server.Labels["tailscale_ipv4"] = "100.100.1.2"
	c.servers = []core.Server{server}
	return server, nil
}

func tailnetFixedFixture(t *testing.T) (*leaseBackend, *tailnetFixedClient, core.AcquireRequest) {
	t.Helper()
	backend, client, req := fixedProxmoxFixture(t)
	cfg := backend.Cfg
	cfg.Network = core.NetworkTailscale
	cfg.Tailscale = core.TailscaleConfig{Enabled: true, Tags: []string{"tag:worker"}, HostnameTemplate: "cbx-{id}"}
	cfg.Proxmox.TailscaleBroker = filepath.Join(t.TempDir(), "broker")
	backend.Cfg = withProxmoxGuestAccess(cfg)
	previousRead := readTailnetMetadata
	readTailnetMetadata = func(context.Context, core.SSHTarget) (core.TailscaleMetadata, error) {
		return core.TailscaleMetadata{Enabled: true, State: "ready", IPv4: "100.100.1.2", Hostname: "cbx-example", DeviceID: "nFixtureDevice"}, nil
	}
	t.Cleanup(func() { readTailnetMetadata = previousRead })
	native := &tailnetFixedClient{fixedProxmoxClient: client}
	newClient = func(core.Config) (proxmoxClient, error) { return native, nil }
	return backend, native, req
}

func TestProxmoxTailnetFixedReplayResolveAndIntent(t *testing.T) {
	backend, client, req := tailnetFixedFixture(t)
	first, err := backend.Acquire(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := backend.Acquire(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := backend.Resolve(t.Context(), core.ResolveRequest{ID: req.RequestedLeaseID})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []core.LeaseTarget{first, replay, resolved} {
		if target.SSH.Host != "100.100.1.2" || target.SSH.Port != "22" || len(target.SSH.FallbackPorts) != 0 || target.Server.ImmutableID != fixedTestGeneration || target.Server.Labels["tailscale_state"] != "ready" || !target.SSH.AuthoritativeNetwork || target.Server.Labels["tailscale_device_id"] != "nFixtureDevice" {
			t.Fatalf("incorrect target %+v", target)
		}
	}
	if first.Server.Labels["tailscale_tags"] != "tag:worker" {
		t.Fatal("native tags passed through cloud label sanitizer")
	}
	if client.fixedCreates != 1 || client.nextCalls != 1 {
		t.Fatal("replay reallocated")
	}
	before := backend.Cfg
	for _, change := range []func(*core.Config){func(c *core.Config) { c.Tailscale.Enabled = false }, func(c *core.Config) { c.Tailscale.Tags = []string{"tag:other"} }, func(c *core.Config) { c.Tailscale.HostnameTemplate = "other-{id}" }, func(c *core.Config) { c.Proxmox.TailscaleBroker += "-other" }} {
		backend.Cfg = before
		change(&backend.Cfg)
		if _, err := backend.Acquire(t.Context(), req); err == nil || !strings.Contains(err.Error(), "lease_id_conflict") {
			t.Fatalf("intent downgrade err=%v", err)
		}
	}
	backend.Cfg = before
	original := client.servers[0]
	for _, change := range []func(*core.Server){
		func(s *core.Server) { s.ImmutableID = replacementGeneration },
		func(s *core.Server) { s.Labels = maps.Clone(s.Labels); delete(s.Labels, "tailscale") },
	} {
		client.servers[0] = original
		change(&client.servers[0])
		if _, err := backend.Resolve(t.Context(), core.ResolveRequest{ID: req.RequestedLeaseID}); err == nil {
			t.Fatal("mutable server bypassed fixed routing/generation binding")
		}
	}
	client.servers[0] = original
	client.servers[0].PublicNet.IPv4.IP = "10.77.1.32"
	if _, err := backend.Resolve(t.Context(), core.ResolveRequest{ID: req.RequestedLeaseID}); err == nil {
		t.Fatal("resolved underlay fallback")
	}
	if _, err := backend.Resolve(t.Context(), core.ResolveRequest{ID: req.RequestedLeaseID, ReleaseOnly: true}); err != nil {
		t.Fatal("cleanup incorrectly requires tailnet", err)
	}
}

func TestProxmoxTailnetAdmissionPrecedesAllocation(t *testing.T) {
	backend, client, req := tailnetFixedFixture(t)
	req.RequestedLeaseID = ""
	if _, err := backend.Acquire(t.Context(), req); err == nil {
		t.Fatal("non-fixed provisioning admitted")
	}
	if client.fixedCreates != 0 || client.nextCalls != 0 {
		t.Fatal("allocated before admission")
	}
}

func TestProxmoxTailnetCancellationAndCleanupRetainOwnership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable fixture")
	}
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "cancelled"}[cancelled], func(t *testing.T) {
			backend, client, req := tailnetFixedFixture(t)
			client.cancelAfterBind = cancelled
			target, err := backend.Acquire(t.Context(), req)
			if cancelled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err=%v", err)
				}
				target = core.LeaseTarget{LeaseID: req.RequestedLeaseID}
			} else if err != nil {
				t.Fatal(err)
			}
			claim := readFixedProxmoxClaim(t, req.RequestedLeaseID)
			if claim.CloudImmutableID != fixedTestGeneration {
				t.Fatal("generation lost on cancellation")
			}
			if cancelled {
				if _, err := backend.Acquire(t.Context(), req); err == nil {
					t.Fatal("uncertain attempt replayed")
				}
				if client.fixedCreates != 1 {
					t.Fatal("cancellation cloned again")
				}
			}
			// VM deletion succeeds, but broker failure must retain the deleting claim.
			broker := backend.Cfg.Proxmox.TailscaleBroker
			if err := os.WriteFile(broker, []byte("#!/bin/sh\nprintf 'private broker diagnostic' >&2\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := backend.ReleaseLease(t.Context(), core.ReleaseLeaseRequest{Lease: target}); err == nil {
				t.Fatal("terminal without broker cleanup")
			}
			retained := readFixedProxmoxClaim(t, req.RequestedLeaseID)
			if retained.FixedCreateIntent.State == "released" || retained.CloudImmutableID != fixedTestGeneration {
				t.Fatal("cleanup owner discarded")
			}
			if len(client.servers) != 0 {
				t.Fatal("VM deletion not performed before broker settlement")
			}
			requestPath := filepath.Join(t.TempDir(), "request")
			script := "#!/bin/sh\ncat >'" + requestPath + "'\nprintf '{\"released\":true}'\n"
			if err := os.WriteFile(broker, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			if err := backend.ReleaseLease(t.Context(), core.ReleaseLeaseRequest{Lease: target}); err != nil {
				t.Fatal(err)
			}
			terminal := readFixedProxmoxClaim(t, req.RequestedLeaseID)
			if terminal.FixedCreateIntent.State != "released" {
				t.Fatal("cleanup not terminal")
			}
			data, err := os.ReadFile(requestPath)
			if err != nil {
				t.Fatal(err)
			}
			var request struct{ Operation, LeaseID, VMID, Generation string }
			if json.Unmarshal(data, &request) != nil || request.Operation != "release" || request.LeaseID != req.RequestedLeaseID || request.VMID != "417" || request.Generation != fixedTestGeneration {
				t.Fatalf("cleanup identity %s", data)
			}
			if client.fixedCreates != 1 {
				t.Fatal("cleanup allocated")
			}
			backend.RT.Stderr = io.Discard
		})
	}
}

func TestProxmoxTailnetMetadataRefreshRejectsIdentityDrift(t *testing.T) {
	backend, client, req := tailnetFixedFixture(t)
	first, err := backend.Acquire(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	meta := core.TailscaleMetadata{Enabled: true, State: "ready", IPv4: "100.100.1.2", DeviceID: "nFixtureDevice"}
	// Fresh remote descriptions do not contain trusted device metadata.
	client.servers[0].Labels = maps.Clone(client.servers[0].Labels)
	client.servers[0].Labels["tailscale_device_id"] = "forged-label-device"
	client.servers[0].Labels["tailscale_fqdn"] = "10.77.1.32"
	live, err := backend.UpdateTailscaleMetadata(t.Context(), first, meta)
	if err != nil || live.Labels["tailscale_device_id"] != meta.DeviceID || live.Labels["tailscale_fqdn"] != "" {
		t.Fatalf("live=%+v err=%v", live, err)
	}
	original := client.servers[0]
	for _, change := range []func(*core.TailscaleMetadata, *core.Server){
		func(m *core.TailscaleMetadata, _ *core.Server) { m.DeviceID = "" },
		func(m *core.TailscaleMetadata, _ *core.Server) { m.DeviceID = "nReplacement" },
		func(m *core.TailscaleMetadata, _ *core.Server) { m.IPv4 = "10.77.1.32" },
		func(_ *core.TailscaleMetadata, s *core.Server) { s.ImmutableID = replacementGeneration },
		func(_ *core.TailscaleMetadata, s *core.Server) {
			s.Labels = maps.Clone(s.Labels)
			s.Labels["lease"] = "cbx_abcdef123456"
		},
	} {
		candidate := meta
		client.servers[0] = original
		change(&candidate, &client.servers[0])
		if _, err := backend.UpdateTailscaleMetadata(t.Context(), first, candidate); err == nil {
			t.Fatal("metadata drift accepted")
		}
		claim := readFixedProxmoxClaim(t, req.RequestedLeaseID)
		if claim.Labels["tailscale_device_id"] != meta.DeviceID || claim.CloudImmutableID != fixedTestGeneration {
			t.Fatal("drift rewrote binding")
		}
	}
	client.servers[0] = original
	// A guest that rejoins with another device ID cannot be adopted on replay.
	readTailnetMetadata = func(context.Context, core.SSHTarget) (core.TailscaleMetadata, error) {
		bad := meta
		bad.DeviceID = "nReplacement"
		return bad, nil
	}
	if _, err := backend.Acquire(t.Context(), req); err == nil {
		t.Fatal("device replacement adopted on replay")
	}
	if client.fixedCreates != 1 {
		t.Fatal("drift reissued enrollment")
	}
}

const tailnetWarmupLease = "cbx_123456abcdef"

var tailnetWarmupArgs = []string{"warmup", "--provider", "proxmox", "--keep=true", "--lease-id", tailnetWarmupLease, "--slug", "fixed-proxmox", "--tailscale", "--network", "tailscale", "--tailscale-tags", "tag:worker", "--tailscale-hostname-template", "cbx-{id}"}

type tailnetReopenFixture struct {
	Server     core.Server
	Generation string
	Dirs       map[string]string
}

func TestProxmoxTailnetWarmupFreshProcessInspectReplay(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX SSH fixture")
	}
	if encoded := os.Getenv("CRABBOX_TEST_TAILNET_REOPEN"); encoded != "" {
		waitForSSHReadyFunc = func(_ context.Context, target *core.SSHTarget, _ io.Writer, _ string, _ time.Duration) error {
			target.SSHConfigProxy = true
			return nil
		}
		var fixture tailnetReopenFixture
		if err := json.Unmarshal([]byte(encoded), &fixture); err != nil {
			t.Fatal(err)
		}
		for key, value := range fixture.Dirs {
			t.Setenv(key, value)
		}
		fixture.Server.ImmutableID = fixture.Generation
		// A fresh API read is reconstructed without an in-memory receipt. A forged
		// mutable label must never become the device reported to the owner.
		fixture.Server.Labels["tailscale_device_id"] = "forged-label-device"
		fixture.Server.Labels["tailscale_fqdn"] = "10.77.1.32"
		client := &tailnetFixedClient{fixedProxmoxClient: &fixedProxmoxClient{fakeProxmoxDoctorClient: &fakeProxmoxDoctorClient{servers: []core.Server{fixture.Server}}, nextVMID: 417}}
		newClient = func(core.Config) (proxmoxClient, error) { return client, nil }
		readTailnetMetadata = core.ReadRemoteTailscaleMetadata
		out, err := runControllerTestCommand(t, "inspect", "--provider", "proxmox", "--id", tailnetWarmupLease, "--json")
		if err != nil {
			t.Fatalf("fresh inspect: %v %s", err, out)
		}
		var view core.StatusView
		if err := json.Unmarshal([]byte(out), &view); err != nil {
			t.Fatalf("inspect JSON: %v %s", err, out)
		}
		if view.Tailscale == nil || view.Tailscale.DeviceID != "nFixtureDevice" || view.SSHHost != "100.100.1.2" || view.Network != core.NetworkTailscale {
			t.Fatalf("fresh inspect lost identity: %+v", view)
		}
		if out, err := runControllerTestCommand(t, tailnetWarmupArgs...); err != nil {
			t.Fatalf("fresh replay: %v %s", err, out)
		}
		if client.fixedCreates != 0 || client.nextCalls != 0 {
			t.Fatal("fresh replay allocated or issued again")
		}
		return
	}
	_, client, _ := tailnetFixedFixture(t)
	waitForSSHReadyFunc = func(_ context.Context, target *core.SSHTarget, _ io.Writer, _ string, _ time.Duration) error {
		target.SSHConfigProxy = true
		return nil
	}
	cfg := controllerTestConfig()
	setControllerTestEnv(t, cfg)
	broker := filepath.Join(t.TempDir(), "broker-must-not-be-called-on-replay")
	t.Setenv("CRABBOX_PROXMOX_TAILSCALE_BROKER", broker)
	dir := t.TempDir()
	capture := filepath.Join(dir, "ssh-calls")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + capture + "'\ncase \"$*\" in\n*'for field in ipv4 hostname'*) printf '100.100.1.2\\000cbx-fixture\\000\\000\\000\\000\\000nFixtureDevice\\000';;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	readTailnetMetadata = core.ReadRemoteTailscaleMetadata
	if out, err := runControllerTestCommand(t, tailnetWarmupArgs...); err != nil {
		t.Fatalf("warmup: %v %s", err, out)
	}
	claim := readFixedProxmoxClaim(t, tailnetWarmupLease)
	if claim.Labels["tailscale_device_id"] != "nFixtureDevice" || claim.CloudImmutableID != fixedTestGeneration {
		t.Fatal("warmup lost generation-bound device")
	}
	if client.fixedCreates != 1 {
		t.Fatal("warmup allocation count")
	}
	fixture := tailnetReopenFixture{Server: client.servers[0], Generation: fixedTestGeneration, Dirs: map[string]string{}}
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "APPDATA", "LOCALAPPDATA", "USERPROFILE"} {
		fixture.Dirs[key] = os.Getenv(key)
	}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProxmoxTailnetWarmupFreshProcessInspectReplay$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CRABBOX_TEST_TAILNET_REOPEN="+string(data))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh process: %v %s", err, out)
	}
	calls, _ := os.ReadFile(capture)
	if strings.Contains(string(calls), "10.77.1.32") {
		t.Fatalf("LAN fallback: %s", calls)
	}
}

// Keep native fixed-claim validation wired to the actual common warmup caller.
// The provider's acquisition receipt is valid; the subsequent common SSH read
// must not downgrade an identity rejection to a warning and report ready.
func TestProxmoxTailnetWarmupPropagatesRequiredReceiptFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX SSH fixture")
	}
	_, client, _ := tailnetFixedFixture(t)
	waitForSSHReadyFunc = func(_ context.Context, target *core.SSHTarget, _ io.Writer, _ string, _ time.Duration) error {
		target.SSHConfigProxy = true
		return nil
	}
	setControllerTestEnv(t, controllerTestConfig())
	t.Setenv("CRABBOX_PROXMOX_TAILSCALE_BROKER", filepath.Join(t.TempDir(), "must-not-issue"))
	dir := t.TempDir()
	receipt := filepath.Join(dir, "receipt")
	script := "#!/bin/sh\ncase \"$*\" in\n*'for field in ipv4 hostname'*) cat '" + receipt + "'; exit $?;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	writeReceipt := func(ip, device string) {
		t.Helper()
		data := strings.Join([]string{ip, "cbx-fixture", "", "", "", "", device, ""}, "\x00")
		if err := os.WriteFile(receipt, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeReceipt("100.100.1.2", "nFixtureDevice")
	if out, err := runControllerTestCommand(t, tailnetWarmupArgs...); err != nil {
		t.Fatalf("initial warmup: %v %s", err, out)
	}
	for _, failure := range []string{"changed device", "missing device", "wrong address", "malformed", "unreadable"} {
		t.Run(failure, func(t *testing.T) {
			switch failure {
			case "changed device":
				writeReceipt("100.100.1.2", "nReplacement")
			case "missing device":
				writeReceipt("100.100.1.2", "")
			case "wrong address":
				writeReceipt("100.100.1.3", "nFixtureDevice")
			case "malformed":
				if err := os.WriteFile(receipt, []byte("bad framing"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				if err := os.Remove(receipt); err != nil {
					t.Fatal(err)
				}
			}
			out, err := runControllerTestCommand(t, tailnetWarmupArgs...)
			if err == nil || !strings.Contains(err.Error(), "required tailscale receipt") || strings.Contains(out, "ready ssh=") {
				t.Fatalf("common native warmup failed open: %v %s", err, out)
			}
			claim := readFixedProxmoxClaim(t, tailnetWarmupLease)
			if claim.Labels["tailscale_device_id"] != "nFixtureDevice" || claim.CloudImmutableID != fixedTestGeneration || claim.FixedCreateIntent.State != "acquired" {
				t.Fatalf("receipt failure changed owned binding: %+v", claim)
			}
			if client.fixedCreates != 1 || client.nextCalls != 1 {
				t.Fatal("receipt failure allocated or reissued")
			}
		})
	}
}
