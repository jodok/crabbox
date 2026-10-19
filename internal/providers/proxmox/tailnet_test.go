package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
		if target.SSH.Host != "100.100.1.2" || target.SSH.Port != "22" || len(target.SSH.FallbackPorts) != 0 || target.Server.ImmutableID != fixedTestGeneration || target.Server.Labels["tailscale_state"] != "ready" {
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
