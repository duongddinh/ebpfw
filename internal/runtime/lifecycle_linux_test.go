package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/duongddinh/ebpfw/internal/policy"
	"github.com/duongddinh/ebpfw/internal/testnet"
)

func TestKernelDaemonLifecycle(t *testing.T) {
	if os.Getenv("EBPFW_LIVE_TEST") != "1" {
		t.Skip("set EBPFW_LIVE_TEST=1 on a disposable Linux host")
	}
	pair, err := testnet.New()
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()
	config := filepath.Join(t.TempDir(), "rules.json")
	if err = policy.Edit(config, func(c *policy.Config) error {
		c.Rules = []policy.Rule{{Action: "allow", Protocol: "udp", Port: "53"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", config, "run", "--interface", pair.Right.Name, "--mode", "generic", "--object", os.Getenv("EBPFW_OBJECT")}
	cmd := exec.Command(os.Getenv("EBPFW_BINARY"), args...)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	read := func() metric {
		var out bytes.Buffer
		var m metric
		if Stats(pair.Right.Name, &out) == nil {
			json.Unmarshal(out.Bytes(), &m)
		}
		return m
	}
	wait := func(check func() bool) {
		t.Helper()
		end := time.Now().Add(8 * time.Second)
		for time.Now().Before(end) {
			if check() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("timed out waiting for daemon state")
	}
	wait(func() bool { return read().Rules == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = exec.CommandContext(ctx, os.Getenv("EBPFW_BINARY"), args...).Run(); err == nil || ctx.Err() != nil {
		t.Fatal("second instance did not safely refuse ownership")
	}
	before := read()
	pair.Send(pair.Packet(53))
	pair.Send(pair.Packet(54))
	wait(func() bool { m := read(); return m.Passed > before.Passed && m.Denied > before.Denied })
	valid, _ := os.ReadFile(config)
	os.WriteFile(config, []byte(`{"version":999}`), 0600)
	wait(func() bool { return read().ReloadError != "" })
	before = read()
	pair.Send(pair.Packet(54))
	wait(func() bool { return read().Denied > before.Denied })
	os.WriteFile(config, valid, 0600)
	if err = policy.Edit(config, func(c *policy.Config) error {
		c.Rules = append(c.Rules, policy.Rule{Action: "allow", Protocol: "udp", Port: "54"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { m := read(); return m.Rules == 2 && m.ReloadError == "" })
	before = read()
	pair.Send(pair.Packet(54))
	wait(func() bool { return read().Passed > before.Passed })
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err = <-done:
		waited = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop")
	}
	// Successfully starting again proves the old link was detached.
	again := exec.Command(os.Getenv("EBPFW_BINARY"), args...)
	again.Stdout = &logs
	again.Stderr = &logs
	if err = again.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { again.Process.Kill(); again.Wait() }()
	wait(func() bool { return read().Rules == 2 })
}
