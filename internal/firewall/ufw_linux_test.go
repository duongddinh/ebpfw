package firewall

import (
	"os"
	"os/exec"
	"testing"
)

func TestUFWAvailable(t *testing.T) {
	if os.Getenv("EBPFW_UFW_TEST") != "1" {
		t.Skip("official Debian guest files required")
	}
	for _, args := range [][]string{{"--version"}, {"status", "verbose"}} {
		out, e := exec.Command("ufw", args...).CombinedOutput()
		if e != nil {
			t.Fatalf("UFW %v: %v %s", args, e, out)
		}
		t.Log(string(out))
	}
	out, e := exec.Command("iptables", "--version").CombinedOutput()
	if e != nil {
		t.Fatal(e, string(out))
	}
	t.Log(string(out))
}
