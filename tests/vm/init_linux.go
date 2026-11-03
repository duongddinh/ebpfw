// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

func main() {
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	os.Chmod("/", 0755)
	if os.Getpid() != 1 {
		panic("VM init may run only as PID 1 in a disposable guest")
	}
	for _, m := range []struct{ dir, fs string }{{"/proc", "proc"}, {"/sys", "sysfs"}, {"/dev", "devtmpfs"}, {"/sys/fs/bpf", "bpf"}} {
		os.MkdirAll(m.dir, 0755)
		if e := syscall.Mount(m.fs, m.dir, m.fs, 0, ""); e != nil {
			panic(e)
		}
	}
	modules, e := os.ReadFile("/modules.list")
	if e != nil {
		panic(e)
	}
	for _, name := range strings.Fields(string(modules)) {
		b, e := os.ReadFile("/" + name)
		if e != nil {
			panic(e)
		}
		empty := []byte{0}
		_, _, code := syscall.Syscall(syscall.SYS_INIT_MODULE, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&empty[0])))
		if code != 0 {
			panic(fmt.Sprintf("load %s: %s", name, code))
		}
	}
	cmd := exec.Command("/full.test", "-test.v", "-test.timeout=20m")
	cmd.Env = []string{"EBPFW_FULL_TEST=1", "EBPFW_OBJECT=/stateful.o", "EBPFW_BINARY=/ebpfw", "HOME=/tmp", "TMPDIR=/tmp", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if _, e := os.Stat("/ufw-test-enabled"); e == nil {
		cmd.Env = append(cmd.Env, "EBPFW_UFW_TEST=1")
	}
	if _, e := os.Stat("/ufw-benchmark-enabled"); e == nil {
		cmd.Env = append(cmd.Env, "EBPFW_UFW_BENCH=1")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	e = cmd.Run()
	if e == nil {
		fmt.Println("EBPFW_FULL_VM_PASS")
	} else {
		fmt.Println("EBPFW_FULL_VM_FAIL:", e)
	}
	syscall.Sync()
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	select {}
}
