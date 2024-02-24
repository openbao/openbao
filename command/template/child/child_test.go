// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package child

import (
	"bytes"
	"io"
	"log"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/consul-template/signals"
	"github.com/hashicorp/go-hclog"

	"github.com/hashicorp/go-gatedio"
	"golang.org/x/sys/unix"
)

const fileWaitSleepDelay = 50 * time.Millisecond

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func testChild(t *testing.T) *Child {
	c, err := New(&NewInput{
		Stdout:       io.Discard,
		Stderr:       io.Discard,
		Command:      "echo",
		Args:         []string{"hello", "world"},
		ReloadSignal: os.Interrupt,
		KillSignal:   os.Kill,
		KillTimeout:  2 * time.Second,
		Splay:        0 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNew(t *testing.T) {
	stdin := gatedio.NewByteBuffer()
	stdout := gatedio.NewByteBuffer()
	stderr := gatedio.NewByteBuffer()
	command := "echo"
	args := []string{"hello", "world"}
	env := []string{"a=b", "c=d"}
	reloadSignal := os.Interrupt
	killSignal := os.Kill
	killTimeout := fileWaitSleepDelay
	splay := fileWaitSleepDelay

	c, err := New(&NewInput{
		Stdin:        stdin,
		Stdout:       stdout,
		Stderr:       stderr,
		Command:      command,
		Args:         args,
		Env:          env,
		ReloadSignal: reloadSignal,
		KillSignal:   killSignal,
		KillTimeout:  killTimeout,
		Splay:        splay,
	})
	if err != nil {
		t.Fatal(err)
	}

	if c.stdin != stdin {
		t.Errorf("expected %q to be %q", c.stdin, stdin)
	}

	if c.stdout != stdout {
		t.Errorf("expected %q to be %q", c.stdout, stdout)
	}

	if c.stderr != stderr {
		t.Errorf("expected %q to be %q", c.stderr, stderr)
	}

	if c.command != command {
		t.Errorf("expected %q to be %q", c.command, command)
	}

	if !reflect.DeepEqual(c.args, args) {
		t.Errorf("expected %q to be %q", c.args, args)
	}

	if !reflect.DeepEqual(c.env, env) {
		t.Errorf("expected %q to be %q", c.env, env)
	}

	if c.reloadSignal != reloadSignal {
		t.Errorf("expected %q to be %q", c.reloadSignal, reloadSignal)
	}

	if c.killSignal != killSignal {
		t.Errorf("expected %q to be %q", c.killSignal, killSignal)
	}

	if c.killTimeout != killTimeout {
		t.Errorf("expected %q to be %q", c.killTimeout, killTimeout)
	}

	if c.splay != splay {
		t.Errorf("expected %q to be %q", c.splay, splay)
	}

	if c.stopCh == nil {
		t.Errorf("expected %#v to be", c.stopCh)
	}
}

func TestNew_errMissingCommand(t *testing.T) {
	_, err := New(nil)
	if err == nil {
		t.Fatal("expected error")
	}

	if err != ErrMissingCommand {
		t.Errorf("expected %q to be %q", err, ErrMissingCommand)
	}
}

func TestExitCh_noProcess(t *testing.T) {
	c := testChild(t)
	ch := c.ExitCh()
	if ch != nil {
		t.Errorf("expected %#v to be nil", ch)
	}
}

func TestExitCh(t *testing.T) {
	c := testChild(t)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	ch := c.ExitCh()
	if ch == nil {
		t.Error("expected ch to exist")
	}
}

func TestPid_noProcess(t *testing.T) {
	c := testChild(t)
	pid := c.Pid()
	if pid != 0 {
		t.Errorf("expected %q to be 0", pid)
	}
}

func TestPid(t *testing.T) {
	c := testChild(t)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	pid := c.Pid()
	if pid == 0 {
		t.Error("expected pid to not be 0")
	}
}

func TestStart(t *testing.T) {
	c := testChild(t)

	// Set our own reader and writer so we can verify they are wired to the child.
	stdin := gatedio.NewByteBuffer()
	stdout := gatedio.NewByteBuffer()
	stderr := gatedio.NewByteBuffer()
	c.stdin = stdin
	c.stdout = stdout
	c.stderr = stderr

	// Custom env and command
	c.env = []string{"a=b", "c=d"}
	c.command = "env"
	c.args = nil

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	select {
	case <-c.ExitCh():
	case <-time.After(fileWaitSleepDelay):
		t.Fatal("process should have exited")
	}

	expected := "a=b\nc=d\n"
	if stdout.String() != expected {
		t.Errorf("expected %q to be %q", stdout.String(), expected)
	}
}

func TestSignal(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "trap 'echo one; exit' USR1; while true; do sleep 0.2; done"}

	out := gatedio.NewByteBuffer()
	c.stdout = out

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	if err := c.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	expected := "one\n"
	if out.String() != expected {
		t.Errorf("expected %q to be %q", out.String(), expected)
	}
}

func TestSignal_noProcess(t *testing.T) {
	c := testChild(t)
	if err := c.Signal(syscall.SIGUSR1); err != nil {
		// Just assert there is no error
		t.Fatal(err)
	}
}

func TestReload_signal(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "trap 'echo one; exit' USR1; while true; do sleep 0.2; done"}
	c.reloadSignal = syscall.SIGUSR1

	out := gatedio.NewByteBuffer()
	c.stdout = out

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	expected := "one\n"
	if out.String() != expected {
		t.Errorf("expected %q to be %q", out.String(), expected)
	}
}

func TestReload_nilSignal(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "while true; do sleep 0.2; done"}
	c.killTimeout = 10 * time.Millisecond
	c.reloadSignal = signals.SIGNULL

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	// Grab the original pid
	opid := c.cmd.Process.Pid

	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	// Get the new pid
	npid := c.cmd.Process.Pid

	if opid != npid {
		t.Error("unexpected process restart")
	}
}

func TestReload_noSignal(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "while true; do sleep 0.2; done"}
	c.killTimeout = 10 * time.Millisecond
	c.reloadSignal = nil

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	// Grab the original pid
	opid := c.cmd.Process.Pid

	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	// Get the new pid
	npid := c.cmd.Process.Pid

	if opid == npid {
		t.Error("expected new process to restart")
	}
}

func TestReload_noProcess(t *testing.T) {
	c := testChild(t)
	c.reloadSignal = syscall.SIGUSR1
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
}

func TestKill_signal(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "trap 'echo one; exit' USR1; while true; do sleep 0.2; done"}
	c.killSignal = syscall.SIGUSR1

	out := gatedio.NewByteBuffer()
	c.stdout = out

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	c.Kill()

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	expected := "one\n"
	if out.String() != expected {
		t.Errorf("expected %q to be %q", out.String(), expected)
	}
}

func TestKill_noSignal(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "while true; do sleep 0.2; done"}
	c.killTimeout = 20 * time.Millisecond
	c.killSignal = nil

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	c.Kill()

	// Give time for the file to flush
	time.Sleep(fileWaitSleepDelay)

	if c.cmd != nil {
		t.Errorf("expected cmd to be nil")
	}
}

func TestKill_noProcess(t *testing.T) {
	c := testChild(t)
	c.killSignal = syscall.SIGUSR1
	c.Kill()
}

func TestStop_noWaitForSplay(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "trap 'echo one; exit' USR1; while true; do sleep 0.2; done"}
	c.splay = 100 * time.Second
	c.reloadSignal = nil
	c.killSignal = syscall.SIGUSR1
	c.setpgid = true

	out := gatedio.NewByteBuffer()
	c.stdout = out

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	killStartTime := time.Now()
	c.StopImmediately()
	killEndTime := time.Now()

	expected := "one\n"
	if out.String() != expected {
		t.Errorf("expected %q to be %q", out.String(), expected)
	}

	if killEndTime.Sub(killStartTime) > fileWaitSleepDelay {
		t.Error("expected not to wait for splay")
	}
}

func TestStop_childAlreadyDead(t *testing.T) {
	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "exit 1"}
	c.splay = 100 * time.Second
	c.reloadSignal = nil
	c.killSignal = syscall.SIGTERM

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}

	// For some reason bash doesn't start immediately
	time.Sleep(fileWaitSleepDelay)

	killStartTime := time.Now()
	c.Stop()
	killEndTime := time.Now()

	if killEndTime.Sub(killStartTime) > fileWaitSleepDelay {
		t.Error("expected not to wait for splay")
	}
}

func TestSetpgid(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		c := testChild(t)
		c.command = "sh"
		c.args = []string{"-c", "while true; do sleep 0.2; done"}
		// default, but to be explicit for the test
		c.setsid = false
		c.setpgid = true

		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		defer c.Stop()

		// when setsid is false, the pid and gpid should be the same
		gpid, err := syscall.Getpgid(c.Pid())
		if err != nil {
			t.Fatal("Getpgid error:", err)
		}

		if c.Pid() != gpid {
			t.Fatal("pid and gpid should match")
		}
	})
	t.Run("false", func(t *testing.T) {
		c := testChild(t)
		c.command = "sh"
		c.args = []string{"-c", "while true; do sleep 0.2; done"}
		c.setsid = false
		c.setpgid = false

		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		defer c.Stop()

		// when setpgid is false, the pid and gpid should not be the same
		gpid, err := syscall.Getpgid(c.Pid())
		if err != nil {
			t.Fatal("Getpgid error:", err)
		}

		if c.Pid() == gpid {
			t.Fatal("pid and gpid should NOT match")
		}
	})
}

func TestSetsid(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		c := testChild(t)
		c.command = "sh"
		c.args = []string{"-c", "while true; do sleep 0.2; done"}
		c.setsid = true
		c.setpgid = false

		var err error

		if err = c.Start(); err != nil {
			t.Fatal(err)
		}
		defer c.Stop()

		var sid int = -1

		os := runtime.GOOS

		switch os {
		//  Using x/sys/unix for Unix systems
		case "linux", "darwin":
			sid, err = unix.Getsid(c.Pid())
			if err != nil {
				t.Fatal("Getsid error:", err)
			}
		// Stub for windows which isn't supported
		case "windows":
			sid = c.Pid()
		}

		// when setsid is true, the pid and sid should match
		if c.Pid() != sid {
			t.Fatal("pid and sid should match when setsid is true")
		}
	})
	t.Run("false", func(t *testing.T) {
		c := testChild(t)
		c.command = "sh"
		c.args = []string{"-c", "while true; do sleep 0.2; done"}
		c.setsid = false
		c.setpgid = false

		var err error

		if err = c.Start(); err != nil {
			t.Fatal(err)
		}
		defer c.Stop()

		var sid int

		os := runtime.GOOS

		switch os {
		//  Using x/sys/unix for Unix systems
		case "darwin":
		case "linux":
			sid, err = unix.Getsid(c.Pid())
			if err != nil {
				t.Fatal("Getsid error:", err)
			}
		// Stub for windows which isn't supported
		case "windows":
			sid = -1
		}

		// when setsid is false, the pid and sid should not match
		if c.Pid() == sid {
			t.Fatal("pid and sid should not match when setsid is false")
		}
	})
}

func TestLog(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "echo 1"}

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	expected := "[INFO] (child) spawning: sh -c echo 1\n"
	actual := buf.String()

	// trim off leading timestamp
	index := strings.Index(actual, "[")
	actual = actual[index:]
	if actual != expected {
		t.Fatalf("Expected '%s' to be '%s'", actual, expected)
	}
}

func TestCustomLogger(t *testing.T) {
	var buf bytes.Buffer

	c := testChild(t)
	c.command = "sh"
	c.args = []string{"-c", "echo 1"}
	c.logger = hclog.New(&hclog.LoggerOptions{
		Output: &buf,
	}).With("child-name", "echo").StandardLogger(&hclog.StandardLoggerOptions{
		InferLevels: true,
		ForceLevel:  0,
	})

	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	expected := " [INFO]  (child) spawning: sh -c echo 1: child-name=echo\n"
	actual := buf.String()

	// trim off leading timestamp
	index := strings.Index(actual, " ")
	actual = actual[index:]
	if actual != expected {
		t.Fatalf("Expected '%s' to be '%s'", actual, expected)
	}
}
