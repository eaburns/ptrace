// Package ptrace provides an interface to the ptrace system call.
package ptrace

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

var (
	// TraceeExited is returned when a command is executed on a tracee
	// that has already exited.
	TraceeExited = errors.New("tracee exited")
)

// An Event is sent on a Tracee's event channel whenever it changes state.
type Event interface{}

// A Tracee is a process that is being traced.
type Tracee struct {
	proc   *os.Process
	events chan Event
	err    chan error

	cmds chan func()
}

// Events returns the events channel for the tracee.
func (t *Tracee) Events() <-chan Event {
	return t.events
}

// Exec executes a process with tracing enabled, returning the Tracee
// or an error if an error occurs while executing the process.
func Exec(name string, argv []string) (*Tracee, error) {
	t := &Tracee{
		events: make(chan Event, 1),
		err:    make(chan error, 1),
		cmds:   make(chan func()),
	}

	err := make(chan error)
	proc := make(chan *os.Process)
	go func() {
		runtime.LockOSThread()
		p, e := os.StartProcess(name, argv, &os.ProcAttr{
			Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
			Sys: &syscall.SysProcAttr{
				Ptrace:    true,
				Pdeathsig: syscall.SIGCHLD,
			},
		})
		proc <- p
		err <- e
		if e != nil {
			return
		}
		go t.wait()
		t.trace()
	}()
	t.proc = <-proc
	return t, <-err
}

// Detach detaches the tracee, allowing it to continue its execution normally.
// No more tracing is performed, and no events are sent on the event channel
// until the tracee exits.
func (t *Tracee) Detach() error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.PtraceDetach(t.proc.Pid) }) {
		return <-err
	}
	return TraceeExited
}

// SingleStep continues the tracee for one instruction.
func (t *Tracee) SingleStep() error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.PtraceSingleStep(t.proc.Pid) }) {
		return <-err
	}
	return TraceeExited
}

// Continue makes the tracee execute unmanaged by the tracer.  Most
// commands are not possible in this state, with the notable exception
// of sending a syscall.SIGSTOP signal.
func (t *Tracee) Continue() error {
	err := make(chan error, 1)
	const signum = 0
	if t.do(func() { err <- syscall.PtraceCont(t.proc.Pid, signum) }) {
		return <-err
	}
	return TraceeExited
}

// SendSignal sends the given signal to the tracee.
func (t *Tracee) SendSignal(sig syscall.Signal) error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.Kill(t.proc.Pid, sig) }) {
		return <-err
	}
	return TraceeExited
}

// Sends the command to the tracer go routine.  Returns whether the command
// was sent or not.  The command may not have been sent if the tracee exited.
func (t *Tracee) do(f func()) bool {
	if t.cmds != nil {
		t.cmds <- f
		return true
	}
	return false
}

// Close cleans up internal memory for managing the tracee.  If an error is
// pending, it is returned.
func (t *Tracee) Close() error {
	var err error
	select {
	case err = <-t.err:
	default:
		err = nil
	}
	close(t.err)
	close(t.cmds)
	t.cmds = nil
	return err
}

func (t *Tracee) wait() {
	defer close(t.events)
	for {
		state, err := t.proc.Wait()
		if err != nil {
			t.err <- err
			return
		}
		if state.Exited() {
			t.events <- Event(state.Sys().(syscall.WaitStatus))
			return
		}
		t.events <- Event(state.Sys().(syscall.WaitStatus))
	}
}

func (t *Tracee) trace() {
	for cmd := range t.cmds {
		cmd()
	}
}
