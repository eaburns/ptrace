// The ptrace package provides an interface to the Linux ptrace system call.
package ptrace

import (
	"os"
	"runtime"
	"syscall"
)

// BUG(eaburns): Add different events.
type Event struct {
}

// A Tracee is a process that is being traced.
type Tracee struct {
	proc   *os.Process
	events chan Event
	err    chan error
	cmds   chan func()
}

// Events returns the events channel for the tracee.
func (t *Tracee) Events() <-chan Event {
	return t.events
}

// Error returns an error if one occurred, or nil.  It is to be called once
// after all events have been received from the Tracee.
func (t *Tracee) Error() error {
	return <-t.err
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

// Detach detaches the tracee, allowing the traced process to continue
// normally.  No more tracing is performed, and the events channel is
// closed.
func (t *Tracee) Detach() error {
	err := make(chan error, 1)
	t.cmds <- func() { err <- syscall.PtraceDetach(t.proc.Pid) }
	return <-err
}

// SingleStep continues the tracee for one instruction.
func (t *Tracee) SingleStep() error {
	err := make(chan error, 1)
	t.cmds <- func() { err <- syscall.PtraceSingleStep(t.proc.Pid) }
	return <-err
}

func (t *Tracee) wait() {
	defer func() {
		close(t.events)
		close(t.err)
		close(t.cmds)
	}()
	for {
		state, err := t.proc.Wait()
		if err != nil {
			t.err <- err
			return
		}
		if state.Exited() {
			return
		}
		t.events <- struct{}{}
	}
}

func (t *Tracee) trace() {
	for cmd := range t.cmds {
		cmd()
	}
}
