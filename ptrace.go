// Package ptrace provides an interface to the Linux ptrace system call.
package ptrace

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"syscall"
)

var (
	// TraceeExited is returned when a command is executed on a tracee
	// that has already exited.
	TraceeExited = errors.New("tracee exited")
)

// An Event is sent on a Tracee's event channel whenever it is stopped.
//
// BUG(eaburns): For now, an event is the wait status, but that's Unix
// specific.  We should find something better and more general.  This
// should be an interface.
type Event syscall.WaitStatus

// A Tracee is a process that is being traced.
type Tracee struct {
	proc   *os.Process
	events chan Event
	err    chan error

	cmds chan func()
	// CmdsLock synchronizes sends to the commands channel with the
	// closing of the channel.
	cmdsLock sync.RWMutex
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

// Sends the command to the tracer go routine.  Returns whether the command
// was sent or not.  The command may not have been sent if the tracee exited.
func (t *Tracee) do(f func()) bool {
	t.cmdsLock.RLock()
	defer t.cmdsLock.RUnlock()
	if t.cmds != nil {
		t.cmds <- f
		return true
	}
	return false
}

func (t *Tracee) wait() {
	defer func() {
		close(t.events)
		close(t.err)
		t.cmdsLock.Lock()
		close(t.cmds)
		t.cmds = nil
		t.cmdsLock.Unlock()
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
		t.events <- Event(state.Sys().(syscall.WaitStatus))
	}
}

func (t *Tracee) trace() {
	for cmd := range t.cmds {
		cmd()
	}
}
