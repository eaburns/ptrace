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
	// Events is sent each event coming from the traced process.
	Events <-chan Event

	// Error is a channel of any out-of-band errors by the tracee.  If an error is sent on Errors, the trace terminates and the tracee should no longer be used.
	Error <-chan error

	// Proc is the process being traced.
	proc *os.Process

	// Cmds is used to send ptrace commands to the Go routine residing on the thread that is tracing the tracee.
	cmds chan<- func()
}

// Exec executes a process with tracing enabled, returning the Tracee or an error if an error occurs while executing the process.
func Exec(name string, argv []string) (*Tracee, error) {
	proc := make(chan *os.Process)
	err := make(chan error)
	events := make(chan Event, 1)
	errs := make(chan error)
	cmds := make(chan func())
	t := &Tracee{
		Events: events,
		Error:  errs,
		cmds:   cmds,
	}

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
		go func() {
			defer func() {
				close(events)
				close(errs)
			}()
			for {
				state, err := p.Wait()
				if err != nil {
					errs <- err
					t.stop()
					return
				}
				if state.Exited() {
					t.stop()
					return
				}
				events <- struct{}{}
			}
		}()
		for cmd := range cmds {
			cmd()
		}
	}()
	t.proc = <-proc
	return t, <-err
}

// Detach detaches the tracee, allowing the traced process to continue normally.  No more tracing is performed, and the events channel is closed.
func (t *Tracee) Detach() error {
	err := make(chan error)
	t.cmds <- func() {
		err <- syscall.PtraceDetach(t.proc.Pid)
	}
	return <-err
}

// SingleStep continues the tracee for one instruction.
func (t *Tracee) SingleStep() error {
	err := make(chan error)
	t.cmds <- func() {
		e := syscall.PtraceSingleStep(t.proc.Pid)
		if e != nil {
			t.stop()
		}
		err <- e
	}
	return <-err
}

func (t *Tracee) stop() {
	cmds := t.cmds
	t.cmds = nil
	close(cmds)
}
