// The ptrace package provides an interface to the Linux ptrace system call.
package ptrace

import (
	"os"
	"runtime"
	"syscall"
)

// BUG(eaburns): Add different events.
type Event struct{}

// A Tracee is a process that is being traced.
type Tracee struct {
	// Events is sent each event coming from the traced process.
	Events <-chan Event

	// Error is a channel of any out-of-band errors by the tracee.  If an error is sent on Errors, the trace terminates and the tracee should no longer be used.
	Error <-chan error

	pid int
	// Cmds is used to send ptrace commands to the Go routine residing on the thread that is tracing the tracee.
	cmds chan<- func()
}

// Pid returns the pid of the tracee.
func (t *Tracee) Pid() int {
	return t.pid
}

// Exec executes a process with tracing enabled, returning the Tracee or an error if an error occurs while executing the process.
func Exec(name string, argv []string) (*Tracee, error) {
	sys := &syscall.SysProcAttr{
		Ptrace: true,
		Pdeathsig:  syscall.SIGCHLD,
	}
	files := []*os.File{os.Stdin, os.Stdout, os.Stderr}
	attrs := &os.ProcAttr{ Files: files, Sys: sys }

	pid := make(chan int)
	err := make(chan error)
	events := make(chan Event, 1)
	errs := make(chan error)
	cmds := make(chan func())
	t := &Tracee{
		Events: events,
		Error: errs,
		cmds: cmds,
	}

	go func() {
		runtime.LockOSThread()

		proc, e := os.StartProcess(name, argv, attrs)
		pid <- proc.Pid
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
				var status syscall.WaitStatus
				_, err := syscall.Wait4(proc.Pid, &status, 0, nil)
				if err != nil {
					errs <- err
					t.stop()
					return
				}
				if !status.Stopped() {
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
	t.pid = <-pid
	return t, <-err
}

// Detach detaches the tracee, allowing the traced process to continue normally.  No more tracing is performed, and the events channel is closed.
func (t *Tracee) Detach() error {
	err := make(chan error)
	t.cmds <- func() {
		err <- syscall.PtraceDetach(t.pid)
	}
	return <-err
}

// SingleStep continues the tracee for one instruction.
func (t *Tracee) SingleStep() error {
	err := make(chan error)
	t.cmds <- func() {
		e := syscall.PtraceSingleStep(t.pid)
		if e != nil {
			t.stop()
		}
		err <- e
	}
	return <- err
}

func (t *Tracee) stop() {
	cmds := t.cmds
	t.cmds = nil
	close(cmds)
}