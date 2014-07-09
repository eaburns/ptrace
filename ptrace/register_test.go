package ptrace
import "syscall"
import "testing"

func TestReadingInstructionPointer(t *testing.T) {
	tracee, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
		t.FailNow()
	}
	iptr, err := tracee.GetIPtr()
	if err != nil { t.Fatalf("iptr error: %v\n", err) }
	// 0x00400000 is linux/amd64's entry point.  it would be absurd if the iptr
	// was less than that, since it couldn't have gotten far (or even anywhere)
	// since it began.
	if iptr < 0x00400000 {
		t.Fatalf("instruction pointer is too small: 0x%x\n", iptr)
	}
	tracee.SendSignal(syscall.SIGKILL)
}

func TestSetInstructionPointer(t *testing.T) {
	tracee, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
		t.FailNow()
	}
	<- tracee.Events() // wait for tracee to start.
	err = tracee.SetIPtr(0x00400000)
	if err != nil { t.Fatalf("set iptr error: %v\n", err) }

	iptr, err := tracee.GetIPtr()
	if err != nil { t.Fatalf("get iptr error: %v\n", err) }

	if iptr != 0x00400000 {
		t.Fatalf("iptr set 0x%x instead of 0x00400000\n", iptr)
	}
	tracee.SendSignal(syscall.SIGKILL)
}

func TestGrabRegs(t *testing.T) {
	tracee, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
		t.FailNow()
	}
	<- tracee.Events() // wait for tracee to start.
	// run a few instructions, just so we get something of interest in the
	// registers.
	for i:=0; i < 1000; i++ {
		if err = tracee.SingleStep() ; err != nil {
			t.Fatalf("error stepping! %v\n", err)
		}
		<- tracee.Events() // eat the 'tracee stopped!' event we get.
	}

	registers, err := tracee.GetRegs()
	if err != nil { t.Fatalf("get registers error: %v\n", err) }
	if registers.Rip == 0x0 {
		t.Fatalf("instruction pointer is nonsense.\n")
	}

	tracee.SendSignal(syscall.SIGKILL)
}
