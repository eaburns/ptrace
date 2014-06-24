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
  tracee.SendSignal(syscall.SIGKILL)
}
