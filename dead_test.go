package ptrace
import "syscall"
import "testing"

func TestDiedThenStep(t *testing.T) {
  tracee, err := Exec("/bin/true", []string{"/bin/true"})
  if err != nil {
    t.Fatalf("could not start process: %v\n", err)
    t.FailNow()
  }
  if err := tracee.Continue() ; err != nil {
    t.Fatalf("continuing failed: %v\n", err)
    t.FailNow()
  }
  stat := <- tracee.Events()
  if stat.(syscall.WaitStatus).Exited() {
		/* This *should* produce an error. */
    err := tracee.SingleStep()
    if err == nil {
      t.Fatalf("single stepping post-exit did not produce error!")
    }
    return
  }
}
