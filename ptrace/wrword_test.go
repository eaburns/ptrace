package ptrace
import "testing"

func TestWritingWord(t *testing.T) {
	tracee, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
		t.FailNow()
	}
	// ugh.	0x00400000 is specific to linux/amd64.
	_, err = tracee.ReadWord(0x00400000)
	if err != nil {
		t.Fatalf("could not read first word of program image: %v\n", err)
	}
	err = tracee.WriteWord(0x00400000, 0xCCccCCccCCccCCcc)
	if err != nil { t.Fatalf("%v\n", err) }
}
