package ptrace
import "testing"

func TestReadingWord(t *testing.T) {
	tracee, err := Exec("/bin/true", []string{"/bin/true"})
	if err != nil {
		t.Fatalf("could not start process: %v\n", err)
		t.FailNow()
	}
	// ugh.	0x00400000 is specific to linux/amd64.
	wd, err := tracee.ReadWord(0x00400000)
	
	if err != nil {
		t.Fatalf("could not read first word of program image: %v\n", err)
	}
	// The first word of the binary image should be the file's magic.
	magic := 0x00000000FFFFFFFF & wd
	// .. and since we're assuming linux, that magic is {0x7f,'E','L','F'}
	if magic != 0x464c457f {
		t.Fatalf("magic does not match! 0x%x\n", magic)
	}
}
