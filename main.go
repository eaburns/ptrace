// +build ignore

package main

import (
	"log"
	"runtime"

	"github.com/davecheney/profile"
	"github.com/eaburns/ptrace"
)

func main() {
	defer profile.Start(profile.CPUProfile).Stop()
	runtime.GOMAXPROCS(4)

	tracee, err := ptrace.Exec("/bin/true", []string{})
	if err != nil {
		log.Fatal(err)
	}
	var n uint64
loop:
	for {
		select {
		case err, ok := <-tracee.Error:
			if ok {
				log.Fatalf("error: %s", err)
			}
		case _, ok := <-tracee.Events:
			if !ok {
				break loop
			}
			n++
			if err := tracee.SingleStep(); err != nil {
				log.Fatalf("step error: %s\n", err)
			}
		}
	}
	log.Printf("%d instructions\n", n)
}
