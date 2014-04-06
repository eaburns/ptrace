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
	for _ = range tracee.Events() {
		n++
		if n == 1000 {
			if err := tracee.Detach(); err != nil {
				log.Fatal("detach error: %s\n", err)
			}
			continue
		}
		if err := tracee.SingleStep(); err != nil {
			log.Fatalf("step error: %s\n", err)
		}
	}
	if err := tracee.Error(); err != nil {
		log.Fatal("error: %s\n", err.Error())
	}
	log.Printf("%d instructions\n", n)
}
