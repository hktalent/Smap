package main

import (
	"github.com/hktalent/smap/pkg/core"
	"log"
	"os"
)

func main() {
	ms := core.NewManagerScan()
	err := ms.Start(os.Args[1:])
	if nil != err {
		log.Println(err)
	}
}
