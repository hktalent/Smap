package output

import (
	"fmt"
	"os"

	config "github.com/hktalent/smap/pkg/global"
)

var openedPairFile *os.File

func StartPair(g *config.Config) {
	if g.PairFilename != "-" {
		openedPairFile = OpenFile(g.PairFilename)
	}
}

func ContinuePair(result config.Output, g *config.Config) {
	thisString := ""
	for _, port := range result.Ports {
		thisString += fmt.Sprintf("%s:%d\n", result.IP, port.Port)
	}
	Write(thisString, g.PairFilename, openedPairFile)
}

func EndPair(g *config.Config) {
}
