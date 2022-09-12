package output

import (
	"fmt"
	config "github.com/hktalent/smap/pkg/global"
)

func StartPair(g *config.Config) {
	if g.PairFilename != "-" {
		g.OpenedPairFile = OpenFile(g.PairFilename)
	}
}

func ContinuePair(result config.Output, g *config.Config) {
	thisString := ""
	for _, port := range result.Ports {
		thisString += fmt.Sprintf("%s:%d\n", result.IP, port.Port)
	}
	Write(thisString, g.PairFilename, g.OpenedPairFile)
}

func EndPair(g *config.Config) {
	g.OpenedPairFile.Close()
}
