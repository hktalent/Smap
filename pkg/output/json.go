package output

import (
	"encoding/json"
	config "github.com/hktalent/smap/pkg/global"
)

func StartJson(g *config.Config) {
	if g.JsonFilename != "-" {
		g.OpenedJsonFile = OpenFile(g.JsonFilename)
	}
	Write("[", g.JsonFilename, g.OpenedJsonFile)
}

func ContinueJson(result config.Output, g *config.Config) {
	prefix := ""
	if g.FirstDone {
		prefix = ","
	}
	g.FirstDone = true
	jsoned, _ := json.Marshal(&result)
	Write(prefix+string(jsoned), g.JsonFilename, g.OpenedJsonFile)
}

func EndJson(g *config.Config) {
	Write("]", g.JsonFilename, g.OpenedJsonFile)
	defer g.OpenedJsonFile.Close()
}
