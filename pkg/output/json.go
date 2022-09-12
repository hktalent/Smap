package output

import (
	"encoding/json"
	"os"

	config "github.com/hktalent/smap/pkg/global"
)

var firstDone = false
var openedJsonFile *os.File

func StartJson(g *config.Config) {
	if g.JsonFilename != "-" {
		openedJsonFile = OpenFile(g.JsonFilename)
	}
	Write("[", g.JsonFilename, openedJsonFile)
}

func ContinueJson(result config.Output, g *config.Config) {
	prefix := ""
	if firstDone {
		prefix = ","
	}
	firstDone = true
	jsoned, _ := json.Marshal(&result)
	Write(prefix+string(jsoned), g.JsonFilename, openedJsonFile)
}

func EndJson(g *config.Config) {
	Write("]", g.JsonFilename, openedJsonFile)
	defer openedJsonFile.Close()
}
