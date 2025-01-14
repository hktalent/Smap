package output

import (
	"fmt"
	"strings"

	config "github.com/hktalent/smap/pkg/global"
)

func StartSmap(g *config.Config) {
	if g.SmapFilename != "-" {
		g.OpenedSmapFile = OpenFile(g.SmapFilename)
	}
	Write(fmt.Sprintf("\n\tSmap (%s)\n", config.Version), g.SmapFilename, g.OpenedSmapFile)
}

func ContinueSmap(result config.Output, g *config.Config) {
	thisString := ""
	hostnames := result.Hostnames
	if result.UHostname != "" {
		hostnames = append(hostnames, result.UHostname)
	}
	if len(hostnames) != 0 {
		thisString += fmt.Sprintf("\n+ %s (%s)\n", result.IP, strings.Join(hostnames, ", "))
	} else {
		thisString += fmt.Sprintf("%s\n", result.IP)
	}
	if result.OS.Name != "" {
		thisString += fmt.Sprintf("  - OS: %s\n", result.OS.Name)
	}
	if len(result.Tags) != 0 {
		thisString += fmt.Sprintf("  - Tags: %s\n", strings.Join(result.Tags, ", "))
	}
	thisString += "  + Ports:\n"
	for _, port := range result.Ports {
		thisString += fmt.Sprintf("    - %d %s", port.Port, port.Protocol)
		if port.Service != "" {
			thisString += fmt.Sprintf("/%s ", port.Service)
		} else {
			thisString += " "
		}
		if len(port.Cpes) != 0 {
			thisString += strings.Join(port.Cpes, " ")
		}
		thisString += "\n"
	}
	if len(result.Vulns) != 0 {
		thisString += fmt.Sprintf("  - Vulns: %s\n", strings.Join(result.Vulns, ", "))
	}
	Write(thisString, g.SmapFilename, g.OpenedSmapFile)
}

func EndSmap(g *config.Config) {
	g.OpenedSmapFile.Close()
}
