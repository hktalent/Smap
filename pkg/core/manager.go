package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/hktalent/smap/pkg/db"
	config "github.com/hktalent/smap/pkg/global"
	o "github.com/hktalent/smap/pkg/output"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var (
	activeScans    sync.WaitGroup
	activeOutputs  sync.WaitGroup
	activeEnders   sync.WaitGroup
	activeObjects  sync.WaitGroup
	targetsChannel = make(chan scanObject, 3)
	outputChannel  = make(chan config.Output, 1000)
	reAddressRange = regexp.MustCompile(`^\d{1,3}(-\d{1,3})?\.\d{1,3}(-\d{1,3})?\.\d{1,3}(-\d{1,3})?\.\d{1,3}(-\d{1,3})?$`)
)

type scanObject struct {
	IP       string
	Ports    []int
	Hostname string
}

type respone struct {
	Cpes      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

func getPorts(g *config.Config) []int {
	thesePorts := []int{}
	if value, ok := g.Args["p"]; ok {
		for _, port := range strings.Split(value, ",") {
			intPort, err := strconv.Atoi(port)
			if err == nil && intPort >= 0 && intPort <= 65535 {
				thesePorts = append(thesePorts, intPort)
			} else {
				fmt.Fprint(os.Stderr, "' ' is not a valid port number.\nQUITTING!\n")
				os.Exit(1)
			}
		}
	}
	return thesePorts
}

func isIPv4(str string) bool {
	parsed := net.ParseIP(str)
	if parsed == nil {
		return false
	}
	return reAddressRange.MatchString(str)
}

func isHostname(str string) bool {
	_, err := publicsuffix.Domain(str)
	return err == nil
}

func isAddressRange(str string) bool {
	if !reAddressRange.MatchString(str) {
		return false
	}
	for _, part := range strings.Split(str, ".") {
		for _, each := range strings.Split(part, "-") {
			if each[0] == 48 { // 48 is 0 in decimal
				return false
			}
			n, _ := strconv.Atoi(each)
			if n > 255 {
				return false
			}
		}
	}
	return true
}

func hostnameToIP(hostname string) string {
	ips, _ := net.LookupIP(hostname)
	if len(ips) > 0 {
		return ips[0].String()
	}
	return ""
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func handleOutput(g *config.Config) {
	var (
		startOutput    []func(*config.Config)
		continueOutput []func(config.Output, *config.Config)
		endOutput      []func(*config.Config)
	)

	activeEnders.Add(1)
	if value, ok := g.Args["oA"]; ok {
		activeEnders.Add(2)
		if value == "-" {
			fmt.Fprint(os.Stderr, "Cannot display multiple output types to stdout.\nQUITTING!\n")
			os.Exit(1)
		} else {
			g.XmlFilename = value + ".xml"
			g.GrepFilename = value + ".gnmap"
			g.Args["oN"] = value + ".nmap"
		}
		startOutput = []func(*config.Config){o.StartXML, o.StartGrep, o.StartNmap}
		continueOutput = []func(config.Output, *config.Config){o.ContinueXML, o.ContinueGrep, o.ContinueNmap}
		endOutput = []func(*config.Config){o.EndXML, o.EndGrep, o.EndNmap}
	} else if value, ok := g.Args["oX"]; ok {
		startOutput = []func(*config.Config){o.StartXML}
		continueOutput = []func(config.Output, *config.Config){o.ContinueXML}
		endOutput = []func(*config.Config){o.EndXML}
		g.XmlFilename = value
	} else if value, ok := g.Args["oG"]; ok {
		startOutput = []func(*config.Config){o.StartGrep}
		continueOutput = []func(config.Output, *config.Config){o.ContinueGrep}
		endOutput = []func(*config.Config){o.EndGrep}
		g.GrepFilename = value
	} else if value, ok := g.Args["oJ"]; ok {
		startOutput = []func(*config.Config){o.StartJson}
		continueOutput = []func(config.Output, *config.Config){o.ContinueJson}
		endOutput = []func(*config.Config){o.EndJson}
		g.JsonFilename = value
	} else if value, ok := g.Args["oS"]; ok {
		startOutput = []func(*config.Config){o.StartSmap}
		continueOutput = []func(config.Output, *config.Config){o.ContinueSmap}
		endOutput = []func(*config.Config){o.EndSmap}
		g.SmapFilename = value
	} else if value, ok := g.Args["oP"]; ok {
		startOutput = []func(*config.Config){o.StartPair}
		continueOutput = []func(config.Output, *config.Config){o.ContinuePair}
		endOutput = []func(*config.Config){o.EndPair}
		g.PairFilename = value
	} else {
		startOutput = []func(*config.Config){o.StartNmap}
		continueOutput = []func(config.Output, *config.Config){o.ContinueNmap}
		endOutput = []func(*config.Config){o.EndNmap}
	}
	for _, function := range startOutput {
		function(g)
	}
	for output := range outputChannel {
		for _, function := range continueOutput {
			function(output, g)
		}
		activeOutputs.Done()
	}
	for _, function := range endOutput {
		function(g)
		activeEnders.Done()
	}
}

func scanner(g *config.Config) {
	threads := make(chan bool, 3)
	for target := range targetsChannel {
		threads <- true
		go func(target scanObject) {
			processScanObject(target, g)
			activeScans.Done()
			<-threads
		}(target)
	}
}

func createScanObjects(object string, g *config.Config) {
	activeScans.Add(1)
	var oneObject scanObject
	oneObject.Ports = g.PortList
	if isIPv4(object) {
		oneObject.IP = object
		targetsChannel <- oneObject
	} else if strings.Contains(object, "/") && isIPv4(strings.Split(object, "/")[0]) {
		activeScans.Done()
		ip, ipnet, err := net.ParseCIDR(object)
		if err != nil {
			return
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			oneObject.IP = ip.String()
			activeScans.Add(1)
			targetsChannel <- oneObject
		}
	} else if isHostname(object) {
		ip := hostnameToIP(object)
		if ip != "" {
			oneObject.IP = ip
			oneObject.Hostname = object
			targetsChannel <- oneObject
		} else {
			activeScans.Done()
		}
	} else if isAddressRange(object) {
		return
	} else {
		activeScans.Done()
	}
}

func processScanObject(object scanObject, g *config.Config) {
	g.Increment(0)
	scanStarted := time.Now()
	response := Query(object.IP)
	var output config.Output
	if len(response) < 50 {
		return
	} else {
		activeOutputs.Add(1)
	}
	var data respone
	json.Unmarshal(response, &data)
	output.IP = data.IP
	output.Tags = data.Tags
	output.Vulns = data.Vulns
	output.Hostnames = data.Hostnames
	output.UHostname = object.Hostname
	filteredPorts := []int{}
	if len(object.Ports) > 0 {
		for _, port := range data.Ports {
			if containsInt(object.Ports, port) {
				filteredPorts = append(filteredPorts, port)
			}
		}
		if len(filteredPorts) == 0 {
			return
		}
	} else {
		filteredPorts = data.Ports
	}
	output.Ports, output.OS = Correlate(filteredPorts, data.Cpes)
	output.Start = scanStarted
	output.End = time.Now()
	g.Increment(1)
	outputChannel <- output
}

func Init() {
	g := &config.Config{}
	args, extra, invalid := ParseArgs()
	if invalid {
		fmt.Println("One or more of your arguments are invalid. Refer to docs.\nQUITTING!")
		os.Exit(1)
	} else if _, ok := args["h"]; ok || len(os.Args) == 1 {
		fmt.Print(db.HelpText)
		os.Exit(0)
	}
	g.Args = args
	json.Unmarshal(db.NmapSigs, &Probes)
	json.Unmarshal(db.NmapTable, &Table)
	g.PortList = getPorts(g)
	g.ScanStartTime = time.Now()
	go scanner(g)
	go handleOutput(g)
	if value, ok := g.Args["iL"]; ok {
		scanner := bufio.NewScanner(os.Stdin)
		if value != "-" {
			file, err := os.Open(value)
			if err != nil {
				os.Exit(1)
			}
			defer file.Close()
			scanner = bufio.NewScanner(file)
		}
		for scanner.Scan() {
			createScanObjects(scanner.Text(), g)
		}

		if err := scanner.Err(); err != nil {
			os.Exit(1)
		}
	} else if len(extra) != 0 {
		threads := make(chan bool, 3)
		for _, arg := range extra {
			activeObjects.Add(1)
			threads <- true
			go func(object string) {
				createScanObjects(object, g)
				<-threads
				activeObjects.Done()
			}(arg)
		}
		activeObjects.Wait()
	} else {
		fmt.Println("WARNING: No targets were specified, so 0 hosts scanned.")
	}
	activeScans.Wait()
	close(targetsChannel)
	g.ScanEndTime = time.Now()
	activeOutputs.Wait()
	close(outputChannel)
	activeEnders.Wait()
}
