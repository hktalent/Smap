package core

import (
	"regexp"
	"strings"
)

var reValidPair = regexp.MustCompile(`^([-]{1,2}[A-Za-z-]+)(\d.*)?`)

// 校验参数
var validArgs = map[string]bool{ // name : is_boolean_type
	"iL":                  false,
	"iR":                  false,
	"exclude":             false,
	"excludefile":         false,
	"sL":                  true,
	"sn":                  true,
	"Pn":                  true,
	"PS":                  true,
	"PA":                  true,
	"PU":                  true,
	"PY":                  true,
	"PE":                  true,
	"PP":                  true,
	"PM":                  true,
	"PO":                  true,
	"n":                   true,
	"R":                   true,
	"dns-servers":         false,
	"system-dns":          true,
	"traceroute":          true,
	"sS":                  true,
	"sT":                  true,
	"sA":                  true,
	"sW":                  true,
	"sM":                  true,
	"sU":                  true,
	"sN":                  true,
	"sF":                  true,
	"sX":                  true,
	"scanflags":           false,
	"sI":                  false,
	"sY":                  true,
	"sZ":                  true,
	"sO":                  true,
	"b":                   false,
	"p":                   false,
	"exclude-ports":       false,
	"F":                   true,
	"r":                   true,
	"top-ports":           false,
	"port-ratio":          false,
	"sV":                  true,
	"version-intensity":   false,
	"version-light":       true,
	"version-all":         true,
	"version-trace":       true,
	"sC":                  true,
	"script":              true,
	"script-args":         true,
	"script-args-file":    true,
	"script-trace":        true,
	"script-updatedb":     true,
	"script-help":         true,
	"O":                   true,
	"osscan-limit":        true,
	"osscan-guess":        true,
	"T":                   false,
	"min-hostgroup":       false,
	"max-hostgroup":       false,
	"min-parallelism":     false,
	"max-parallelism":     false,
	"min-rtt-timeout":     false,
	"max-rtt-timeout":     false,
	"initial-rtt-timeout": false,
	"max-retries":         false,
	"host-timeout":        false,
	"scan-delay":          false,
	"max-scan-delay":      false,
	"min-rate":            false,
	"max-rate":            false,
	"f":                   true,
	"D":                   false,
	"S":                   false,
	"e":                   false,
	"g":                   false,
	"source-port":         false,
	"proxies":             false,
	"data":                false,
	"data-string":         false,
	"data-length":         false,
	"ip-options":          false,
	"ttl":                 false,
	"spoof-mac":           false,
	"badsum":              true,
	"oN":                  false,
	"oX":                  false,
	"oS":                  false,
	"oG":                  false,
	"oA":                  false,
	"oJ":                  false,
	"oP":                  false,
	"v":                   true,
	"d":                   true,
	"reason":              true,
	"open":                true,
	"packet-trace":        true,
	"iflist":              true,
	"append-output":       true,
	"resume":              false,
	"stylesheet":          false,
	"webxml":              true,
	"no-stylesheet":       true,
	"6":                   true,
	"A":                   true,
	"datadir":             false,
	"send-eth":            true,
	"send-ip":             true,
	"privileged":          true,
	"unprivileged":        true,
	"V":                   true,
	"h":                   true,
}

const (
	WhatToDo_error     int = -1
	WhatToDo_next      int = 0
	WhatToDo_value     int = 1
	WhatToDo_extraData int = 2
)

func whatToDo(token string, lastAction int) (string, int) {
	/*
	   -1 = error
	    0 = look for next arg
	    1 = look for arg's value
	    2 = treat as extra data
	*/
	if strings.HasPrefix(token, "-") {
		if lastAction == WhatToDo_value {
			if token == "-" {
				return token, WhatToDo_next
			}
			return token, WhatToDo_error
		}
		newToken := strings.TrimPrefix(strings.TrimPrefix(token, "-"), "-")
		if newToken == "6" {
			return newToken, WhatToDo_next
		}
		argName := strings.Replace(newToken, "_", "-", WhatToDo_error)
		if boolType, ok := validArgs[argName]; ok {
			if boolType {
				return argName, WhatToDo_next
			}
			return argName, WhatToDo_value
		}
		return argName, WhatToDo_error
	} else if lastAction == WhatToDo_value {
		return token, WhatToDo_next
	}
	return token, WhatToDo_extraData
}

// 参数解析
//
//	参数以 - 开头，参数与值之间 可以与 = 相连
func ParseArgs(args []string) (map[string]string, []string, bool) {
	var lastAction int
	var lastArg string
	var extra []string
	argPair := map[string]string{}
	for _, token := range args {
		groups := reValidPair.FindStringSubmatch(token)
		if strings.HasPrefix(token, "-") && (strings.Contains(token, "=") || groups != nil) {
			if lastAction == WhatToDo_value {
				return argPair, extra, true
			}
			thisArgName := strings.Split(token, "=")[0]
			if groups != nil {
				thisArgName = groups[1]
			}
			cleaned, action := whatToDo(thisArgName, lastAction)
			if action == WhatToDo_value {
				if groups != nil {
					argPair[cleaned] = groups[2]
				} else {
					argPair[cleaned] = strings.Replace(token, thisArgName+"=", "", WhatToDo_value)
				}
			} else if action == WhatToDo_next {
				argPair[cleaned] = ""
			} else if action == WhatToDo_extraData {
				extra = append(extra, cleaned)
			} else if action == WhatToDo_error {
				return argPair, extra, true
			}
			lastArg = cleaned
			lastAction = action
			continue
		}
		cleaned, action := whatToDo(token, lastAction)
		if action == WhatToDo_extraData {
			extra = append(extra, cleaned)
		} else if action == WhatToDo_value {
			lastArg = cleaned
		} else if action == WhatToDo_error {
			return argPair, extra, true
		} else if action == WhatToDo_next && lastAction == WhatToDo_value {
			argPair[lastArg] = cleaned
		}
		lastAction = action
	}
	if lastAction == WhatToDo_value {
		return argPair, extra, true
	}
	return argPair, extra, false
}
