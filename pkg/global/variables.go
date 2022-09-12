package global

import (
	"os"
	"sync/atomic"
	"time"
)

type count32 int32

func (c *count32) inc() int32 {
	return atomic.AddInt32((*int32)(c), 1)
}

// 配置
//
//	优化后，可以多实例，便于工程化，不同实例允许不多参数
type Config struct {
	PortList       []int
	ScanStartTime  time.Time
	ScanEndTime    time.Time
	XmlFilename    string
	GrepFilename   string
	NmapFilename   string
	JsonFilename   string
	SmapFilename   string
	PairFilename   string
	Args           map[string]string
	TotalHosts     count32
	AliveHosts     count32
	OpenedGrepFile *os.File
	OpenedXmlFile  *os.File
	OpenedSmapFile *os.File
	OpenedJsonFile *os.File
	OpenedPairFile *os.File
	FirstDone      bool
	Probes         []Contender
	Table          map[string]string
}

func NewConfig() *Config {
	return &Config{FirstDone: false}
}

func (r *Config) Close() {
	for _, x := range []*os.File{r.OpenedGrepFile, r.OpenedXmlFile, r.OpenedSmapFile, r.OpenedJsonFile, r.OpenedPairFile} {
		if nil != x {
			x.Close()
			x = nil
		}
	}
	r.Probes = nil
	r.Args = nil
	r.Table = nil
	r.PortList = nil
}

func (r *Config) Increment(counterType int) {
	if counterType == 0 {
		r.TotalHosts.inc()
	} else {
		r.AliveHosts.inc()
	}
}

var (
	Version = "0.1.2"
)
