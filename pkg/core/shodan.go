package core

import (
	"io/ioutil"
	"net/http"
)

func (r *ManagerScan) Query(ip string) []byte {
	url := "https://internetdb.shodan.io/" + ip
	var content []byte
	var err error
	r.Client.DoGet(url, func(resp *http.Response, err1 error, szU string) {
		err = err1
		if nil == err && nil != resp {
			content, err = ioutil.ReadAll(resp.Body)
		}
	})
	if err != nil {
		return []byte{}
	}
	return content
}
