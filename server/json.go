package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
)

type jsonObject map[string]interface{}

var censorPattern = regexp.MustCompile("password")

func parseRequest(r *http.Request) (j jsonObject, err error) {
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return
	}

	if conf.Debug {
		if !censorPattern.Match(body) {
			log.Printf("%s", body)
		}
	}

	d := json.NewDecoder(strings.NewReader(string(body[:])))
	d.UseNumber()

	err = d.Decode(&j)

	if err != nil {
		return
	}

	return
}

func (j jsonObject) String() (s string) {
	b, err := json.Marshal(j)

	if err != nil {
		log.Print(err)
		return
	}

	s = string(b)

	return
}

// FIXME: very basic validation function that needs much improvement
func validateRequest(req jsonObject, reqAttrs []string) (err error) {
	for i := 0; i < len(reqAttrs); i++ {
		if _, ok := req[reqAttrs[i]]; !ok {
			err = fmt.Errorf("missing attribute %s", reqAttrs[i])
			return
		}
	}

	return
}
