package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"strconv"
)

type config struct {
	Debug       bool     `json:"debug"`
	BindAddress string   `json:"bind_address"`
	TLSCert     string   `json:"tls_cert"`
	TLSKey      string   `json:"tls_key"`
	KeyPath     string   `json:"key_path"`
	Ciphers     []string `json:"ciphers"`

	availableCiphers map[string]cipherInterface
	enabledCiphers   map[string]cipherInterface
	mountPoint       string
}

var conf config

func (c *config) FindCipherByExt(ext string) (cipher cipherInterface) {
	for _, value := range c.enabledCiphers {
		if value.GetInfo().Extension == ext {
			return value
		}
	}

	return
}

func (c *config) SetAvailableCipher(cipher cipherInterface) {
	if c.availableCiphers == nil {
		c.availableCiphers = make(map[string]cipherInterface)
	}

	c.availableCiphers[cipher.GetInfo().Name] = cipher
}

func (c *config) EnableCiphers() {
	if c.enabledCiphers == nil {
		c.enabledCiphers = make(map[string]cipherInterface)
	}

	if len(c.Ciphers) == 0 {
		c.PrintAvailableCiphers()
		log.Fatalf("missing cipher specification")
	}

	for i := 0; i < len(c.Ciphers); i++ {
		if val, ok := c.availableCiphers[c.Ciphers[i]]; ok {
			c.enabledCiphers[c.Ciphers[i]] = val
		} else {
			c.PrintAvailableCiphers()
			log.Fatalf("unsupported cipher name %s", c.Ciphers[i])
		}
	}
}

func (c *config) PrintAvailableCiphers() {
	log.Println("supported ciphers:")

	for k := range c.availableCiphers {
		log.Printf("\t%s", k)
	}
}

func (c *config) SetDefaults() {
	c.TLSCert = "certs/cert.pem"
	c.TLSKey = "certs/key.pem"
	c.KeyPath = "keys"
	c.mountPoint = "/mnt/interlock"
}

func (c *config) Set(configPath string) (err error) {
	f, err := os.Open(configPath)

	if err != nil {
		return
	}

	b, err := ioutil.ReadAll(f)

	if err != nil {
		return
	}

	err = json.Unmarshal(b, &c)

	if err != nil {
		return
	}

	c.EnableCiphers()

	return
}

func (c *config) Print() {
	j, _ := json.MarshalIndent(c, "", "\t")

	log.Println("configuration:")
	log.Printf("\n%s", string(j))
}

func setTime(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	var epoch int64

	err = validateRequest(req, []string{"epoch"})

	if err != nil {
		return errorResponse(err, "")
	}

	switch t := req["epoch"].(type) {
	case json.Number:
		epoch, err = t.Int64()
	default:
		return errorResponse(errors.New("invalid epoch format"), "")
	}

	status.Log(syslog.LOG_NOTICE, "setting system time to %v", epoch)

	args := []string{"-s", "@" + strconv.FormatInt(epoch, 10)}
	cmd := "/bin/date"

	_, err = execCommand(cmd, args, true, "")

	if err != nil {
		return errorResponse(err, "")
	}

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}
