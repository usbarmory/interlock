// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.
//
//+build linux

package interlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const mountPoint = ".interlock-mnt"

type Config struct {
	Debug       bool     `json:"debug"`
	StaticPath  string   `json:"static_path"`
	SetTime     bool     `json:"set_time"`
	BindAddress string   `json:"bind_address"`
	TLS         string   `json:"tls"`
	TLSCert     string   `json:"tls_cert"`
	TLSKey      string   `json:"tls_key"`
	TLSClientCA string   `json:"tls_client_ca"`
	HSM         string   `json:"hsm"`
	KeyPath     string   `json:"key_path"`
	VolumeGroup string   `json:"volume_group"`
	Ciphers     []string `json:"ciphers"`

	availableCiphers map[string]cipherInterface
	enabledCiphers   map[string]cipherInterface
	availableHSMs    map[string]HSMInterface
	authHSM          HSMInterface
	tlsHSM           HSMInterface
	MountPoint       string
	TestMode         bool
	logFile          *os.File
}

var conf Config

func GetConfig() *Config {
	return &conf
}

func (c *Config) SetAvailableCipher(cipher cipherInterface) {
	if c.availableCiphers == nil {
		c.availableCiphers = make(map[string]cipherInterface)
	}

	c.availableCiphers[cipher.GetInfo().Name] = cipher
}

func (c *Config) SetAvailableHSM(model string, HSM HSMInterface) {
	if c.availableHSMs == nil {
		c.availableHSMs = make(map[string]HSMInterface)
	}

	c.availableHSMs[model] = HSM
}

func (c *Config) GetAvailableCipher(cipherName string) (cipher cipherInterface, err error) {
	cipher, ok := c.availableCiphers[cipherName]

	if !ok {
		err = errors.New("invalid cipher")
		return
	}

	// get a fresh instance
	cipher = cipher.New()

	return
}

func (c *Config) GetCipher(cipherName string) (cipher cipherInterface, err error) {
	cipher, ok := c.enabledCiphers[cipherName]

	if !ok {
		err = errors.New("invalid cipher")
		return
	}

	// get a fresh instance
	cipher = cipher.New()

	return
}

func (c *Config) GetCipherByExt(ext string) (cipher cipherInterface, err error) {
	for _, val := range c.enabledCiphers {
		if val.GetInfo().Extension == ext {
			cipher = val
			return
		}
	}

	err = errors.New("invalid cipher")

	return
}

func (c *Config) EnableCiphers() (err error) {
	if c.enabledCiphers == nil {
		c.enabledCiphers = make(map[string]cipherInterface)
	}

	if len(c.Ciphers) == 0 {
		c.PrintAvailableCiphers()
		return errors.New("missing cipher specification")
	}

	for i := 0; i < len(c.Ciphers); i++ {
		if val, ok := c.availableCiphers[c.Ciphers[i]]; ok {
			c.enabledCiphers[c.Ciphers[i]] = val
		} else {
			c.PrintAvailableCiphers()
			return fmt.Errorf("unsupported cipher name %s", c.Ciphers[i])
		}
	}

	return
}

func (c *Config) EnableHSM() (err error) {
	if c.HSM == "off" {
		return
	}

	HSMConf := strings.Split(c.HSM, ":")

	if len(HSMConf) < 2 {
		log.Fatal("invalid hsm configuration directive")
	}

	model := HSMConf[0]

	if val, ok := c.availableHSMs[model]; ok {
		options := strings.Split(HSMConf[1], ",")
		HSM := val.New()

		for i := 0; i < len(options); i++ {
			switch options[i] {
			case "luks":
				c.authHSM = HSM
			case "tls":
				c.tlsHSM = HSM
			case "cipher":
				cipher := HSM.Cipher()
				c.SetAvailableCipher(cipher)
				c.enabledCiphers[cipher.GetInfo().Name] = cipher
			default:
				log.Fatal("invalid hsm option")
			}
		}
	} else {
		log.Fatal("invalid hsm model")
	}

	return
}

func (c *Config) ActivateCiphers(activate bool) {
	for _, val := range c.enabledCiphers {
		err := val.Activate(activate)

		if err != nil {
			log.Print(err)
		}
	}
}

func (c *Config) PrintAvailableCiphers() {
	log.Println("supported ciphers:")

	for k := range c.availableCiphers {
		log.Printf("\t%s", k)
	}
}

func (c *Config) SetDefaults() {
	c.Debug = false
	c.StaticPath = "static"
	c.SetTime = false
	c.TLS = "on"
	c.TLSCert = "certs/cert.pem"
	c.TLSKey = "certs/key.pem"
	c.HSM = "off"
	c.KeyPath = "keys"
	c.Ciphers = []string{"OpenPGP", "AES-256-OFB", "TOTP"}
	c.TestMode = false
	c.VolumeGroup = "lvmvolume"
}

func (c *Config) SetMountPoint() error {
	c.MountPoint = filepath.Join(os.Getenv("HOME"), mountPoint)

	return os.MkdirAll(c.MountPoint, 0700)
}

func (c *Config) Set(configPath string) (err error) {
	debugFlag := c.Debug

	b, err := ioutil.ReadFile(configPath)

	if err != nil {
		return
	}

	err = json.Unmarshal(b, &c)

	if debugFlag {
		c.Debug = true
	}

	return
}

func (c *Config) Print() {
	j, _ := json.MarshalIndent(c, "", "\t")

	log.Println("applied configuration:")
	log.Printf("\n%s", string(j))
}

func setTime(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	var epoch int64

	err = validateRequest(req, []string{"epoch:n"})

	if err != nil {
		return errorResponse(err, "")
	}

	switch t := req["epoch"].(type) {
	case json.Number:
		epoch, err = t.Int64()
	default:
		return errorResponse(errors.New("invalid epoch format"), "")
	}

	if err != nil {
		return errorResponse(err, "")
	}

	args := []string{"-s", "@" + strconv.FormatInt(epoch, 10)}
	cmd := "/bin/date"

	if conf.SetTime {
		_, err = execCommand(cmd, args, true, "")

		if err != nil {
			return errorResponse(err, "")
		}

		hour, min, sec := time.Now().Clock()

		status.Log(syslog.LOG_NOTICE, "adjusted device time to %02d:%02d:%02d", hour, min, sec)
	}

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}
