// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

// +build signal

package interlock

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aebruno/textsecure"
)

const timeFormat = "Jan 02 15:04 MST"
const attachmentMsg = "INTERLOCK attachment: "
const historySize = 10 * 1024
const registrationTimeout = 60 * time.Second
const keyType = 0x05
const hashIterations = 5200

var numberPattern = regexp.MustCompile(`^(?:\+)[0-9]+$`)
var contactPattern = regexp.MustCompile(`^(([^/]*) ((?:\+)[0-9]+))$`)
var remoteIdentityPattern = regexp.MustCompile("^remote_([0-9]+)")

type Signal struct {
	info             cipherInfo
	client           *textsecure.Client
	number           string
	verificationType string
	verificationCode string
	registering      int

	cipherInterface
}

type contactInfo struct {
	Name        string
	Number      string
	Directory   string
	HistoryPath string
}

func init() {
	conf.SetAvailableCipher(new(Signal).Init())
}

func (t *Signal) Init() cipherInterface {
	t.info = cipherInfo{
		Name:        "Signal",
		Description: "Signal (TextSecure) protocol V2",
		KeyFormat:   "binary",
		Enc:         false,
		Dec:         false,
		Sig:         false,
		OTP:         false,
		Msg:         true,
		Extension:   "signal",
	}

	return t
}

func (t *Signal) New() cipherInterface {
	// this cipher is always a single instance
	return t
}

func (t *Signal) Activate(activate bool) (err error) {
	if activate {
		err = t.setupClient()

		if err != nil {
			return
		}
	}

	if activate {
		if !needsRegistration() {
			go func() {
				t.start()
			}()
		}
	} else {
		t.stop()
	}

	return
}

func (t *Signal) GetInfo() cipherInfo {
	return t.info
}

func (t *Signal) GenKey(i string, e string) (p string, s string, err error) {
	err = errors.New("cipher does not support key generation")
	return
}

func (t *Signal) GetKeyInfo(k key) (i string, err error) {
	var remoteIdentity []byte
	var identity []byte
	var sn string

	m := remoteIdentityPattern.FindStringSubmatch(k.Identifier)

	if len(m) == 0 {
		i = "Signal library private data"
		return
	}

	remoteIdentityPath := filepath.Join(conf.MountPoint, k.Path)
	identityPath := filepath.Join(storagePath(), "identity", "identity_key")

	remoteIdentity, err = ioutil.ReadFile(remoteIdentityPath)

	if err != nil {
		return
	}

	identity, err = ioutil.ReadFile(identityPath)

	if err != nil {
		return
	}

	remoteSafetyNumbers := genSafetyNumbers(m[1], remoteIdentity)
	safetyNumbers := genSafetyNumbers(t.number, identity[0:32])

	if strings.Compare(safetyNumbers, remoteSafetyNumbers) <= 0 {
		sn = safetyNumbers + remoteSafetyNumbers
	} else {
		sn = remoteSafetyNumbers + safetyNumbers
	}

	i = fmt.Sprintf("Verify safety numbers:\n\n")

	for n := 0; n < 60; n += 20 {
		i += fmt.Sprintf("%s %s %s %s\n", sn[n:n+5], sn[n+5:n+10], sn[n+10:n+15], sn[n+15:n+20])
	}

	return
}

func (t *Signal) SetPassword(password string) error {
	return errors.New("cipher does not support passwords")
}

func (t *Signal) SetKey(k key) error {
	return errors.New("cipher does not support explicit key set")
}

func (t *Signal) Encrypt(input *os.File, output *os.File, _ bool) error {
	return errors.New("cipher does not support encryption")
}

func (t *Signal) Decrypt(input *os.File, output *os.File, verify bool) error {
	return errors.New("cipher does not support decryption")
}

func (t *Signal) Sign(input *os.File, output *os.File) error {
	return errors.New("cipher does not support signin")
}

func (t *Signal) GenOTP(timestamp int64) (otp string, exp int64, err error) {
	err = errors.New("cipher does not support OTP generation")
	return
}

func (t *Signal) Verify(input *os.File, signature *os.File) error {
	return errors.New("cipher does not support signature verification")
}

func (t *Signal) HandleRequest(r *http.Request) (res jsonObject) {
	switch r.RequestURI {
	case "/api/Signal/register":
		res = t.registerNumber(r)
	case "/api/Signal/send":
		res = sendMessage(r)
	case "/api/Signal/history":
		res = downloadHistory(r)
	default:
		res = notFound()
	}

	return
}

func (t *Signal) registerNumber(r *http.Request) (res jsonObject) {
	var verificationType string
	var verificationCode string

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"contact:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	contact := req["contact"].(string)

	if !numberPattern.MatchString(contact) {
		return errorResponse(errors.New("invalid contact"), "")
	}

	if !needsRegistration() {
		n, _ := registeredNumber()
		return errorResponse(fmt.Errorf("%s is already registered, delete %s to reset", n, filepath.Join(conf.KeyPath, "signal")), "")
	}

	if f, ok := req["type"]; ok {
		verificationType = f.(string)
	}

	if c, ok := req["code"]; ok {
		verificationCode = c.(string)
	}

	if verificationCode == "" && verificationType == "" {
		return errorResponse(errors.New("type or code must be specified"), "")
	}

	if verificationCode != "" && verificationType != "" {
		return errorResponse(errors.New("type or code cannot be both specified"), "")
	}

	err = os.MkdirAll(storagePath(), 0700)

	if err != nil {
		return
	}

	output, err := os.OpenFile(numberPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return errorResponse(fmt.Errorf("failed to save registration contact: %v", err), "")
	}

	output.Write([]byte(contact))
	output.Close()

	if verificationType != "" {
		t.verificationType = verificationType

		if t.client != nil {
			t.stop()
		}

		err = t.setupClient()
	}

	if verificationCode != "" {
		t.verificationCode = verificationCode
	}

	if err != nil {
		return errorResponse(err, "")
	}

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func sendMessage(r *http.Request) (res jsonObject) {
	var attachmentPath string
	var attachment *os.File

	if needsRegistration() {
		return errorResponse(errors.New("Signal is not registered, please register before sending messages"), "")
	}

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"contact:s", "msg:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	msg := req["msg"].(string)
	contact, err := getContact(req["contact"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	if a, ok := req["attachment"]; ok {
		attachmentPath, err = absolutePath(a.(string))

		if err != nil {
			return errorResponse(err, "")
		}

		inKeyPath, private := detectKeyPath(attachmentPath)

		if inKeyPath && private {
			return errorResponse(errors.New("attaching private key(s) is not allowed"), "")
		}

		attachment, err = os.Open(attachmentPath)

		if err != nil {
			return errorResponse(err, "")
		}
		defer attachment.Close()

		// append attachment name with INTERLOCK specific metadata format
		msg = msg + " [" + attachmentMsg + path.Base(attachmentPath) + "]"
		_, err = textsecure.SendAttachment(contact.Number, msg, attachment)

		if err != nil {
			return errorResponse(err, "")
		}

		err = updateHistory(contact, msg, "->", time.Now())
	} else {
		_, err = textsecure.SendMessage(contact.Number, msg)

		if err != nil {
			return errorResponse(err, "")
		}

		err = updateHistory(contact, msg, "->", time.Now())
	}

	if err != nil {
		return errorResponse(err, "")
	}

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func downloadHistory(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"contact:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	contact, err := getContact(req["contact"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	_, err = os.Stat(contact.HistoryPath)

	if err != nil {
		updateHistory(contact, "[new contact history created]", "", time.Now())
	}

	input, err := os.Open(contact.HistoryPath)

	if err != nil {
		return errorResponse(err, "")
	}
	defer input.Close()

	stat, err := input.Stat()

	if err != nil {
		return errorResponse(err, "")
	}

	trimOffset := 0

	if stat.Size() > historySize {
		_, err = input.Seek(stat.Size()-historySize, 0)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	history, err := ioutil.ReadAll(input)

	if err != nil {
		return errorResponse(err, "")
	}

	if stat.Size() > historySize {
		trimOffset = bytes.IndexByte(history, 0x0a) // \n

		if trimOffset < 0 {
			trimOffset = 0
		}
	}

	res = jsonObject{
		"status":   "OK",
		"response": string(history[trimOffset:]),
	}

	return
}

func (t *Signal) getConfig() (*textsecure.Config, error) {
	logLevel := "error"

	if conf.Debug {
		logLevel = "debug"
	}

	tsConf := textsecure.Config{
		Tel:              t.number,
		VerificationType: t.verificationType,
		StorageDir:       storagePath(),
		LogLevel:         logLevel,
	}

	return &tsConf, nil
}

func (t *Signal) setupClient() (err error) {
	err = os.MkdirAll(storagePath(), 0700)

	if err != nil {
		return
	}

	err = os.MkdirAll(contactsPath(), 0700)

	if err != nil {
		return
	}

	t.verificationCode = ""
	t.registering = 0
	t.number, err = registeredNumber()

	if err != nil {
		return errors.New("skipping Signal cipher setup, no registered number")
	}

	if t.client == nil {
		t.client = &textsecure.Client{
			GetConfig:           t.getConfig,
			GetVerificationCode: t.getVerificationCode,
			GetStoragePassword:  getStoragePassword,
			MessageHandler:      messageHandler,
			RegistrationDone:    t.registrationDone,
		}
	}

	if needsRegistration() {
		if t.registering > 0 {
			return fmt.Errorf("Signal registration in progress, waiting verification code for %s", t.number)
		}

		n := status.Notify(syslog.LOG_NOTICE, "Signal registration in progress, waiting verification code for %s", t.number)
		t.registering = n

		go func() {
			time.Sleep(registrationTimeout)
			status.Remove(n)
		}()

		go func() {
			err = textsecure.Setup(t.client)

			if err != nil {
				status.Log(syslog.LOG_ERR, "failed to enable Signal cipher: %v", err)
				status.Remove(t.registering)
				t.registering = 0
			}
		}()
	} else {
		err = textsecure.Setup(t.client)
	}

	return
}

func (t *Signal) getVerificationCode() (code string) {
	start := time.Now()

	for {
		if t.verificationCode != "" {
			status.Log(syslog.LOG_NOTICE, "received Signal registration verification code for %s", t.number)
			code = t.verificationCode
			break
		}

		if time.Since(start) > registrationTimeout {
			status.Log(syslog.LOG_ERR, "timed out while waiting for Signal verification code for %s\n", t.number)
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	return
}

func (t *Signal) registrationDone() {
	status.Log(syslog.LOG_NOTICE, "registration complete for %s\n", t.number)
	status.Remove(t.registering)
	t.registering = 0
	t.start()
}

func (t *Signal) start() {
	status.Log(syslog.LOG_NOTICE, "starting Signal message listener for %s", t.number)
	err := textsecure.StartListening()

	if err != nil {
		status.Log(syslog.LOG_ERR, "failed to start Signal message listener: %v", err)
	}
}

func (t *Signal) stop() {
	status.Log(syslog.LOG_NOTICE, "stopping Signal message listener for %s", t.number)
	err := textsecure.StopListening()

	if err != nil {
		status.Log(syslog.LOG_ERR, "failed to stop Signal message listener: %v", err)
	}
}

func messageHandler(msg *textsecure.Message) {
	status.Log(syslog.LOG_NOTICE, "received message from %s\n", msg.Source())

	go func() {
		n := status.Notify(syslog.LOG_NOTICE, "received message from %s\n", msg.Source())
		time.Sleep(30 * time.Second)
		status.Remove(n)
	}()

	contact, err := getContact(msg.Source())

	if err != nil {
		status.Error(err)
		return
	}

	if msg.Message() != "" {
		t := time.Unix(int64(msg.Timestamp()/1000), 0)
		updateHistory(contact, msg.Message(), "<-", t)
	}

	attachments := msg.Attachments()
	attachmentPattern := regexp.MustCompile("\\[" + attachmentMsg + "(.*)\\]$")
	m := attachmentPattern.FindStringSubmatch(msg.Message())

	// assign random name by default, use name embedded in msg for
	// attachment sent via INTERLOCK
	name := ""

	if len(attachments) == 1 && len(m) == 2 {
		name = path.Base(m[1])
	}

	for _, a := range attachments {
		err := saveAttachment(contact, a.R, name, msg)

		if err != nil {
			status.Error(err)
			return
		}
	}
}

func saveAttachment(contact contactInfo, attachment io.Reader, name string, msg *textsecure.Message) (err error) {
	var output *os.File

	err = os.MkdirAll(contact.Directory, 0700)

	if err != nil {
		return
	}

	if name == "" {
		output, err = ioutil.TempFile(contact.Directory, "attachment_")
	} else {
		outputPath := filepath.Join(contact.Directory, name)
		output, err = os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)
	}

	if err != nil {
		return
	}
	defer output.Close()

	io.Copy(output, attachment)
	status.Log(syslog.LOG_NOTICE, "saved attachment from %s %s\n", contact.Name, contact.Number)

	name = relativePath(output.Name())
	t := time.Unix(int64(msg.Timestamp()/1000), 0)
	updateHistory(contact, "["+name+"]", "<-", t)

	return
}

func parseContact(identifier string) (name string, number string, err error) {
	m := contactPattern.FindStringSubmatch(identifier)

	if len(m) == 0 {
		err = errors.New("invalid contact")
		return
	}

	name = m[2]
	number = m[3]

	return
}

func getContact(identifier string) (contact contactInfo, err error) {
	var name string
	var number string

	if numberPattern.MatchString(identifier) {
		number = identifier
	} else {
		name, number, err = parseContact(identifier)

		if err != nil {
			return
		}
	}

	err = os.MkdirAll(contactsPath(), 0700)

	if err != nil {
		return
	}

	contacts, err := filepath.Glob(contactsPath() + "/" + "*" + number)

	if len(contacts) == 0 {
		if name == "" {
			name = "Unknown"
		}

		contact = contactInfo{
			Name:        name,
			Number:      number,
			Directory:   filepath.Join(contactsPath(), name+" "+number),
			HistoryPath: filepath.Join(contactsPath(), name+" "+number, "history"),
		}
	} else {
		identifier = path.Base(contacts[0])
		name, number, err = parseContact(identifier)

		if err != nil {
			return
		}

		path := filepath.Join(contactsPath(), identifier)
		contact = contactInfo{
			Name:        name,
			Number:      number,
			Directory:   path,
			HistoryPath: filepath.Join(path, "history"),
		}
	}

	return
}

func updateHistory(contact contactInfo, msg string, prefix string, t time.Time) (err error) {
	err = os.MkdirAll(contact.Directory, 0700)

	if err != nil {
		return
	}

	output, err := os.OpenFile(contact.HistoryPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)

	if err != nil {
		status.Error(err)
		return
	}
	defer output.Close()

	h := fmt.Sprintf("%s %s %s\n", t.Format(timeFormat), prefix, msg)

	output.Write([]byte(h))

	return
}

func needsRegistration() (reg bool) {
	reg = false

	// check for last resort key ID
	_, err := os.Stat(filepath.Join(storagePath(), "prekeys", fmt.Sprintf("%09d", 0xffffff)))

	if err != nil {
		reg = true
	}

	return
}

func registeredNumber() (number string, err error) {
	n, err := ioutil.ReadFile(numberPath())

	if err != nil {
		return
	}

	number = string(n)

	return
}

func storagePath() string {
	return filepath.Join(conf.MountPoint, conf.KeyPath, "signal", "private")
}

func contactsPath() string {
	return filepath.Join(conf.MountPoint, "signal")
}

func numberPath() string {
	return filepath.Join(storagePath(), "number")
}

func getStoragePassword() string {
	return ""
}

func genSafetyNumbers(number string, identity []byte) (safetyNumbers string) {
	identityHash := []byte{0, 0, keyType}
	identityHash = append(identityHash, identity...)

	if !strings.HasPrefix(number, "+") {
		identityHash = append(identityHash, "+"...)
	}

	identityHash = append(identityHash, number...)

	h := sha512.New()

	for i := 0; i < hashIterations; i++ {
		h.Write(identityHash)
		h.Write([]byte{keyType})
		h.Write(identity)
		identityHash = h.Sum(nil)
		h.Reset()
	}

	for i := 0; i <= 25; i += 5 {
		n := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, identityHash[i:i+5]...)) % 100000
		safetyNumbers += fmt.Sprintf("%05d", n)
	}

	return
}
