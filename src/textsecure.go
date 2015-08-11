// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build textsecure

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"time"

	"github.com/janimo/textsecure"
)

const contactExt = "textsecure"
const timeFormat = "Jan 02 15:04"
const attachmentMsg = "INTERLOCK attachment: "
const historySize = 10 * 1024

var numberPattern = regexp.MustCompile("^(?:\\+|00)[0-9]+$")
var register = false

type textSecure struct {
	info   cipherInfo
	client *textsecure.Client
	number string

	cipherInterface
}

type contactInfo struct {
	Name          string
	Number        string
	HistoryPath   string
	AttachmentDir string
}

func init() {
	flag.BoolVar(&register, "r", false, "textsecure registration")
	conf.SetAvailableCipher(new(textSecure).Init())
}

func (t *textSecure) Init() (c cipherInterface) {
	t.info = cipherInfo{
		Name:        "TextSecure",
		Description: "TextSecure/Signal protocol V2",
		KeyFormat:   "binary",
		Enc:         false,
		Dec:         false,
		Sig:         false,
		OTP:         false,
		Msg:         true,
		Extension:   contactExt,
	}

	return t
}

func (t *textSecure) New() cipherInterface {
	return new(textSecure).Init()
}

func (t *textSecure) Enable() (c cipherInterface, err error) {
	if register {
		err = t.registerNumber()

		if err != nil {
			log.Fatal(err)
		}

		os.Exit(0)
	}

	return t, nil
}

func (t *textSecure) Activate(activate bool) (err error) {
	err = t.setupClient()

	if err != nil {
		return
	}

	if activate {
		go func() {
			status.Log(syslog.LOG_NOTICE, "starting TextSecure message listener for %s", t.number)
			err = textsecure.StartListening()

			if err != nil {
				status.Log(syslog.LOG_ERR, "failed to enable TextSecure message listener: %v", err)
			}
		}()
	} else {
		status.Log(syslog.LOG_NOTICE, "stopping TextSecure message listener for %s", t.number)
		textsecure.StopListening()
	}

	return
}

func (t *textSecure) GetInfo() cipherInfo {
	return t.info
}

func (t *textSecure) HandleRequest(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	switch r.RequestURI {
	case "/api/textsecure/send":
		res = sendMessage(w, r)
	case "/api/textsecure/history":
		res = downloadHistory(w, r)
	default:
		res = notFound(w)
	}

	return
}

func sendMessage(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	var attachmentPath string
	var attachment *os.File

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"contact:s", "msg:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	msg := req["msg"].(string)
	contactPath, err := absolutePath(req["contact"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	contact, err := parseContact(contactPath)

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
		err = textsecure.SendAttachment(contact.Number, msg, attachment)

		if err != nil {
			return errorResponse(err, "")
		}

		err = updateHistory(contact, msg, ">", time.Now())
	} else {
		err = textsecure.SendMessage(contact.Number, msg)

		if err != nil {
			return errorResponse(err, "")
		}

		err = updateHistory(contact, msg, ">", time.Now())
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

func downloadHistory(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"contact:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	contactPath, err := absolutePath(req["contact"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	_, err = parseContact(contactPath)

	if err != nil {
		return errorResponse(err, "")
	}

	input, err := os.Open(contactPath)

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
		trimOffset = bytes.IndexByte(history, 0xa) // \n

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

func (t *textSecure) getConfig() (*textsecure.Config, error) {
	logLevel := "error"

	if conf.Debug {
		logLevel = "debug"
	}

	tsConf := textsecure.Config{
		Tel:              t.number,
		VerificationType: "sms",
		StorageDir:       storagePath(),
		LogLevel:         logLevel,
	}

	return &tsConf, nil
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
		updateHistory(contact, msg.Message(), "<", msg.Timestamp())
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
		err := saveAttachment(contact, a, name, msg)

		if err != nil {
			status.Error(err)
			return
		}
	}
}

func saveAttachment(contact contactInfo, attachment io.Reader, name string, msg *textsecure.Message) (err error) {
	var output *os.File

	attachmentPath := contact.AttachmentDir

	err = os.MkdirAll(attachmentPath, 0700)

	if err != nil {
		return
	}

	if name == "" {
		output, err = ioutil.TempFile(attachmentPath, "attachment_")
	} else {
		outputPath := filepath.Join(attachmentPath, name)
		output, err = os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)
	}

	if err != nil {
		return
	}
	defer output.Close()

	io.Copy(output, attachment)
	status.Log(syslog.LOG_NOTICE, "saved attachment from %s %s\n", contact.Name, contact.Number)

	name, _ = relativePath(output.Name())
	updateHistory(contact, "["+name+"]", "<", msg.Timestamp())

	return
}

func parseContact(path string) (contact contactInfo, err error) {
	contactPattern := regexp.MustCompile("^" + contactsPath() + "/(([^/]*) ((?:\\+|00)[0-9]+))\\." + contactExt + "$")
	m := contactPattern.FindStringSubmatch(path)

	if len(m) == 0 {
		err = errors.New("invalid contact")
		return
	}

	// detect path traversal
	_, err = absolutePath(path)

	if err != nil {
		return
	}

	contact = contactInfo{
		Name:          m[2],
		Number:        m[3],
		HistoryPath:   path,
		AttachmentDir: filepath.Join(attachmentsPath(), m[1]),
	}

	return
}

func getContact(number string) (contact contactInfo, err error) {
	if !numberPattern.MatchString(number) {
		err = fmt.Errorf("invalid contact number format: %s", number)
		return
	}

	err = os.MkdirAll(contactsPath(), 0700)

	if err != nil {
		return
	}

	contacts, err := filepath.Glob(contactsPath() + "/" + "*" + number + "." + contactExt)

	if err != nil {
		return
	}

	if len(contacts) == 0 {
		contact = contactInfo{
			Name:          "Unknown",
			Number:        number,
			HistoryPath:   filepath.Join(contactsPath(), "Unknown "+number+"."+contactExt),
			AttachmentDir: filepath.Join(attachmentsPath(), "Unknown "+number),
		}
	} else {
		contact, err = parseContact(contacts[0])
	}

	return
}

func updateHistory(contact contactInfo, msg string, prefix string, t time.Time) (err error) {
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
	input, err := os.Open(numberPath())

	if err != nil {
		return
	}
	defer input.Close()

	n, err := ioutil.ReadAll(input)

	if err != nil {
		return
	}

	number = string(n)

	return
}

func (t *textSecure) registerNumber() (err error) {
	dispose := false
	volume := readLine("\nPlease enter encrypted volume name for TextSecure key storage: ")
	disposePrompt := readLine("\nIf you would like to have the password disposed of after use enter YES all\nuppercase: ")

	if disposePrompt == "YES" {
		fmt.Println("\nWARNING: password will be destroyed after its use!\n(quit now if this is undesired)")
		dispose = true
	}

	if !conf.testMode {
		password := readPasswd("Please enter volume password (will not echo): ", true)

		err := authenticate(volume, password, dispose)

		if err != nil {
			_ = luksUnmount()
			_ = luksClose()
			log.Fatal(err)
		}
	}

	if needsRegistration() {
		number := readLine("\nPlease enter the mobile number to be used for TextSecure registration: ")
		output, err := os.OpenFile(numberPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

		if err != nil {
			log.Fatalf("failed to save number: %v", err)
		}

		output.Write([]byte(number))
		output.Close()
	} else {
		n, _ := registeredNumber()

		if !conf.testMode {
			_ = luksUnmount()
			_ = luksClose()
		}

		log.Fatalf("TextSecure registration already present for number %s, delete %s contents to reset.", n, storagePath())
	}

	err = t.setupClient()

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("TextSecure registration successful, locking volume and shutting down. Please restart to apply registration.")

	if !conf.testMode {
		_ = luksUnmount()
		_ = luksClose()
	}

	return
}

func (t *textSecure) setupClient() (err error) {
	err = os.MkdirAll(storagePath(), 0700)

	if err != nil {
		return
	}

	t.number, err = registeredNumber()

	if err != nil {
		return errors.New("TextSecure cipher enabled but not registered, please restart with -r flag for registration.")
	}

	t.client = &textsecure.Client{
		GetConfig:           t.getConfig,
		GetVerificationCode: getVerificationCode,
		GetStoragePassword:  getStoragePassword,
		MessageHandler:      messageHandler,
		RegistrationDone:    t.registrationDone,
	}

	err = textsecure.Setup(t.client)

	if err != nil {
		return fmt.Errorf("failed to enable TextSecure cipher: %v", err)
	}

	return
}

func storagePath() string {
	return filepath.Join(conf.mountPoint, conf.KeyPath, "textsecure", "private")
}

func contactsPath() string {
	return filepath.Join(conf.mountPoint, "textsecure", "contacts")
}

func attachmentsPath() string {
	return filepath.Join(conf.mountPoint, "textsecure", "attachments")
}

func numberPath() string {
	return filepath.Join(storagePath(), "number")
}

func (t *textSecure) registrationDone() {
	log.Printf("TextSecure registration complete for %s\n", t.number)
}

func getVerificationCode() string {
	return readLine("Please enter the TextSecure verification code received over SMS: ")
}

func getStoragePassword() string {
	return ""
}

func (t *textSecure) GenKey(i string, e string) (p string, s string, err error) {
	err = errors.New("cipher does not support key generation")
	return
}

func (t *textSecure) GetKeyInfo(k key) (i string, err error) {
	i = "TextSecure library private data"
	return
}

func (t *textSecure) SetPassword(password string) error {
	return errors.New("cipher does not support passwords")
}

func (t *textSecure) Encrypt(input *os.File, output *os.File, _ bool) error {
	return errors.New("cipher does not support encryption")
}

func (t *textSecure) Decrypt(input *os.File, output *os.File, verify bool) error {
	return errors.New("cipher does not support decryption")
}

func (t *textSecure) Sign(input *os.File, output *os.File) error {
	return errors.New("cipher does not support signin")
}

func (t *textSecure) Verify(input *os.File, signature *os.File) error {
	return errors.New("cipher does not support signature verification")
}
