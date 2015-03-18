package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type openPGP struct {
	info   cipherInfo
	pubKey *openpgp.Entity
	secKey *openpgp.Entity

	cipherInterface
}

func init() {
	conf.SetAvailableCipher(new(openPGP).Init())
}

func (o *openPGP) Init() (c cipherInterface) {
	o.info = cipherInfo{
		Name:        "OpenPGP",
		Description: "OpenPGP (golang.org/x/crypto/openpgp)",
		KeyFormat:   "armor",
		Enc:         true,
		Dec:         true,
		Sig:         true,
		Extension:   "pgp",
	}

	return o
}

func (o *openPGP) GetInfo() cipherInfo {
	return o.info
}

func (o *openPGP) SetPassword(password string) (err error) {
	if o.secKey == nil {
		err = errors.New("password cannot be set without secret key")
		return
	}

	err = o.secKey.PrivateKey.Decrypt([]byte(password))

	for _, subKey := range o.secKey.Subkeys {
		err = subKey.PrivateKey.Decrypt([]byte(password))
	}

	return
}

func (o *openPGP) SetKey(k key) (err error) {
	keyPath := filepath.Join(conf.mountPoint, k.Path)

	keyFile, err := os.Open(keyPath)
	defer keyFile.Close()

	if err != nil {
		return
	}

	keyBlock, err := armor.Decode(keyFile)

	if err != nil {
		return
	}

	reader := packet.NewReader(keyBlock.Body)
	entity, err := openpgp.ReadEntity(reader)

	if err != nil {
		return
	}

	switch keyBlock.Type {
	case openpgp.PrivateKeyType:
		o.secKey = entity
	case openpgp.PublicKeyType:
		o.pubKey = entity
	default:
		return fmt.Errorf("key type error: %s", keyBlock.Type)
	}

	if err != nil {
		return
	}

	return
}

func (o *openPGP) Encrypt(input *os.File, output *os.File) (err error) {
	hints := &openpgp.FileHints{
		IsBinary: true,
		FileName: input.Name(),
		ModTime:  time.Now(),
	}

	pgpOut, err := openpgp.Encrypt(output, []*openpgp.Entity{o.pubKey}, o.secKey, hints, nil)
	defer pgpOut.Close()

	_, err = io.Copy(pgpOut, input)

	return
}

func (o *openPGP) Decrypt(input *os.File, output *os.File) (err error) {
	keyRing := openpgp.EntityList{}
	keyRing = append(keyRing, o.pubKey)
	keyRing = append(keyRing, o.secKey)

	messageDetails, err := openpgp.ReadMessage(input, keyRing, nil, nil)

	if err != nil {
		return
	}

	_, err = io.Copy(output, messageDetails.UnverifiedBody)

	return
}
