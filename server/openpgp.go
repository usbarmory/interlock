// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

func (o *openPGP) GetKeyInfo(k key) (info string, err error) {
	err = o.SetKey(k)

	if err != nil {
		return
	}

	if k.Private {
		info = printKeyInformation(o.secKey)
	} else {
		info = printKeyInformation(o.pubKey)
	}

	return
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

func algoName(algo packet.PublicKeyAlgorithm) (name string) {
	switch algo {
	case packet.PubKeyAlgoRSA:
		name = "RSA"
	case packet.PubKeyAlgoRSAEncryptOnly:
		name = "RSA (encrypt only)"
	case packet.PubKeyAlgoRSASignOnly:
		name = "RSA (sign only)"
	case packet.PubKeyAlgoElGamal:
		name = "ElGamal"
	case packet.PubKeyAlgoDSA:
		name = "DSA"
	case packet.PubKeyAlgoECDH:
		name = "ECDH"
	case packet.PubKeyAlgoECDSA:
		name = "ECDSA"
	default:
	}

	return
}

func printKeyInformation(entity *openpgp.Entity) (info string) {
	if entity.PrivateKey != nil {
		info += fmt.Sprintf("OpenPGP private key:\n")
	} else {
		creation := entity.PrimaryKey.CreationTime
		algoId := entity.PrimaryKey.PubKeyAlgo
		fingerprint := entity.PrimaryKey.Fingerprint
		keyId := entity.PrimaryKey.KeyIdShortString()
		bitLength, _ := entity.PrimaryKey.BitLength()

		info += fmt.Sprintf("OpenPGP public key:\n")
		info += fmt.Sprintf("  ID: %v\n", keyId)
		info += fmt.Sprintf("  Type: %v/%v\n", bitLength, algoName(algoId))
		info += fmt.Sprintf("  Fingerprint: % X\n", fingerprint)
		info += fmt.Sprintf("  Creation: %v\n", creation)
	}

	info += fmt.Sprintf("  Identities:\n")

	for _, uid := range entity.Identities {
		info += fmt.Sprintf("    %s\n", uid.Name)
	}

	info += fmt.Sprintf("  Subkeys:\n")

	for _, sub := range entity.Subkeys {
		bitLength, _ := sub.PublicKey.BitLength()
		info += fmt.Sprintf("    %v/%v %v [expired: %v]\n", algoName(sub.PublicKey.PubKeyAlgo), bitLength, sub.Sig.CreationTime, sub.Sig.KeyExpired(time.Now()))
	}

	info += fmt.Sprintf("  Revocations:\n")

	for _, rev := range entity.Revocations {
		info += fmt.Sprintf("    %v [reason: %s]\n", rev.CreationTime, rev.RevocationReasonText)
	}

	return
}
