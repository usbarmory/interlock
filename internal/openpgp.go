// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
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

func (o *openPGP) Init() cipherInterface {
	o.info = cipherInfo{
		Name:        "OpenPGP",
		Description: "OpenPGP (golang.org/x/crypto/openpgp)",
		KeyFormat:   "armor",
		Enc:         true,
		Dec:         true,
		Sig:         true,
		OTP:         false,
		Msg:         false,
		Extension:   "pgp",
	}

	return o
}

func (o *openPGP) New() cipherInterface {
	return new(openPGP).Init()
}

func (o *openPGP) Activate(activate bool) (err error) {
	// no activation required
	return
}

func (o *openPGP) GetInfo() cipherInfo {
	return o.info
}

func (o *openPGP) GenKey(identifier string, email string) (pubKey string, secKey string, err error) {
	buf := bytes.NewBuffer(nil)
	header := map[string]string{
		"Version": fmt.Sprintf("INTERLOCK %s OpenPGP generated key", Revision),
	}

	entity, err := openpgp.NewEntity(identifier, "", email, nil)

	if err != nil {
		return
	}

	encoder, err := armor.Encode(buf, openpgp.PublicKeyType, header)

	if err != nil {
		return
	}

	// we use our own function due to issues in openpgp.Serialize (see Serialize() comments)
	err = serialize(entity, encoder, nil)

	if err != nil {
		return
	}

	encoder.Close()
	pubKey = buf.String()

	buf.Reset()
	encoder, err = armor.Encode(buf, openpgp.PrivateKeyType, header)

	if err != nil {
		encoder.Close()
		return
	}

	err = entity.SerializePrivate(encoder, nil)

	if err != nil {
		return
	}

	encoder.Close()
	secKey = buf.String()

	return
}

func (o *openPGP) GetKeyInfo(k key) (info string, err error) {
	err = o.SetKey(k)

	if err != nil {
		return
	}

	info = fmt.Sprintf("Identifier: %s, Format: %s, Cipher: %s\n", k.Identifier, k.KeyFormat, k.Cipher)

	if k.Private {
		info += getKeyInfo(o.secKey)
	} else {
		info += getKeyInfo(o.pubKey)
	}

	return
}

func (o *openPGP) SetPassword(password string) (err error) {
	if o.secKey == nil {
		return errors.New("password cannot be set without secret key")
	}

	err = o.secKey.PrivateKey.Decrypt([]byte(password))

	for _, subKey := range o.secKey.Subkeys {
		err = subKey.PrivateKey.Decrypt([]byte(password))
	}

	return
}

// workaround for https://github.com/golang/go/issues/15353
func readEntityWithoutExpiredSubkeys(packets *packet.Reader) (entity *openpgp.Entity, err error) {
	var p packet.Packet
	var q []packet.Packet

	for {
		p, err = packets.Next()

		if err == io.EOF {
			break
		}

		switch pkt := p.(type) {
		case *packet.Signature:
			if pkt.SigType == packet.SigTypeSubkeyBinding && pkt.KeyExpired(time.Now()) {
				continue
			}
		}

		q = append(q, p)
	}

	for i := range q {
		packets.Unread(q[len(q)-1-i])
	}

	entity, err = openpgp.ReadEntity(packets)

	return
}

func (o *openPGP) SetKey(k key) (err error) {
	keyPath := filepath.Join(conf.MountPoint, k.Path)
	keyFile, err := os.Open(keyPath)

	if err != nil {
		return
	}
	defer keyFile.Close()

	keyBlock, err := armor.Decode(keyFile)

	if err != nil {
		return
	}

	reader := packet.NewReader(keyBlock.Body)
	entity, err := readEntityWithoutExpiredSubkeys(reader)

	if err != nil {
		return
	}

	switch keyBlock.Type {
	case openpgp.PrivateKeyType:
		if !k.Private {
			return fmt.Errorf("public key detected in private key slot")
		}

		o.secKey = entity
	case openpgp.PublicKeyType:
		if k.Private {
			return fmt.Errorf("private key detected in public key slot")
		}

		o.pubKey = entity
	default:
		return fmt.Errorf("key type error: %s", keyBlock.Type)
	}

	return
}

func (o *openPGP) Encrypt(input *os.File, output *os.File, _ bool) (err error) {
	hints := &openpgp.FileHints{
		IsBinary: true,
		FileName: input.Name(),
		ModTime:  time.Now(),
	}

	// signing is automatically detected if SetKey(secKey) is performed on
	// the *openPGP instance

	pgpOut, err := openpgp.Encrypt(output, []*openpgp.Entity{o.pubKey}, o.secKey, hints, nil)

	if err != nil {
		return
	}
	defer pgpOut.Close()

	_, err = io.Copy(pgpOut, input)

	return
}

func (o *openPGP) Decrypt(input *os.File, output *os.File, verify bool) (err error) {
	keyRing := openpgp.EntityList{}
	keyRing = append(keyRing, o.secKey)

	if o.pubKey != nil {
		keyRing = append(keyRing, o.secKey)
	}

	messageDetails, err := openpgp.ReadMessage(input, keyRing, nil, nil)

	if err != nil {
		return
	}

	_, err = io.Copy(output, messageDetails.UnverifiedBody)

	if err != nil {
		return
	}

	if verify && !(messageDetails.IsSigned && messageDetails.SignatureError == nil) {
		return errors.New("file has been decrypted but signature verification failed")
	}

	return
}

func (o *openPGP) Sign(input *os.File, output *os.File) error {
	return openpgp.ArmoredDetachSign(output, o.secKey, input, nil)
}

func (o *openPGP) Verify(input *os.File, signature *os.File) (err error) {
	keyRing := openpgp.EntityList{}
	keyRing = append(keyRing, o.pubKey)

	_, err = openpgp.CheckArmoredDetachedSignature(keyRing, input, signature)

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

func getKeyInfo(entity *openpgp.Entity) (info string) {
	if entity == nil {
		info += "no entity\n"
		return
	}

	if entity.PrivateKey != nil {
		info += "OpenPGP private key:\n"
	} else {
		creation := entity.PrimaryKey.CreationTime
		algoID := entity.PrimaryKey.PubKeyAlgo
		fingerprint := entity.PrimaryKey.Fingerprint
		keyID := entity.PrimaryKey.KeyIdShortString()
		bitLength, _ := entity.PrimaryKey.BitLength()

		info += "OpenPGP public key:\n"
		info += fmt.Sprintf("  ID: %v\n", keyID)
		info += fmt.Sprintf("  Type: %v/%v\n", bitLength, algoName(algoID))
		info += fmt.Sprintf("  Fingerprint: % X\n", fingerprint)
		info += fmt.Sprintf("  Creation: %v\n", creation)
	}

	info += "  Identities:\n"

	for _, uid := range entity.Identities {
		info += fmt.Sprintf("    %s\n", uid.Name)
	}

	info += "  Subkeys:\n"

	for _, sub := range entity.Subkeys {
		bitLength, _ := sub.PublicKey.BitLength()
		info += fmt.Sprintf("    %v/%v %v [expired: %v]\n", algoName(sub.PublicKey.PubKeyAlgo), bitLength, sub.Sig.CreationTime, sub.Sig.KeyExpired(time.Now()))
	}

	info += "  Revocations:\n"

	for _, rev := range entity.Revocations {
		info += fmt.Sprintf("    %v [reason: %s]\n", rev.CreationTime, rev.RevocationReasonText)
	}

	return
}

// entity.Serialize() does not generate valid encryption keys because of lack
// of self signatures, we adapt SerializePrivate() for public key material.
//
// Additionally we address the fact that NewEntity returns key material not
// compatible with its own package Encrypt function due to lack of the optional
// PreferredHash Signature attribute.
func serialize(e *openpgp.Entity, w io.Writer, config *packet.Config) (err error) {
	err = e.PrimaryKey.Serialize(w)
	if err != nil {
		return
	}
	for _, ident := range e.Identities {
		ident.SelfSignature.PreferredHash = []uint8{8}
		err = ident.UserId.Serialize(w)
		if err != nil {
			return
		}
		err = ident.SelfSignature.SignUserId(ident.UserId.Id, e.PrimaryKey, e.PrivateKey, config)
		if err != nil {
			return
		}
		err = ident.SelfSignature.Serialize(w)
		if err != nil {
			return
		}
	}
	for _, subkey := range e.Subkeys {
		err = subkey.PublicKey.Serialize(w)
		if err != nil {
			return
		}
		err = subkey.Sig.SignKey(subkey.PublicKey, e.PrivateKey, config)
		if err != nil {
			return
		}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return
		}
	}
	return nil
}

func (o *openPGP) GenOTP(timestamp int64) (otp string, exp int64, err error) {
	err = errors.New("cipher does not support OTP generation")
	return
}

func (o *openPGP) HandleRequest(r *http.Request) (res jsonObject) {
	res = notFound()
	return
}
