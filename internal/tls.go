// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"log/syslog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func StartServer() (err error) {
	var server *http.Server
	var TLSCert []byte
	var TLSKey []byte

	err = registerHandlers(conf.StaticPath)

	if err != nil {
		return
	}

	if conf.TLS == "gen" {
		err = generateTLSCerts()

		if err != nil {
			return
		}
	}

	if conf.TLS == "off" {
		log.Printf("starting HTTP server on %s", conf.BindAddress)
		return http.ListenAndServe(conf.BindAddress, nil)
	}

	if conf.tlsHSM != nil {
		HSM := conf.tlsHSM.Cipher()

		extHSM := "." + HSM.GetInfo().Extension
		_, err = os.Stat(conf.TLSKey + extHSM)

		// use a previously converted key if found, as tls_key
		// configuration directive might not have been changed
		// by the user
		if err == nil {
			conf.TLSKey += extHSM
		}

		// convert existing plaintext TLSKey file if it is the only one
		// available
		if err != nil && filepath.Ext(conf.TLSKey) != extHSM {
			err = encryptKeyFile(HSM, conf.TLSKey, conf.TLSKey+extHSM)

			if err != nil {
				return
			}

			conf.TLSKey += extHSM
		}

		TLSKey, err = decryptKey(HSM, conf.TLSKey)
	} else {
		TLSKey, err = ioutil.ReadFile(conf.TLSKey)
	}

	if err != nil {
		return
	}

	TLSCert, err = ioutil.ReadFile(conf.TLSCert)

	if err != nil {
		return
	}

	certificate, err := tls.X509KeyPair(TLSCert, TLSKey)

	if err != nil {
		return
	}

	if conf.TLSClientCA != "" {
		var clientCert []byte
		certPool := x509.NewCertPool()

		clientCert, err = ioutil.ReadFile(conf.TLSClientCA)

		if err != nil {
			return
		}

		if ok := certPool.AppendCertsFromPEM(clientCert); !ok {
			log.Fatal("could not parse client certificate authority")
		}

		server = &http.Server{
			Addr: conf.BindAddress,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{certificate},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    certPool,
			},
		}
	} else {
		server = &http.Server{
			Addr: conf.BindAddress,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{certificate},
			},
		}
	}

	log.Printf("starting HTTPS server on %s", conf.BindAddress)
	err = server.ListenAndServeTLS("", "")

	return
}

func generateTLSCerts() (err error) {
	TLSCert, err := os.OpenFile(conf.TLSCert, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0644)

	if err != nil {
		log.Printf("skipping TLS keypair generation: %v", err)
		return nil
	}

	TLSKey, err := os.OpenFile(conf.TLSKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		log.Printf("skipping TLS keypair generation: %v", err)
		return nil
	}

	address := net.ParseIP(strings.Split(conf.BindAddress, ":")[0])
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<63-1))

	status.Log(syslog.LOG_NOTICE, "generating TLS keypair IP: %s, Serial: % X", address.String(), serial)

	certTemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"INTERLOCK"},
			OrganizationalUnit: []string{"generateTLSCerts()"},
			CommonName:         address.String(),
		},
		IPAddresses:        []net.IP{address},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		SubjectKeyId:       []byte{1, 2, 3, 4, 5},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	caTemplate := certTemplate
	caTemplate.SerialNumber = serial
	caTemplate.SubjectKeyId = []byte{1, 2, 3, 4, 6}
	caTemplate.BasicConstraintsValid = true
	caTemplate.IsCA = true
	caTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	caTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, &certTemplate, &caTemplate, pub, priv)

	if err != nil {
		return
	}

	pem.Encode(TLSCert, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	ecb, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(TLSKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})

	h := sha256.New()
	h.Write(cert)

	status.Log(syslog.LOG_NOTICE, "SHA-256 fingerprint: % X", h.Sum(nil))

	return
}

func encryptKeyFile(cipher cipherInterface, src string, dst string) (err error) {
	status.Log(syslog.LOG_NOTICE, "encrypting existing TLS key file")

	input, err := os.Open(src)

	if err != nil {
		return
	}

	output, err := ioutil.TempFile("", "tls_key-hsm")

	if err != nil {
		input.Close()
		return
	}

	err = cipher.Encrypt(input, output, false)

	if err != nil {
		input.Close()
		output.Close()
		return
	}

	input.Close()
	output.Close()

	_ = fileOp(src, "", _delete)
	err = fileOp(output.Name(), dst, _move)

	status.Log(syslog.LOG_NOTICE, "TLS key file %s moved and encrypted to %s\n", src, dst)

	return
}

func decryptKey(cipher cipherInterface, keyPath string) (key []byte, err error) {
	status.Log(syslog.LOG_NOTICE, "decrypting TLS key file")

	input, err := os.Open(keyPath)

	if err != nil {
		return
	}

	stat, err := input.Stat()

	if err != nil {
		return
	}

	r, output, err := os.Pipe()

	if err != nil {
		return
	}

	err = cipher.Decrypt(input, output, false)

	if err != nil {
		return
	}

	// salt (8 bytes) + iv (16 bytes) + hmac (32 bytes) == 56 bytes
	key = make([]byte, stat.Size()-56)
	_, err = r.Read(key)

	return
}
