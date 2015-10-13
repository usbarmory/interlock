// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

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
	"net/http"
	"os"
	"strings"
	"time"
)

func startServer() error {
	var err error

	if conf.TLS == "gen" {
		err = generateTLSCerts()
	}

	if err != nil {
		return err
	}

	log.Printf("starting server on %s", conf.BindAddress)

	if conf.TLS != "off" && conf.TLSClientCA != "" {
		certPool := x509.NewCertPool()
		{
			clientCert, err := ioutil.ReadFile(conf.TLSClientCA)

			if err != nil {
				return err
			}

			if ok := certPool.AppendCertsFromPEM(clientCert); !ok {
				log.Fatal("could not parse client certificate authority")
			}
		}

		server := &http.Server{
			Addr: conf.BindAddress,
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  certPool,
			},
		}

		err = server.ListenAndServeTLS(conf.TLSCert, conf.TLSKey)
	} else if conf.TLS != "off" {
		err = http.ListenAndServeTLS(conf.BindAddress, conf.TLSCert, conf.TLSKey, nil)
	} else {
		err = http.ListenAndServe(conf.BindAddress, nil)
	}

	return err
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

	cn := strings.Split(conf.BindAddress, ":")[0]
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<63-1))

	status.Log(syslog.LOG_NOTICE, "generating TLS keypair CN: %s, Serial: % X", cn, serial)

	certTemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"INTERLOCK"},
			OrganizationalUnit: []string{"generateTLSCerts()"},
			CommonName:         cn,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(5, 0, 0),
		SubjectKeyId:       []byte{1, 2, 3, 4, 5},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
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
	ec_b, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(TLSKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ec_b})

	h := sha256.New()
	h.Write(cert)

	status.Log(syslog.LOG_NOTICE, "SHA-256 fingerprint: % X", h.Sum(nil))

	return
}
