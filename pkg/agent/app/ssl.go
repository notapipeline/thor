package app

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/notapipeline/thor/pkg/config"
)

const KEYSIZE int = 2048

func LoadSSLCertificates(c *config.Config) (tls.Certificate, error) {
	var (
		certPath string = filepath.Join(config.DataDir, "certificate.crt")
		keyPath  string = filepath.Join(config.DataDir, "certificate.key")
	)
	if c.Agent.TLS != nil {
		if c.Agent.TLS.Cacert != "" && c.Agent.TLS.Cakey != "" {
			certPath = c.Agent.TLS.Cacert
			keyPath = c.Agent.TLS.Cakey
		}
	}

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	return certificate, nil
}

func CreateSSLCertificates(hostname string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, KEYSIZE)
	if err != nil {
		return tls.Certificate{}, err
	}

	var names []string = []string{hostname}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{hostname},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
	}

	publicKey := pubkey(key)
	certificate, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	})

	if err := write(out.String(), filepath.Join(config.DataDir, "certificate.crt")); err != nil {
		return tls.Certificate{}, err
	}

	out.Reset()

	pem.Encode(out, pemblock(key))
	if write(out.String(), filepath.Join(config.DataDir, "certificate.key")); err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certificate},
		PrivateKey:  key,
		Leaf:        &template,
	}, nil
}

func pubkey(key interface{}) interface{} {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

func pemblock(key interface{}) *pem.Block {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	}
	return nil
}

func write(what, where string) error {
	if _, err := os.Stat(where); err != nil {
		if _, err := os.Stat(filepath.Dir(where)); os.IsNotExist(err) {
			os.Mkdir(filepath.Dir(where), 0755)
		}

		file, err := os.Create(where)
		if err != nil {
			return fmt.Errorf("Failed to create %s. %s", where, err)
		}
		defer file.Close()
		if _, err := file.WriteString(what); err != nil {
			return fmt.Errorf("Failed to write key contents for %s. Error was: %s", where, err)
		}
	}
	return nil
}
