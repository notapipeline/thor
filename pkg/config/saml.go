// This file is part of thor (https://github.com/notapipeline/thor).
//
// Copyright (c) 2024 Martin Proffitt <mproffitt@choclab.net>.
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	log "github.com/sirupsen/logrus"
)

type SamlConfig struct {
	IDPMetadata string             `yaml:"idpMetadata"`
	PrivateKey  []byte             `yaml:"privateKey"`
	Certificate []byte             `yaml:"certificate"`
	SamlSP      *samlsp.Middleware `yaml:"-"`
}

func (s *SamlConfig) Configure(hostname string) error {
	log.Infof("Setting up SAML configuration")

	if len(s.IDPMetadata) == 0 {
		return fmt.Errorf("No IDP metadata")
	}
	entity := &saml.EntityDescriptor{}
	err := xml.Unmarshal([]byte(s.IDPMetadata), entity)

	if err != nil && err.Error() == "Expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal([]byte(s.IDPMetadata), entities); err != nil {
			return err
		}

		err = fmt.Errorf("No entity found with IDPSSODescriptor")
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				entity = &entities.EntityDescriptors[i]
				err = nil
			}
		}
	}
	if err != nil {
		return err
	}

	keyPair, err := tls.X509KeyPair(s.Certificate, s.PrivateKey)
	if err != nil {
		return fmt.Errorf("Failed to load SAML keypair: %s", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("Failed to parse SAML certificate: %s", err)
	}

	rootURL := url.URL{
		Scheme: "https",
		Host:   hostname,
		Path:   "/",
	}

	newsp, err := samlsp.New(samlsp.Options{
		URL:               rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       entity,
		CookieName:        SessionCookieNameSSO,
		AllowIDPInitiated: true,
	})

	if err != nil {
		log.Warnf("Failed to configure SAML: %s", err)
		s.SamlSP = nil
		return fmt.Errorf("Failed to configure SAML: %s", err)
	}

	newsp.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat

	s.SamlSP = newsp
	log.Infof("Successfully configured SAML")
	return nil
}

func (c *Config) generateSAMLKeyPair() error {
	// Generate private key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Generate the certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   c.TLS.HostName,
			Organization: []string{"CHOCLAB"},
		},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// Generate private key PEM block.
	c.Saml.PrivateKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Generate certificate PEM block.
	c.Saml.Certificate = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	return c.Save()
}
