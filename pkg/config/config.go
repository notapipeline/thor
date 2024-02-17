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
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/pquerna/otp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	SessionCookieName    string = "__thor_session"
	SessionCookieNameSSO string = "__thor_sso_session"
)

type Agent struct {
	VaultAddr string     `yaml:"vaultServer"`
	ThorAddr  string     `yaml:"thorServer"`
	Paths     []string   `yaml:"paths"`
	Namespace string     `yaml:"namespace"`
	TLS       *TlsConfig `yaml:"tls"`
	Edge      bool       `yaml:"edge" default:"false"`
	ApiKey    string     `yaml:"-"`
}

type User struct {
	Admin  bool
	Email  string
	Groups []string
}

type Admin struct {
	Email    string `yaml:"email"`
	Password string `yaml:"password"`
	TotpKey  string `yaml:"totp"`
}

type TlsConfig struct {
	HostName    string `yaml:"hostname"`
	Port        int    `yaml:"port"`
	Cacert      string `yaml:"cacert"`
	Cakey       string `yaml:"cakey"`
	LetsEncrypt bool   `yaml:"letsencrypt"`
}

type Config struct {
	mu             sync.RWMutex
	filename       string
	TLS            *TlsConfig   `yaml:"tls"`
	Vault          *VaultConfig `yaml:"vault"`
	Loki           *LokiConfig  `yaml:"loki"`
	Ldap           *LdapConfig  `yaml:"ldap"`
	Saml           *SamlConfig  `yaml:"saml"`
	Admin          *Admin       `yaml:"admin"`
	Agent          *Agent       `yaml:"agent"`
	Configured     bool         `yaml:"configured"`
	TrustedInbound []string     `yaml:"trustedInbound"`
	AdminOTP       *otp.Key     `yaml:"-"`
}

func NewConfig(filename string) (*Config, error) {
	filename = filepath.Join(DataDir, filename)

	c := &Config{
		filename:   filename,
		Configured: false,
	}

	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("Invalid config file %s: %s", filename, err)
	}

	if c.Vault != nil {
		c.Vault.Configure()
	}

	if c.Loki != nil {
		c.Loki.Configure()
	}

	if c.Ldap != nil {
		c.Ldap.Configure()
	}

	if c.Saml != nil {
		// Configure SAML if available
		if len(c.Saml.IDPMetadata) > 0 {
			if err := c.Saml.Configure(c.TLS.HostName); err != nil {
				log.Warnf("Configuring SAML failed: %s", err)
			}
		}
	}

	if c.TLS != nil && c.Admin != nil {
		if c.AdminOTP, err = c.GenerateTOTP(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Config) Save() error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return Overwrite(c.filename, b, 0644)
}

func (c *Config) Lock() {
	c.mu.Lock()
}

func (c *Config) Unlock() {
	c.mu.Unlock()
}

func (c *Config) RLock() {
	c.mu.RLock()
}

func (c *Config) RUnlock() {
	c.mu.RUnlock()
}

func Overwrite(filename string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), perm); err != nil {
		return err
	}
	return os.Rename(f.Name(), filename)
}
