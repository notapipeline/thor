package app

import (
	"time"

	"github.com/notapipeline/thor/pkg/config"
	"github.com/notapipeline/thor/pkg/vault"
)

type Vault struct {
	token     string
	backend   *vault.Vault
	namespace string
	requested bool
	thor      *Thor
}

func NewVault(address, namespace string) *Vault {
	v := Vault{
		namespace: namespace,
		token:     "",
		requested: false,
	}
	c := config.VaultConfig{
		Address:   address,
		Namespace: namespace,
	}
	c.Configure()

	v.backend = vault.NewVault(&c)
	return &v
}

func (v *Vault) Thor(t *Thor) {
	v.thor = t
}

func (v *Vault) UnwrapWithCheck(what string, requesting *bool) (string, error) {
	// If wrapping token has been used, an error will be
	// returned when trying to unwrap the data inside.
	//
	// This can be leveraged to force re-authentication
	// in case of man in the middle attacks.
	val, err := v.backend.Unwrap(what, v.namespace)
	if *requesting {
		return val, err
	}
	return "", err
}

func (v *Vault) Unwrap(what string) (string, error) {
	// If wrapping token has been used, an error will be
	// returned when trying to unwrap the data inside.
	//
	// This can be leveraged to force re-authentication
	// in case of man in the middle attacks.
	return v.backend.Unwrap(what, v.namespace)
}

func (v *Vault) SetToken(token, key string) error {
	var err error
	token, err = v.Unwrap(token)
	if err != nil {
		v.requested = false
		return err
	}
	v.token = v.backend.Decrypt(token, key)
	return err
}

func (v *Vault) RotationCredentials(paths []string, token string) (map[string]string, error) {
	credentials := make(map[string]string)
	for _, path := range paths {
		c, err := v.backend.Read(path, token, v.namespace)
		if err == nil {
			for k, v := range c {
				// Take the first, skip any overwrites
				if _, ok := credentials[k]; !ok {
					credentials[k] = v
				}
			}
		}
	}
	return credentials, nil
}

func (v *Vault) GetToken() string {
	if v.token == "" {
		if !v.requested {
			v.requestToken()
		}
		// block until token is returned from Thor
		collected := make(chan bool, 1)
		go func() {
			for {
				if v.token != "" {
					collected <- true
				}
				time.Sleep(Duration)
			}
		}()
		<-collected
	}
	return v.token
}

func (v *Vault) requestToken() {
	v.thor.RequestToken()
}
