package config

import (
	vault "github.com/hashicorp/vault/api"
)

type Policy struct {
	ExcludeCharacters string `yaml:"excludeCharacters"`
	Length            int    `yaml:"length"`
}

type VaultConfig struct {
	Address string `yaml:"address"`
	AppRole *struct {
		RoleId              string `yaml:"roleId"`
		SecretId            string `yaml:"secretId"`
		ResponseWrapped     bool   `yaml:"wrapped"`
		InitialisationToken string `yaml:"InitialisationToken"`
	} `yaml:"appRole,omitempty"`
	AzureRole *struct {
		RoleName string `yaml:"role"`
	} `yaml:"azureRole,omitempty"`
	AwsRole *struct {
		RoleName string `yaml:"role"`
	} `yaml:"awsRole,omitempty"`
	Namespace       string  `yaml:"namespace"`
	SecureTokenPath string  `yaml:"securePath"`
	EncryptionKey   string  `yaml:"encryptionkey"`
	PasswordPolicy  *Policy `yaml:"passwordPolicy"`
	//
	// Replaceable is a list of keys likely to be found under
	// a given vault path whose value can/should be replaced by
	// automation.
	//
	// This is only relevant to an Ex-Employee search type.
	Replaceable []string      `yaml:"replaceableKeys"`
	VaultConfig *vault.Config `yaml:"-"`
	TokenPolicy *Policy       `yaml:"-"`
}

func (c *VaultConfig) Configure() {
	c.VaultConfig = vault.DefaultConfig()
	c.VaultConfig.Address = c.Address
	c.TokenPolicy = &Policy{
		ExcludeCharacters: `"\\` + "`" + `'`,
		Length:            32,
	}
}
