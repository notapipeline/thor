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
