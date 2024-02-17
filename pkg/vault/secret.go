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

package vault

import (
	"fmt"
	"io/ioutil"
	"os"

	vault "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

//
// Handles rotation of the approle-secret ID
//

func (v *Vault) rotateAppRoleSecret() {
	if v.config.AppRole == nil {
		// not using approle
		return
	}
	roleConfig := v.config.AppRole

	if roleConfig.InitialisationToken != "" {
		if roleConfig.RoleId == "" && roleConfig.SecretId == "" {
			v.initialiseAppRole()
		}
	}
}

func (v *Vault) initialiseAppRole() {
	roleConfig := v.config.AppRole

	// initialisation token may be a vault token or a path to file
	var (
		token  []byte = []byte(roleConfig.InitialisationToken)
		err    error
		client *vault.Client
	)

	if _, err = os.Stat(roleConfig.InitialisationToken); err == nil {
		token, err = ioutil.ReadFile(roleConfig.InitialisationToken)
		if err != nil {
			log.Error("Failed to read initialisation token")
			return
		}
		if err = os.Remove(roleConfig.InitialisationToken); err != nil {
			// non-fatal
			log.Error("Failed to delete initialisation token file")
		}
		roleConfig.InitialisationToken = string(token)
	}

	client, err = v.tokenClient(roleConfig.InitialisationToken, v.config.Namespace)
	if err != nil {
		log.Error(err)
		return
	}
	v.handleRotation(client)
}

func (v *Vault) handleRotation(client *vault.Client) {
	var (
		secret *vault.Secret
		err    error
	)
	roleConfig := v.config.AppRole

	if secret, err = client.Logical().Read(v.config.EncryptionKey); err != nil {
		log.Error(err)
		return
	}

	var (
		mount        = "approle"
		name  string = secret.Data["role-name"].(string)
	)

	if m, ok := secret.Data["mount-name"]; ok {
		mount = m.(string)
	}

	if secret, err = client.Logical().Read(fmt.Sprintf("auth/%s/role/%s/role-id", mount, name)); err != nil {
		log.Fatalf("Unable to read role-id: %v", err)
		return
	}
	roleConfig.RoleId = secret.Data["data"].(map[string]interface{})["role-id"].(string)

	var cidrs []string = []string{}
	var config map[string]interface{} = make(map[string]interface{})
	config["cidr_list"] = cidrs
	if secret, err = client.Logical().Write(fmt.Sprintf("auth/%s/role/%s/secret-id", mount, name), config); err != nil {
		log.Fatalf("Unable to create secret id %v", err)
		return
	}
	roleConfig.SecretId = secret.Data["data"].(map[string]interface{})["secret-id"].(string)
}
