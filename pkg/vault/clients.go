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
	"context"
	"fmt"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/aws"
	"github.com/hashicorp/vault/api/auth/azure"
)

func (v *Vault) tokenClient(token, namespace string) (*vault.Client, error) {
	client, err := vault.NewClient(v.config.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	if namespace != "" && namespace != "root" {
		client.SetNamespace(namespace)
	}
	client.SetToken(token)

	return client, nil
}

// Helper function to get the configured client
func (v *Vault) roleClient() (*vault.Client, error) {
	var (
		multiple bool = false
		none     bool = true
	)
	for _, c := range []bool{
		v.config.AppRole == nil,
		v.config.AzureRole == nil,
		v.config.AwsRole == nil,
	} {
		if c {
			none = false
			continue
		}

		if !none && c {
			multiple = true
			break
		}
	}

	var msg string = "One of `AwsRole`, `AzureRole`, `AppRole` must be configured. Please update your configuration file."
	if none {
		return nil, fmt.Errorf(msg)
	} else if multiple {
		msg = fmt.Sprintf("Only %s.", msg)
		return nil, fmt.Errorf(msg)
	}

	if v.config.AppRole != nil {
		return v.appRoleClient()
	}

	if v.config.AzureRole != nil {
		return v.azureRoleClient()
	}

	if v.config.AwsRole != nil {
		return v.awsRoleClient()
	}

	return nil, fmt.Errorf("No vault role configured")
}

func (v *Vault) awsRoleClient() (*vault.Client, error) {
	client, err := vault.NewClient(v.config.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	if v.config.Namespace != "" && v.config.Namespace != "root" {
		client.SetNamespace(v.config.Namespace)
	}

	awsAuth, err := aws.NewAWSAuth(aws.WithRole(v.config.AwsRole.RoleName))
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AWS auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.TODO(), awsAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login to AWS auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}
	return client, nil
}

func (v *Vault) azureRoleClient() (*vault.Client, error) {
	client, err := vault.NewClient(v.config.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	if v.config.Namespace != "" && v.config.Namespace != "root" {
		client.SetNamespace(v.config.Namespace)
	}

	azureAuth, err := azure.NewAzureAuth(v.config.AzureRole.RoleName)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Azure auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.TODO(), azureAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login to Azure auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}
	return client, nil
}

func (v *Vault) appRoleClient() (*vault.Client, error) {
	client, err := vault.NewClient(v.config.VaultConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	if v.config.Namespace != "" && v.config.Namespace != "root" {
		client.SetNamespace(v.config.Namespace)
	}

	var secretID string = v.config.AppRole.SecretId

	if v.config.AppRole.ResponseWrapped {
		unwrappedToken, err := client.Logical().Unwrap(string(secretID))
		if err != nil {
			return nil, fmt.Errorf("unable to unwrap token: %w", err)
		}
		secretID = unwrappedToken.Data["secret_id"].(string)
	}

	roleID := v.config.AppRole.RoleId
	if roleID == "" {
		return nil, fmt.Errorf("no role ID was provided")
	}

	params := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	resp, err := client.Logical().Write("auth/approle/login", params)
	if err != nil {
		return nil, fmt.Errorf("unable to log in with approle: %w", err)
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return nil, fmt.Errorf("login response did not return client token")
	}

	client.SetToken(resp.Auth.ClientToken)
	return client, nil
}
