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
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

/**
 * Config methods for time based one time password
 */

func (c *Config) ResetTotp() (*otp.Key, error) {
	c.Lock()
	defer c.Unlock()

	c.Admin.TotpKey = ""

	if err := c.Save(); err != nil {
		return nil, err
	}

	return c.GenerateTOTP()
}

func (c *Config) GenerateTOTP() (*otp.Key, error) {
	key, err := totp.Generate(
		totp.GenerateOpts{
			Issuer:      c.TLS.HostName,
			AccountName: c.Admin.Email,
		},
	)
	if err != nil {
		return nil, err
	}

	return key, nil
}
