//go:build windows

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

package app

import (
	"fmt"
	"os"
	"os/exec"

	wapi "github.com/iamacarpet/go-win64api"
)

const LOGOUT_SCRIPT string = `
((quser /server:"localhost" | ? { $_ -match "%s" }) -split ' +')[2] | foreach {
  logoff $_ /server:"localhost"
}
`

func (a *App) setPassword(username, password string) {
	var (
		ok  bool
		err error
	)
	if ok, err = wapi.ChangePassword(username, password); err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
		return
	}

	if !ok {
		*a.errors <- NewLogItem(ERROR, fmt.Sprintf("Failed to change password for %s", username))
		return
	}

	*a.errors <- NewLogItem(INFO, fmt.Sprintf("Password changed for %s", username))

	// Logout all active RDP sessions for that account
	a.logout(username)
}

func (a *App) logout(username string) {
	var file string = "C:\\Windows\\Temp\\thor-logout.ps1"
	os.Remove(file)
	f, err := os.Create(file)
	if err != nil {
		return
	}
	f.WriteString(fmt.Sprintf(LOGOUT_SCRIPT, username))
	f.Close()
	ps, _ := exec.LookPath("powershell.exe")
	var (
		response []byte
		args     []string = []string{
			"-NoProfile",
			"-NonInteractive",
			file,
		}
	)
	cmd := exec.Command(ps, args...)
	if response, err = cmd.CombinedOutput(); err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
		if response != nil {
			*a.errors <- NewLogItem(ERROR, string(response))
		}
		return
	}
	os.Remove(file)
	*a.errors <- NewLogItem(INFO, fmt.Sprintf("%s logged out if it was logged in.", username))
}
