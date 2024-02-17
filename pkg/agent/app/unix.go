//go:build !windows

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
	"io"
	"os/exec"
)

const LOGOUT_SCRIPT string = `x=($(ps -Ao pid,tt,user | awk '/%s/{print $1}')); { [ ${#x[@]} -gt 0 ] && kill -SIGKILL ${x[@]}; } || echo`

func (a *App) setPassword(username, password string) {
	var (
		err      error
		stdin    io.WriteCloser
		response []byte
	)

	cmd := exec.Command("chpasswd")
	if stdin, err = cmd.StdinPipe(); err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
		return
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, fmt.Sprintf("%s:%s\n", username, password))
	}()

	if response, err = cmd.CombinedOutput(); err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
		if response != nil {
			*a.errors <- NewLogItem(ERROR, string(response))
		}
		return
	}
	*a.errors <- NewLogItem(INFO, fmt.Sprintf("Password changed for %s. %s", username, string(response)))
	a.logout(username)
}

func (a *App) logout(username string) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(LOGOUT_SCRIPT, username))
	if response, err := cmd.CombinedOutput(); err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
		if response != nil {
			*a.errors <- NewLogItem(ERROR, string(response))
		}
		return
	}
	*a.errors <- NewLogItem(INFO, fmt.Sprintf("%s logged out if it was logged in.", username))
}
