//go:build !windows
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
