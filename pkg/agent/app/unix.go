//go:build !windows
package app

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

const LOGOUT_SCRIPT string = `
for id in $(ps -hft $(w | grep [%s]%s | tail -n+1 | awk '{print $2}') | grep [-]bash | awk '{print $1}'); do
echo Killing ${id}
kill -SIGKILL ${id}
done
`

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
	*a.errors <- NewLogItem(INFO, fmt.Sprintf("Password changed for %s - %s", username, string(response)))
	a.logout(username)
}

func (a *App) logout(username string) {
	var file string = "/tmp/thor-logout.sh"
	os.Remove(file)
	f, err := os.Create(file)
	if err != nil {
		return
	}
	f.WriteString(fmt.Sprintf(LOGOUT_SCRIPT, string(username[0]), username[1:]))
	f.Close()
	var (
		response []byte
		args     []string = []string{
			"-l",
			file,
		}
	)
	cmd := exec.Command("bash", args...)
	if response, err = cmd.CombinedOutput(); err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
		if response != nil {
			*a.errors <- NewLogItem(ERROR, string(response))
		}
		return
	}
	os.Remove(file)
	*a.errors <- NewLogItem(INFO, fmt.Sprintf("%s logged out - %s", username, string(response)))
}
