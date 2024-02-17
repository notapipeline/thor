//go:build windows
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
