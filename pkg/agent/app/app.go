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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/notapipeline/thor/pkg/config"
)

const (
	BUFFER_SIZE     int = 1024
	BUFFER_SIZE_MAX int = 1048576
	TIME_MAX        int = 10

	INFO  int = 1
	WARN  int = 2
	ERROR int = 3
)

var (
	Duration time.Duration = time.Duration(TIME_MAX) * time.Nanosecond
)

type LogItem struct {
	Level   int
	Message string
}

func NewLogItem(level int, message string) LogItem {
	return LogItem{
		Level:   level,
		Message: message,
	}
}

type App struct {
	Stop       chan bool
	config     *config.Config
	vault      *Vault
	thor       *Thor
	listening  bool
	woken      bool
	errors     *chan LogItem
	requesting bool
	shasum     string
}

func NewApp(errors *chan LogItem, binpath string) (*App, error) {
	*errors <- NewLogItem(INFO, "Loading config")
	config, err := config.NewConfig("agent.yaml")
	if err != nil {
		return nil, err
	}
	*errors <- NewLogItem(INFO, "Configuring app")
	app := App{
		Stop:   make(chan bool),
		config: config,
		vault:  NewVault(config.Agent.VaultAddr, config.Agent.Namespace),
		thor: NewThor(
			config.Agent.ThorAddr,
			config.Agent.Namespace,
			config.Agent.Paths,
			&config.Agent.ApiKey),
		errors:     errors,
		woken:      false,
		requesting: false,
	}
	app.vault.Thor(app.thor)
	if err := app.setShaSum(binpath); err != nil {
		return nil, err
	}
	return &app, nil
}

func (a *App) setShaSum(binpath string) error {
	var (
		executable string
		err        error
		binary     string
		file       *os.File
	)

	if executable, err = os.Executable(); err != nil {
		return err
	}

	if binary, err = filepath.EvalSymlinks(executable); err != nil {
		return err
	}

	if file, err = os.Open(binary); err != nil {
		return err
	}

	defer file.Close()
	handler := sha256.New()
	if _, err := io.Copy(handler, file); err != nil {
		return err
	}

	a.shasum = hex.EncodeToString(handler.Sum(nil))
	return nil
}

func (a *App) Notify() {
	if !a.listening {
		go a.Dtls()
		return
	}

	if a.config.Agent.ApiKey == "" && !a.requesting {
		var err error
		a.requesting = true
		if err = a.thor.Register(a.config.Agent, a.shasum, a.errors); err != nil {
			*a.errors <- NewLogItem(ERROR, err.Error())
			return
		}
	}

	if a.woken && a.config.Agent.ApiKey != "" {
		if err := a.thor.RequestToken(); err != nil {
			*a.errors <- NewLogItem(ERROR, err.Error())
			return
		}
		a.woken = false
	}
}

func (a *App) Rotate() {
	credentials, err := a.vault.RotationCredentials(a.config.Agent.Paths, a.vault.GetToken())
	if err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
	}
	for account, password := range credentials {
		a.setPassword(account, password)
	}
	*a.errors <- NewLogItem(INFO, "Completed rotation")
}

func (a *App) cutBuffer(buffer []byte, size int) string {
	var message string = string(buffer[:size])
	return strings.TrimSpace(message)
}

func (a *App) parseBuffer(value string) {
	var err error
	switch {
	case value == "wakeup":
		*a.errors <- NewLogItem(INFO, "Recieved wakeup")
		a.woken = true
	case value == "reregister":
		*a.errors <- NewLogItem(INFO, "Recieved re-register")
		// If the server goes away during a wakeup call,
		// there's the potential for the agent to get stuck
		// in an un-resolvable state where it thinks it's
		// made a request but never actually does.
		// To resolve this, we set requesting to false
		// so the notify loop can send a fresh request back.
		a.config.Agent.ApiKey = ""
		a.requesting = false
	case value == "standby":
		*a.errors <- NewLogItem(INFO, "Recieved standby")
		time.Sleep(Duration)
	case strings.HasPrefix(value, "key|"):
		*a.errors <- NewLogItem(INFO, "Recieved encryption key")
		value = strings.TrimPrefix(value, "key|")
		a.config.Agent.ApiKey, err = a.vault.UnwrapWithCheck(value, &a.requesting)
		if err != nil {
			*a.errors <- NewLogItem(ERROR, err.Error())
			a.woken = false
			return
		}
		a.requesting = false
	case strings.HasPrefix(value, "tok|"):
		*a.errors <- NewLogItem(INFO, "Recieved encrypted token")
		value = strings.TrimPrefix(value, "tok|")
		if err = a.vault.SetToken(value, a.config.Agent.ApiKey); err != nil {
			*a.errors <- NewLogItem(ERROR, err.Error())
			a.woken = false
			return
		}
		a.Rotate()
	default:
		*a.errors <- NewLogItem(INFO, value)
		a.edgeForward(value)
	}
}

func (a *App) edgeForward(value string) {}
