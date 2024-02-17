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

package unix

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

const SYSTEMFILE string = `
[Unit]
Description=Thor Credential Management Agent
After=syslog.target network.target

[Service]
ExecStart=/usr/bin/thor agent exec
ExecReload=/bin/kill -SIGINT "$MAINPID"
PIDFile=/var/run/thor-agent.pid
Restart=always
RestartSec=120

[Install]
WantedBy=multi-user.target
`

func (s *Service) installService(serviceName string, description string) error {
	var (
		err         error
		channel     chan string = make(chan string)
		service     string      = fmt.Sprintf("%s.service", serviceName)
		servicePath string      = filepath.Join("/usr/lib/systemd/system", service)
	)

	var file *os.File
	{
		defer file.Close()
		if file, err = os.Create(servicePath); err != nil {
			return fmt.Errorf("Unable to create service file: %w", err)
		}

		if _, err = file.WriteString(SYSTEMFILE); err != nil {
			return fmt.Errorf("Unable to write to service file: %w", err)
		}

		if err = file.Sync(); err != nil {
			return fmt.Errorf("Unable to sync service file: %w", err)
		}
	}

	var files []string = []string{service}
	_, _, err = s.systemd.EnableUnitFilesContext(context.Background(), files, false, true)
	if err != nil {
		return fmt.Errorf("Failed to enable the %s service: %v", serviceName, err)
	}

	if err = s.systemd.ReloadContext(context.Background()); err != nil {
		return fmt.Errorf("Failed to reload the Daemon: %v", err)
	}

	_, err = s.systemd.StartUnitContext(context.Background(), service, "replace", channel)
	if err != nil {
		return fmt.Errorf("Failed to start %s service: %v", serviceName, err)
	}
	return nil
}

func (s *Service) removeService(serviceName string) error {
	var (
		err         error
		channel     chan string = make(chan string)
		service     string      = fmt.Sprintf("%s.service", serviceName)
		servicePath string      = filepath.Join("/usr/lib/systemd/system", service)
	)
	_, err = s.systemd.StopUnitContext(context.Background(), service, "replace", channel)
	if err != nil {
		return fmt.Errorf("Failed to stop thor-agent service: %v", err)
	}

	var files []string = []string{service}
	_, err = s.systemd.DisableUnitFilesContext(context.Background(), files, false)
	if err != nil {
		return fmt.Errorf("Failed to disable the thor-agent service: %v", err)
	}

	if err = s.systemd.ReloadContext(context.Background()); err != nil {
		return fmt.Errorf("Failed to reload the Daemon: %v", err)
	}
	if err = os.Remove(servicePath); err != nil {
		return fmt.Errorf("Unable to delete service file %v", err)
	}
	return nil
}
