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
	"strings"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/notapipeline/thor/pkg/agent/app"
	log "github.com/sirupsen/logrus"
)

type Service struct {
	errors  chan app.LogItem
	systemd *dbus.Conn
	app     *app.App
}

func NewService() *Service {
	service := Service{
		errors: make(chan app.LogItem),
	}
	return &service
}

func (service *Service) ErrorChannel() *chan app.LogItem {
	return &service.errors
}

func (s *Service) Usage(errmsg string) {
	fmt.Fprintf(os.Stderr,
		"%s\n\n"+
			"usage: %s <command>\n"+
			"       where <command> is one of\n"+
			"       install, remove, exec, start, stop.\n",
		errmsg, os.Args[0])
	os.Exit(2)
}

func (s *Service) Run() int {
	var (
		err         error
		name        string          = "thor-agent"
		description string          = "Secure credential management"
		ctx         context.Context = context.Background()
	)

	if s.systemd, err = dbus.NewSystemdConnectionContext(ctx); err != nil {
		log.Errorf("Failed to create dbus connection - %v", err)
		return 1
	}

	if len(os.Args) < 3 {
		s.Usage("no command specified")
		return 2
	}

	cmd := strings.ToLower(os.Args[2])
	switch cmd {
	case "exec":
		if err := s.runService(name); err != nil {
			log.Fatalf("failed to exec %s: %v", name, err)
			return 1
		}
		return 0
	case "install":
		err = s.installService(name, description)
	case "remove":
		err = s.removeService(name)
	case "start":
		err = s.startService(name)
	case "stop":
		err = s.stopService(name)
	default:
		s.Usage(fmt.Sprintf("invalid command %s", cmd))
	}
	if err != nil {
		log.Fatalf("failed to %s %s: %v", cmd, name, err)
		return 1
	}
	return 0

}
