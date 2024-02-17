//go:build windows
// +build windows

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

package windows

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/notapipeline/thor/pkg/agent/app"
	"golang.org/x/sys/windows/svc"
)

type Service struct {
	errors chan app.LogItem
	app    *app.App
}

func NewService() *Service {
	service := Service{}
	service.errors = make(chan app.LogItem)
	return &service
}

func (s *Service) ErrorChannel() *chan app.LogItem {
	return &s.errors
}

func (s *Service) Usage(errmsg string) {
	fmt.Fprintf(os.Stderr,
		"%s\n\n"+
			"usage: %s <command>\n"+
			"       where <command> is one of\n"+
			"       install, remove, exec, start, stop, pause or continue.\n",
		errmsg, os.Args[0])
	os.Exit(2)
}

func (s *Service) Run() int {

	var svcName = filepath.Base(os.Args[0])
	var svcNameLong = fmt.Sprintf("%s %s - Vault credential management", svcName, os.Args[1])

	isIntSess, err := svc.IsAnInteractiveSession()
	if err != nil {
		log.Fatalf("failed to determine if we are running in an interactive session: %v", err)
		return 1
	}
	if !isIntSess {
		s.runService(svcName, false)
		return 0
	}

	if len(os.Args) < 3 {
		s.Usage("no command specified")
		return 2
	}

	cmd := strings.ToLower(os.Args[2])
	switch cmd {
	case "exec":
		s.runService(svcName, true)
		return 0
	case "install":
		err = s.installService(svcName, svcNameLong)
	case "remove":
		err = s.removeService(svcName)
	case "start":
		err = s.startService(svcName)
	case "stop":
		err = s.controlService(svcName, svc.Stop, svc.Stopped)
	case "pause":
		err = s.controlService(svcName, svc.Pause, svc.Paused)
	case "continue":
		err = s.controlService(svcName, svc.Continue, svc.Running)
	default:
		s.Usage(fmt.Sprintf("invalid command %s", cmd))
	}
	if err != nil {
		log.Fatalf("failed to %s %s: %v", cmd, svcName, err)
		return 1
	}
	return 0
}
