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
	"os"
	"time"

	"github.com/notapipeline/thor/pkg/agent/app"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	FAST      = 500
	SLOW      = 2000
	NOTIFY_AT = 30000
)

var (
	elog debug.Log
)

func (service *Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

	fasttick := time.Tick(FAST * time.Millisecond)
	slowtick := time.Tick(SLOW * time.Millisecond)

	tick := fasttick
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	stop := make(chan bool)

	go func() {
		for {
			select {
			case <-stop:
				elog.Info(1, "Shutting down error log channel")
				return
			case err := <-service.errors:
				switch err.Level {
				case app.INFO:
					elog.Info(1, err.Message)
				case app.WARN:
					elog.Warning(1, err.Message)
				case app.ERROR:
					elog.Error(1, err.Message)
				}
			default:
				time.Sleep(app.Duration)
			}
		}
	}()

	var err error
	if service.app, err = app.NewApp(&service.errors, os.Args[0]); err != nil {
		service.errors <- app.NewLogItem(app.ERROR, fmt.Sprintf("%s service failed setting up main app: %v", "thor", err))
		return
	}

loop:
	for {
		select {
		case <-tick:
			if tick == fasttick {
				service.app.Notify()
			}
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				elog.Info(1, "Shutting down service")
				service.app.Stop <- true
				stop <- true
				break loop
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
				tick = slowtick
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				tick = fasttick
			default:
				elog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func (service *Service) runService(name string, isDebug bool) {
	var err error
	if isDebug {
		elog = debug.New(name)
	} else {
		elog, err = eventlog.Open(name)
		if err != nil {
			return
		}
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("%s: Setting up run", name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}
	elog.Info(1, "App configured, moving into run...")
	err = run(name, service)
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("%s: stopped", name))
}
