// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go: build windows
// +build windows

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
