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
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/notapipeline/thor/pkg/agent/app"
	log "github.com/sirupsen/logrus"
)

const (
	FAST = 500
	SLOW = 2000
)

func (s *Service) runService(name string) error {
	var err error
	running := time.NewTicker(FAST * time.Millisecond).C
	paused := time.NewTicker(SLOW * time.Millisecond).C

	tick := running
	stop := make(chan bool)
	sig := make(chan os.Signal, 1)
	pause := make(chan bool)
	cont := make(chan bool)
	done := make(chan bool)
	signals := []os.Signal{
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGCONT,
		syscall.SIGSTOP,
	}
	signal.Notify(sig, signals...)

	go func() {
		for {
			select {
			case <-stop:
				log.Info("Shutting down error log channel")
				return
			case err := <-s.errors:
				switch err.Level {
				case app.INFO:
					log.Info(err.Message)
				case app.WARN:
					log.Warning(err.Message)
				case app.ERROR:
					log.Error(err.Message)
				}
			}
		}
	}()

	go func() {
		for s := range sig {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				log.Info("Shutting down listener")
				stop <- true
				time.Sleep(app.Duration)
				done <- true
			case syscall.SIGSTOP:
				pause <- true
			case syscall.SIGCONT:
				cont <- true
			}
		}
	}()
	s.app, err = app.NewApp(&s.errors, os.Args[0])
	if err != nil {
		return fmt.Errorf("Failed setting up main app: %v", err)
	}

	log.Info("App configured, moving into run...")
	go func() {
		for {
			select {
			case <-tick:
				if tick == running {
					s.app.Notify()
				}
			case <-pause:
				tick = paused
			case <-cont:
				tick = running
			}
		}
	}()
	<-done
	return nil
}
