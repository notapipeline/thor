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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/notapipeline/thor/pkg/agent"
	"github.com/notapipeline/thor/pkg/server"
	log "github.com/sirupsen/logrus"
)

type Cmd interface {
	Init() bool
	Run() int
}

var acceptedCommands = []string{
	"server",
	"agent",
}

func Usage() {
	fmt.Printf("USAGE: %s [COMMAND] [FLAGS]:\n", filepath.Base(os.Args[0]))
	for _, command := range acceptedCommands {
		fmt.Printf("    - %s\n", command)
	}
	fmt.Printf("Run `%s COMMAND -h for usage\n", filepath.Base(os.Args[0]))
}

func SetupLog() {
	var level string = os.Getenv("THOR_LOG")
	switch level {
	case "trace":
		log.SetLevel(log.TraceLevel)
		log.SetReportCaller(true)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "info":
		fallthrough
	default:
		log.SetLevel(log.InfoLevel)
	}
}

func Run(args []string) int {
	SetupLog()
	var instance Cmd
	if len(args) != 0 {
		switch args[0] {
		case "server":
			instance = server.NewServer()
		case "agent":
			instance = agent.NewAgent()
		default:
			Usage()
		}
	}

	if instance != nil && instance.Init() {
		code := instance.Run()
		return code
	}
	return 1
}
