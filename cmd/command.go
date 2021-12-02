package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/notapipeline/thor/pkg/agent"
	"github.com/notapipeline/thor/pkg/server"
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
