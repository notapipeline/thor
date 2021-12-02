package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/notapipeline/thor/cmd"
)

func main() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors:   true,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	os.Exit(cmd.Run(os.Args[1:]))
}
