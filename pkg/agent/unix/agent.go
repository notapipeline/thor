//go:build !windows
package unix

import (
	"fmt"
	"os"
	"strings"

	"github.com/coreos/go-systemd/v22/dbus"
	log "github.com/sirupsen/logrus"
	"github.com/notapipeline/thor/pkg/agent/app"
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
		name        string = "thor-agent"
		description string = "Secure credential management"
	)

	if s.systemd, err = dbus.NewSystemdConnection(); err != nil {
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
		s.runService(name)
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
