//go:build !windows
package unix

import (
	"context"
	"fmt"
)

func (s *Service) startService(serviceName string) error {
	var (
		channel chan string = make(chan string)
		service string      = fmt.Sprintf("%s.service", serviceName)
		err     error
	)
	_, err = s.systemd.StartUnitContext(context.Background(), service, "replace", channel)
	if err != nil {
		return fmt.Errorf("Failed to start %s service: %v", serviceName, err)
	}
	return nil
}

func (s *Service) stopService(serviceName string) error {
	var (
		channel chan string = make(chan string)
		service string      = fmt.Sprintf("%s.service", serviceName)
		err     error
	)
	_, err = s.systemd.StopUnitContext(context.Background(), service, "replace", channel)
	if err != nil {
		return fmt.Errorf("Failed to start %s service: %v", serviceName, err)
	}
	return nil
}
