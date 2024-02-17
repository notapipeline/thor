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
