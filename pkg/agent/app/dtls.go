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

package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/notapipeline/thor/pkg/server"
	"github.com/pion/dtls/v2"
)

func (a *App) lookupThorIPs() []string {
	u, _ := url.Parse(a.config.Agent.ThorAddr)
	var (
		addresses        = make([]string, 0)
		addr      string = strings.Split(u.Host, ":")[0]
	)

	ips, err := net.LookupIP(addr)
	if err != nil {
		*a.errors <- NewLogItem(ERROR, fmt.Sprintf("Failed to lookup thor server IP: %s", err.Error()))
		return addresses
	}
	for _, ip := range ips {
		*a.errors <- NewLogItem(INFO, fmt.Sprintf("Resolved %s from %s", ip.String(), addr))
		addresses = append(addresses, ip.String())
	}
	return addresses
}

func (a *App) contains(list []string, what string) bool {
	for _, item := range list {
		if item == what {
			return true
		}
	}
	return false
}

func (a *App) Dtls() {
	*a.errors <- NewLogItem(INFO, "Starting DTLS Secured UDP Listener")
	var (
		certificate tls.Certificate
		err         error
		hostaddr    string
		addr        *net.UDPAddr
	)

	*a.errors <- NewLogItem(INFO, "Detecting external interface")
	if hostaddr, err = externalIP(); err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
		return
	}
	*a.errors <- NewLogItem(INFO, fmt.Sprintf("Found %s", hostaddr))
	var addresses []string = a.lookupThorIPs()

	*a.errors <- NewLogItem(INFO, "Resolving UDP Address")
	if addr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", hostaddr, server.AGENT_PORT)); err != nil {
		*a.errors <- NewLogItem(ERROR, err.Error())
		return
	}

	*a.errors <- NewLogItem(INFO, "Loading Certificates")
	if certificate, err = LoadSSLCertificates(a.config); err != nil {
		*a.errors <- NewLogItem(INFO, "Creating new certificate")
		if certificate, err = CreateSSLCertificates(hostaddr); err != nil {
			*a.errors <- NewLogItem(ERROR, err.Error())
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Millisecond)
		},
	}

	*a.errors <- NewLogItem(INFO, "Setting up listener")
	listener, err := dtls.Listen("udp", addr, config)
	defer listener.Close()
	a.listening = true

	hub := NewHub()
	go func() {
		*a.errors <- NewLogItem(INFO, "Accepting connections")
		for {
			conn, err := listener.Accept()
			if err != nil {
				*a.errors <- NewLogItem(ERROR, err.Error())
				return
			}
			var addr string = strings.Split(conn.RemoteAddr().String(), ":")[0]
			if !a.contains(addresses, addr) {
				*a.errors <- NewLogItem(
					ERROR,
					fmt.Sprintf("Rejecting connection attempt from %s", addr))
				continue
			}
			hub.Register(conn, a)
		}
	}()
	for {
		select {
		case <-a.Stop:
			hub.Stop()
			return
		}
	}
}

func (a *App) DtlsReadLoop(conn net.Conn, hub *Hub) {
	for {
		var (
			err error
			n   int
		)
		buffer := make([]byte, BUFFER_SIZE)
		n, err = conn.Read(buffer)
		if err, ok := err.(net.Error); ok && !err.Timeout() {
			*a.errors <- NewLogItem(ERROR, err.Error())
			if e := hub.Unregister(conn); e != nil {
				*a.errors <- NewLogItem(ERROR, e.Error())
			}
			continue
		}
		var message string = a.cutBuffer(buffer, n)
		if n > 0 {
			a.parseBuffer(message)
			return
		}
	}
}

func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}
