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
	"fmt"
	"net"
	"sync"
)

// Hub is a helper to handle one to many chat
type Hub struct {
	conns map[string]net.Conn
	lock  sync.RWMutex
}

// NewHub builds a new hub
func NewHub() *Hub {
	return &Hub{conns: make(map[string]net.Conn)}
}

func (h *Hub) Stop() {
	h.lock.Lock()
	defer h.lock.Unlock()
	for _, v := range h.conns {
		v.Close()
	}
}

// Register adds a new conn to the Hub
func (h *Hub) Register(conn net.Conn, a *App) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.conns[conn.RemoteAddr().String()] = conn
	go a.DtlsReadLoop(conn, h)
}

func (h *Hub) Unregister(conn net.Conn) error {
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.conns, conn.RemoteAddr().String())
	err := conn.Close()
	if err != nil {
		return fmt.Errorf("Failed to disconnect from %s - %v", conn.RemoteAddr(), err)
	}
	return nil
}
