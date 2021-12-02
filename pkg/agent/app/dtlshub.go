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
