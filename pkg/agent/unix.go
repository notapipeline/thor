//go:build !windows
// +build !windows

package agent

import (
	"github.com/notapipeline/thor/pkg/agent/unix"
)

func (agent *Agent) Init() bool {
	agent.service = unix.NewService()
	agent.errors = agent.service.ErrorChannel()
	return true
}
