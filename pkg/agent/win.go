//go: build windows
// +build windows
// Windows agent service
//
// This service is designed to periodically poll Vault,
// check whether a local account password has been rotated
// and if so, change the password on the local account.
// It will then update the "rotated" key for the secret
// to remove the account name from the list of comma separated
// values stored at that key

package agent

import (
	"github.com/notapipeline/thor/pkg/agent/windows"
)

func (agent *Agent) Init() bool {
	agent.service = windows.NewService()
	agent.errors = agent.service.ErrorChannel()
	return true
}
