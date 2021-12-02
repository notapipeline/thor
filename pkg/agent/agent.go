package agent

import "github.com/notapipeline/thor/pkg/agent/app"

type Service interface {
	ErrorChannel() *chan app.LogItem
	Run() int
}

type Agent struct {
	errors  *chan app.LogItem
	service Service
}

func NewAgent() *Agent {
	agent := Agent{}
	agent.Init()
	return &agent
}

func (agent *Agent) Run() int {
	return agent.service.Run()
}
