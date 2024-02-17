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
