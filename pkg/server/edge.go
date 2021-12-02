package server

import "github.com/gin-gonic/gin"

type edgeRequest struct {
	ForwardIp           string `json:"for"`
	RegistrationRequest string `json:"registration_request"`
}

type edgeToken struct {
	ForwardIp  string `json:"for"`
	ForwardKey string `json:"forwardKey"`
}

func (server *Server) EdgeRegister(c *gin.Context) {}

func (server *Server) EdgeToken(c *gin.Context) {}
