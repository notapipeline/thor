package server

import (
	"os"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

/**
 * Routing information
 */
func (server *Server) setupRoutes() {
	// any address on server.engine is reachable without auth
	server.router.Use(server.RequireAccount)
	// Configure SAML if metadata is present.
	log.Info("Checking for SAML configuration")
	if len(server.config.Saml.IDPMetadata) > 0 {
		samlSP := server.config.Saml.SamlSP

		// any address on the router requires account
		server.engine.GET("/sso", server.Sso)
		server.engine.Any("/saml/*action", gin.WrapH(samlSP))
	}

	// Session is only available on the router so we post there.
	server.router.GET("/signin", server.Signin)
	server.router.POST("/signin", server.Signin)

	server.router.POST("/search", server.Search)
	server.router.POST("/rotate", server.Rotate)

	server.engine.GET("/configure", server.Configure)
	server.engine.POST("/configure", server.Configure)

	server.router.GET("/settings", server.Settings)
	server.router.POST("/settings", server.Settings)
	server.router.GET("/totp/image", server.AdminQR)

	server.router.GET("/", server.Index)
	server.router.GET("/signout", server.Signout)

	// probably want to change this to proper versioning in the future
	server.engine.POST("/api/v1/register", server.Register)
	server.engine.POST("/api/v1/token", server.Token)
	server.engine.POST("/api/v1/adddevices", server.AddDevices)
	server.engine.POST("/api/v1/whatsmyip", server.WhatsMyIP) // not convinced I need this
	server.engine.POST("/api/v1/shasum", server.AddShaSum)

	// edge device api calls
	server.engine.POST("/api/v1/edge/register", server.EdgeRegister)
	server.engine.POST("/api/v1/edge/token", server.EdgeToken)

	// test hook - only available if running in debug
	if os.Getenv("THOR_LOG") == "debug" {
		server.engine.POST("/api/v1/decrypt", server.Decrypt)
	}
}
