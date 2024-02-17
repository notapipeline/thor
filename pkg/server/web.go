package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notapipeline/thor/pkg/config"
	"github.com/pquerna/otp"
	log "github.com/sirupsen/logrus"
)

type Search struct {
	SearchType string
	Password   string
	Email      string
	Namespace  string
	VaultToken string

	Results interface{}
}

type Web struct {
	// Internal
	w  http.ResponseWriter
	r  *http.Request
	ps gin.Params
	// template string

	// Default
	Backlink  string
	Version   string
	Request   *http.Request
	Section   string
	Time      time.Time
	Admin     bool
	SamlM     *samlsp.Middleware
	Saml      config.SamlConfig
	Info      config.Admin
	User      config.User
	Errors    []string
	WebSocket string

	SemanticTheme string
	TempTotpKey   *otp.Key

	Search *Search
}

func NewWeb(c *gin.Context, conf *config.Config) *Web {
	section := strings.Trim(strings.Split(c.Request.RequestURI, "?")[0], "/")
	web := Web{
		w:  c.Writer,
		r:  c.Request,
		ps: c.Params,

		Backlink:    "/",
		Version:     "",
		Request:     c.Request,
		Section:     section,
		Time:        time.Now(),
		SamlM:       conf.Saml.SamlSP,
		Saml:        *conf.Saml,
		TempTotpKey: conf.AdminOTP,
		Search:      &Search{},
		Info:        *conf.Admin,
		Errors:      make([]string, 0),
		WebSocket:   fmt.Sprintf("%s:%d", conf.TLS.HostName, conf.TLS.Port),
	}

	if _, ok := c.Get(sessions.DefaultKey); ok {
		session := sessions.Default(c)
		if session.Get("Admin") != nil {
			web.Admin = session.Get("Admin").(bool)
		}
	}
	return &web
}

func (w *Web) Error(err error) {
	log.Error(err)
	w.Errors = append(w.Errors, err.Error())
}
