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

package server

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notapipeline/thor/pkg/config"
	log "github.com/sirupsen/logrus"
)

var (
	validEmail    = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword = regexp.MustCompile(`^[ -~]{6,200}$`)
	// validString   = regexp.MustCompile(`^[ -~]{1,200}$`)
)

func (server *Server) RequireAccount(c *gin.Context) {
	if !server.config.Configured {
		log.Debug("Routing to configurator")
		c.Redirect(http.StatusFound, "/configure")
		return
	}

	section := strings.Trim(strings.Split(c.Request.RequestURI, "?")[0], "/")
	if section == "signin" || section == "signout" {
		return
	}

	current := sessions.Default(c)
	if current == nil {
		log.Warnf("No session set for %s", c.Request.URL)
		c.Redirect(http.StatusFound, "/signin")
		return
	}

	// user has valid session
	if err := server.ValidateSession(current); err == nil {
		return
	}

	samlSP := server.config.Saml.SamlSP
	if samlSP != nil {
		active := sessions.Default(c)
		if active != nil {
			session, err := samlSP.Session.GetSession(c.Request)
			if err != nil {
				log.Debugf("SAML: Unable to get session from requests: %+v", err)
			}

			if session != nil {
				jwtSessionClaims, ok := session.(samlsp.JWTSessionClaims)
				if !ok {
					server.Error(c, http.StatusInternalServerError, fmt.Errorf("Unable to decode session into JWTSessionClaims"))
					return
				}

				email := jwtSessionClaims.Subject
				if email == "" {
					server.Error(c, http.StatusInternalServerError, fmt.Errorf("SAML: Missing token: email"))
					return
				}

				user := &config.User{
					Email:  email,
					Groups: jwtSessionClaims.Attributes["Groups"],
				}
				if err := server.signinSession(user, c); err != nil {
					server.Error(c, http.StatusInternalServerError, err)
				}
				return
			}
		}
	}

	c.Redirect(http.StatusFound, "/signin")
}

func (server *Server) ValidateSession(session sessions.Session) error {
	if session.Get("NotBefore") == nil || time.Now().Before(session.Get("NotBefore").(time.Time)) {
		return fmt.Errorf("Invalid session (before valid)")
	}

	if session.Get("NotAfter") == nil || time.Now().After(session.Get("NotAfter").(time.Time)) {
		return fmt.Errorf(
			"Invalid session (expired session is %s and now is %s)",
			session.Get("NotAfter").(time.Time),
			time.Now())
	}
	return nil
}
