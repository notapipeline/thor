package server

import (
	"bytes"
	"fmt"
	"image/png"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	b64 "encoding/base64"

	"github.com/crewjam/saml/samlsp"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notapipeline/thor/pkg/config"
	"github.com/notapipeline/thor/pkg/loki"
	"github.com/notapipeline/thor/pkg/vault"
	"github.com/pquerna/otp/totp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// Handler function for the index page
func (server *Server) Index(c *gin.Context) {
	web := NewWeb(c, server.config)

	session := sessions.Default(c)
	var user config.User = config.User{}
	if session.Get("User") != nil {
		user = session.Get("User").(config.User)
	}
	web.User = user
	web.Info = *server.config.Admin

	c.HTML(http.StatusOK, "index", web)
}

func (server *Server) Rotate(c *gin.Context) {
	web := NewWeb(c, server.config)
	request := make(map[string]interface{})

	// This doesn't bind normally due to the checkbox list passed in from the request form
	if err := c.ShouldBind(&request); err != nil {
		request["type"] = c.PostForm("type")
		request["token"] = c.PostForm("token")
		request["password"] = c.PostForm("password")
		request["namespace"] = c.PostForm("namespace")
		request[request["namespace"].(string)] = c.PostFormArray(c.PostForm("namespace") + "[]")
	}

	if c.Request.Method != "POST" || len(request) == 0 {
		c.Redirect(http.StatusFound, "/")
		return
	}

	// Log channel is opened by the websocket
	// which needs to be listening before we write to it.
	for {
		if server.logOpen {
			break
		}
		time.Sleep(100 * time.Nanosecond)
	}

	if token, ok := request["token"].(string); ok {
		namespace := request["namespace"].(string)
		password := request["password"].(string)
		paths := request[namespace].([]string)

		server.logChannel <- loki.SimpleMessage{
			Time:    time.Now().Format("2006-01-02 15:04:05"),
			Host:    "thor",
			Message: "Creating child token",
		}
		if err := server.vault.CreateAndStoreChildCreationToken(token, namespace, paths); err != nil {
			server.Error(c, http.StatusInternalServerError, err)
			return
		}

		current := sessions.Default(c)
		hosts := make([]string, 0)
		for _, p := range paths {
			hosts = append(hosts, filepath.Base(p))
		}
		current.Set("hosts", hosts)

		for _, p := range paths {
			server.logChannel <- loki.SimpleMessage{
				Time:    time.Now().Format("2006-01-02 15:04:05"),
				Host:    "thor",
				Message: fmt.Sprintf("Clearing prior rotation details for %s/%s", namespace, p),
			}

			server.vault.ClearRotation(token, namespace, p)
			if request["type"].(string) == "ex-employee" {
				for _, credential := range server.config.Vault.Replaceable {
					for _, e := range server.vault.Rotate(p, token, credential, namespace, false, &server.logChannel) {
						web.Error(e)
					}
				}
			} else {
				for _, e := range server.vault.Rotate(p, token, password, namespace, true, &server.logChannel) {
					web.Error(e)
				}
			}
		}
		server.wakeup <- request["namespace"].(string)
	}
	c.HTML(http.StatusOK, "index", web)
}

func (server *Server) Search(c *gin.Context) {
	web := NewWeb(c, server.config)
	request := make(map[string]string)
	if err := c.ShouldBind(&request); err != nil {
		server.Error(c, http.StatusInternalServerError, err)
		return
	}

	if c.Request.Method != "POST" || len(request) == 0 {
		c.Redirect(http.StatusFound, "/")
		return
	}

	search := Search{}
	var (
		err error
		l   *loki.Loki
	)
	if l, err = loki.NewLoki(server.config.Loki); err != nil {
		server.Error(c, http.StatusInternalServerError, err)
		return
	}

	var status int = http.StatusOK
	// email search takes precedence...
	if e, ok := request["email"]; ok && e != "" {
		log.Infof("Creating ex-employee search for %s", request["email"])
		search.SearchType = "ex-employee"
		search.Email = request["email"]
		results := make([]loki.Result, 0)
		if err := l.Search(request["email"], &results); err != nil {
			status = http.StatusBadRequest
			web.Error(err)
		}
		log.Infof("Found %d results", len(results))
		search.Results = &results
	} else if _, ok := request["password"]; ok {
		log.Infof("Creating password search to %s", request["namespace"])
		search.SearchType = "password"
		search.Password = request["password"]
		search.Namespace = request["namespace"]
		results := make([]vault.Result, 0)
		if err := server.vault.Search(request["password"], request["token"], request["namespace"], &results); err != nil {
			status = http.StatusBadRequest
			web.Error(err)
		}
		search.Results = &results
	}

	web.Search = &search
	c.HTML(status, "index", web)
}

// Starts the authoriasation flow for Single Signon
func (server *Server) Sso(c *gin.Context) {
	samlSP := server.config.Saml.SamlSP
	session, err := samlSP.Session.GetSession(c.Request)
	if session != nil {
		c.Redirect(http.StatusFound, "/")
		return
	}

	if err == samlsp.ErrNoSession {
		samlSP.HandleStartAuthFlow(c.Writer, c.Request)
		return
	}

	samlSP.OnError(c.Writer, c.Request, err)
}

// Handler function for loading the configuration page
//
// Only accessible when server is first loaded
func (server *Server) Configure(c *gin.Context) {
	if server.config.Configured {
		c.Redirect(http.StatusFound, "/")
		return
	} else if server.isAdminSession(c) {
		c.Redirect(http.StatusFound, "/settings")
		return
	}

	request := make(map[string]string)
	if err := c.ShouldBind(&request); err != nil {
		server.Error(c, http.StatusInternalServerError, err)
		return
	}

	if c.Request.Method == "POST" && len(request) > 0 {
		email := strings.ToLower(strings.TrimSpace(request["email"]))
		emailConfirm := strings.ToLower(strings.TrimSpace(request["email_confirm"]))
		password := request["password"]

		if !validEmail.MatchString(email) || !validPassword.MatchString(password) || email != emailConfirm {
			c.Redirect(http.StatusFound, "/configure?error=invalid")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.Redirect(http.StatusFound, "/configure?error=bcrypt")
			return
		}

		server.config.Admin.Email = email
		server.config.Admin.Password = b64.StdEncoding.EncodeToString(hashedPassword)
		server.config.Configured = true
		if err := server.config.Save(); err != nil {
			c.Redirect(http.StatusFound, "/configure?error=save")
			return
		}

		c.Redirect(http.StatusFound, "/")
		return
	}

	web := NewWeb(c, server.config)
	web.Info = *server.config.Admin
	c.HTML(http.StatusOK, "configure", web)
}

// Handler function for the Admin settings page
func (server *Server) Settings(c *gin.Context) {
	// Only allow server admins access to settings
	if !server.isAdminSession(c) {
		c.Redirect(http.StatusFound, "/")
		return
	}
	request := make(map[string]string)
	if err := c.ShouldBind(&request); err != nil {
		server.Error(c, http.StatusInternalServerError, err)
		return
	}

	if c.Request.Method == "POST" && len(request) > 0 {
		email := strings.ToLower(strings.TrimSpace(request["email"]))
		samlMetadata := strings.TrimSpace(request["saml_metadata"])

		server.config.Admin.Email = email
		server.config.Saml.IDPMetadata = samlMetadata
		if err := server.config.Save(); err != nil {
			c.Redirect(http.StatusFound, "/settings?error=save")
			return
		}

		if len(samlMetadata) > 0 {
			if err := server.config.Saml.Configure(server.config.TLS.HostName); err != nil {
				log.Warnf("Failed to configure SAML %s", err)
				c.Redirect(http.StatusFound, "/settings?error=saml")
				return
			}
		} else {
			server.config.Saml.SamlSP = nil
		}

		currentPassword := request["current_password"]
		newPassword := request["new_password"]
		configPassword, _ := b64.StdEncoding.DecodeString(server.config.Admin.Password)

		if currentPassword != "" || newPassword != "" {
			if !validPassword.MatchString(newPassword) {
				c.Redirect(http.StatusFound, "/settings?error=invalid")
				return
			}

			if err := bcrypt.CompareHashAndPassword(configPassword, []byte(currentPassword)); err != nil {
				c.Redirect(http.StatusFound, "/settings?error=invalid")
				return
			}

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				c.Redirect(http.StatusFound, "/settings?error=bcrypt")
				return
			}

			server.config.Admin.Password = b64.StdEncoding.EncodeToString(hashedPassword)
			if err := server.config.Save(); err != nil {
				c.Redirect(http.StatusFound, "/settings?error=save")
				return
			}
		}

		resetTotp := request["reset_totp"]
		if resetTotp == "true" {
			var err error
			server.config.AdminOTP, err = server.config.ResetTotp()
			if err != nil {
				c.Redirect(http.StatusFound, "/settings?error=totp")
				return
			}
			if err := server.config.Save(); err != nil {
				c.Redirect(http.StatusFound, "/settings?error=save")
				return
			}
			c.Redirect(http.StatusFound, "/settings?success=totp")
			return
		}

		totpCode := request["totp_code"]
		if server.config.Admin.TotpKey == "" && totpCode != "" {
			if !totp.Validate(totpCode, server.config.AdminOTP.Secret()) {
				c.Redirect(http.StatusFound, "/settings?error=totp")
				return
			}
			server.config.Admin.TotpKey = server.config.AdminOTP.Secret()
			if err := server.config.Save(); err != nil {
				c.Redirect(http.StatusFound, "/settings?error=save")
				return
			}
		}
		c.Redirect(http.StatusFound, "/settings?success=settings")
	}

	web := NewWeb(c, server.config)
	web.Info = *server.config.Admin

	c.HTML(http.StatusOK, "settings", web)
}

// Get a QR Code for admin access
func (server *Server) AdminQR(c *gin.Context) {
	web := NewWeb(c, server.config)
	if !web.Admin {
		log.Errorf("Not logged in")
		return
	}

	if server.config.Admin.TotpKey != "" {
		log.Errorf("QR already registered")
		c.Redirect(http.StatusFound, "/")
		return
	}
	var buf bytes.Buffer
	img, err := server.config.AdminOTP.Image(200, 200)
	if err != nil {
		return
	}

	if err := png.Encode(&buf, img); err != nil {
		return
	}
	c.Data(http.StatusOK, "image/png", buf.Bytes())
}

// Display any errors back to the user
func (server *Server) Error(c *gin.Context, code int, err error) {
	log.Error(err)
	c.HTML(code, "error", err.Error())
}

// If we hit a non-session page when we should be in session (e.g. signin)
func (server *Server) shouldRedirect(c *gin.Context) bool {
	if _, ok := c.Get(sessions.DefaultKey); ok {
		session := sessions.Default(c)
		return session.Get("NotAfter") != nil && time.Now().Before(session.Get("NotAfter").(time.Time))
	}
	return false
}

// Helper function to test for admin session
func (server *Server) isAdminSession(c *gin.Context) bool {
	if _, ok := c.Get(sessions.DefaultKey); ok {
		session := sessions.Default(c)
		if session.Get("Admin") != nil {
			return session.Get("Admin").(bool)
		}
	}
	return false
}

// Get the User object from session if session is active
/*func (server *Server) getUserSession(c *gin.Context) *config.User {
	var user *config.User
	if _, ok := c.Get(sessions.DefaultKey); ok {
		session := sessions.Default(c)
		if user, ok = session.Get("User").(*config.User); !ok {
			user = nil
		}
	}
	return user
}*/
