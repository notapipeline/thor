package server

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/autotls"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/notapipeline/thor/pkg/config"
	loki "github.com/notapipeline/thor/pkg/loki"
	"github.com/notapipeline/thor/pkg/vault"
	"golang.org/x/crypto/acme/autocert"
)

type Server struct {
	router      *gin.RouterGroup
	engine      *gin.Engine
	config      *config.Config
	securetoken cookie.Store
	bolt        *bolt.DB
	vault       *vault.Vault
	wakeup      chan string
	stop        chan bool
	logChannel  chan loki.SimpleMessage
	logOpen     bool
}

func NewServer() *Server {
	server := Server{
		logOpen: false,
	}
	var (
		dbname string = filepath.Join(config.DataDir, "thor.db")
		err    error
	)
	server.bolt, err = bolt.Open(dbname, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		log.Error(fmt.Sprintf("Error opening bolt db: %s", err))
		return nil
	}
	server.wakeup = make(chan string)
	server.createBuckets()
	return &server
}

func (server *Server) Init() bool {
	var err error
	mode := os.Getenv("THOR_MODE")
	if mode == "" {
		mode = "production"
	}

	log.Infof("Thor: running in %s mode", mode)
	if mode != "debug" && mode != "trace" {
		gin.SetMode(gin.ReleaseMode)
	}
	gin.DisableConsoleColor()

	if server.config, err = config.NewConfig("config.yaml"); err != nil {
		log.Error("Failed to load config ", err)
		return false
	}

	server.vault = vault.NewVault(server.config.Vault)

	gob.Register(time.Time{})
	gob.Register(config.User{})

	server.securetoken = cookie.NewStore([]byte(config.SessionCookieName))
	server.securetoken.Options(sessions.Options{
		MaxAge:   60 * 60 * 12,
		Secure:   true,
		HttpOnly: true,
		Domain:   server.config.TLS.HostName,
		Path:     "/",
	})

	server.engine = gin.New()
	server.engine.Use(Logger(log.StandardLogger()), gin.Recovery())

	server.router = server.engine.Group("/")
	server.router.Use(sessions.Sessions(config.SessionCookieName, server.securetoken))

	go server.Wakeup()
	log.Info("Thor server initialised")
	return true
}

func (server *Server) Wakeup() {
	for {
		select {
		case namespace := <-server.wakeup:
			if err := server.bolt.View(func(tx *bolt.Tx) error {
				n := tx.Bucket([]byte(namespace))
				c := n.Cursor()
				for k, _ := c.First(); k != nil; k, _ = c.Next() {
					go server.writeto(string(k), "wakeup")
				}
				return nil
			}); err != nil {
				log.Error(err)
			}
		case <-server.stop:
			return
		}
	}
}

func (server *Server) setupRender() multitemplate.Render {
	render := multitemplate.New()

	tplEngine := NewTplEngine(server.config)
	render.Add("index", tplEngine.LoadTemplates("index.html", "header.html", "footer.html"))
	render.Add("configure", tplEngine.LoadTemplates("configure.html", "header.html", "footer.html"))
	render.Add("settings", tplEngine.LoadTemplates("settings.html", "header.html", "footer.html"))
	render.Add("signin", tplEngine.LoadTemplates("signin.html", "header.html", "footer.html"))

	return render
}

func (server *Server) Run() int {
	var (
		err error
	)
	bfs := GetBinFileSystem("static")
	server.engine.Use(static.Serve("/static", bfs))

	server.engine.HTMLRender = server.setupRender()
	server.setupRoutes()

	host := fmt.Sprintf("%s:%d", server.config.TLS.HostName, server.config.TLS.Port)
	log.Infof("Listening on %s", host)

	if server.config.TLS.Cacert != "" && server.config.TLS.Cakey != "" {
		log.Info("Server executing with known cert and key")
		err = server.engine.RunTLS(host, server.config.TLS.Cacert, server.config.TLS.Cakey)
	} else if server.config.TLS.LetsEncrypt {
		log.Info("Server running with LetsEncrypt")
		manager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(server.config.TLS.HostName),
			Cache:      autocert.DirCache(filepath.Join(config.DataDir, "letsencrypt")),
		}
		err = autotls.RunWithManager(server.engine, &manager)
	} else {
		err = server.engine.Run(host)
	}

	if err != nil {
		log.Error("Cannot run server. ", err)
		return 1
	}
	return 0
}
