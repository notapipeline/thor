package server

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/notapipeline/thor/pkg/loki"
	log "github.com/sirupsen/logrus"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (server *Server) log(c *gin.Context) {
	server.logChannel = make(chan loki.SimpleMessage)
	defer close(server.logChannel)
	server.logOpen = true

	//Upgrade get request to webSocket protocol
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Errorf("Failed to upgrade websocket: %v", err)
		log.Fatal(err)
	}
	defer ws.Close()

	var (
		l              *loki.Loki
		searchComplete chan bool = make(chan bool)
		done           chan bool = make(chan bool)
		data           struct {
			Hosts []string `json:"hosts"`
		}
	)

	if l, err = loki.NewLoki(server.config.Loki); err != nil {
		server.Error(c, http.StatusInternalServerError, err)
		return
	}

	if err := ws.ReadJSON(&data); err != nil {
		log.Error(err)
		return
	}

	if err := l.ApplicationLogs(data.Hosts, &server.logChannel, searchComplete); err != nil {
		server.Error(c, http.StatusInternalServerError, err)
		return
	}

	go func() {
		for {
			select {
			case logItem := <-server.logChannel:
				log.Infof("%+v", logItem)
				if err = ws.WriteJSON(logItem); err != nil {
					log.Errorf("Write failed: %v", err)
					return
				}
			case <-searchComplete:
				if err = ws.WriteJSON(loki.SimpleMessage{
					Time:    time.Now().Format("2006-01-02 15:04:05"),
					Host:    "thor",
					Message: "Finished rotating password(s)",
				}); err != nil {
					log.Errorf("Write failed: %v", err)
					return
				}

				done <- true
				return
			}
		}
	}()
	<-done
	server.logOpen = false
}
