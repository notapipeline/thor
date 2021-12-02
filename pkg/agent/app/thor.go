package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"

	"github.com/notapipeline/thor/pkg/config"
	"github.com/notapipeline/thor/pkg/server"
)

type Thor struct {
	hostname  string
	apikey    *string
	namespace string
	paths     []string
	requested bool
}

func NewThor(hostname, namespace string, paths []string, apikey *string) *Thor {
	thor := Thor{
		hostname:  hostname,
		apikey:    apikey,
		namespace: namespace,
		paths:     paths,
		requested: false,
	}
	return &thor
}

func (thor *Thor) Register(c *config.Agent, shasum string, l *chan LogItem) error {
	values := server.RegistrationRequest{
		Registration: thor.publicKey(c),
		Namespace:    thor.namespace,
		ShaSum:       shasum,
	}
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	var endpoint string = fmt.Sprintf("%s/api/v1/register", thor.hostname)
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)
	if status, ok := res["status"].(string); ok {
		switch status {
		case "accepted":
			return nil
		case "rejected":
			return fmt.Errorf("%s", res["message"])
		}
	}
	return fmt.Errorf("Invalid status from registration request")
}

func (thor *Thor) RequestToken() error {
	values := server.TokenRequest{
		Token:     *thor.apikey,
		Namespace: thor.namespace,
		Paths:     thor.paths,
	}
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	var endpoint string = fmt.Sprintf("%s/api/v1/token", thor.hostname)
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)
	if status, ok := res["status"].(string); ok {
		switch status {
		case "accepted":
			thor.requested = true
		case "rejected":
			return fmt.Errorf(res["message"].(string))
		}
	}
	return nil
}

func (thor *Thor) publicKey(c *config.Agent) string {
	var certPath string = filepath.Join(config.DataDir, "certificate.crt")
	if c.TLS != nil {
		if c.TLS.Cacert != "" {
			certPath = c.TLS.Cacert
		}
	}
	if buffer, err := ioutil.ReadFile(certPath); err == nil {
		return string(buffer)
	}
	return ""
}
