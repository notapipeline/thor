package server

import (
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/dustin/go-humanize"
	log "github.com/sirupsen/logrus"
	"github.com/notapipeline/thor/pkg/config"
	"golang.org/x/net/publicsuffix"
)

type TplEngine struct {
	config *config.Config
}

func NewTplEngine(config *config.Config) *TplEngine {
	tplEngine := TplEngine{
		config: config,
	}
	return &tplEngine
}

// LoadTemplates : Load HTML template files
func (tplEngine TplEngine) LoadTemplates(paths ...string) *template.Template {
	var err error
	var tpl *template.Template = template.New(paths[0]).Funcs(tplEngine.FuncMap())
	var path string
	var data []byte
	for _, path = range paths {
		data, err = Asset("templates/" + path)
		if err != nil {
			fmt.Println(err)
		}
		var tmp *template.Template
		if tpl == nil {
			tpl = template.New(path)
		}
		if path == tpl.Name() {
			tmp = tpl
		} else {
			tmp = tpl.New(path)
		}
		if _, err = tmp.Parse(string(data)); err != nil {
			log.Error(err)
		}
	}
	return tpl
}

func (tplEngine TplEngine) FuncMap() template.FuncMap {
	return template.FuncMap{
		"hasprefix": strings.HasPrefix,
		"hassuffix": strings.HasSuffix,
		"add": func(a, b int) int {
			return a + b
		},
		"bytes": func(n int64) string {
			return fmt.Sprintf("%.2f GB", float64(n)/1024/1024/1024)
		},
		"date": func(t time.Time) string {
			return t.Format(time.UnixDate)
		},
		"replace": func(input, from, to string) string {
			return strings.Replace(input, from, to, -1)
		},
		"replaceAll": func(input, from, to string) string {
			return strings.ReplaceAll(input, from, to)
		},
		"time": humanize.Time,
		"ssoprovider": func() string {
			if tplEngine.config.Saml.SamlSP == nil {
				return ""
			}
			redirect, err := url.Parse(
				tplEngine.config.Saml.SamlSP.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding),
			)
			if err != nil {
				log.Warnf("SSO redirect invalid URL: %s", err)
				return "unknown"
			}
			domain, err := publicsuffix.EffectiveTLDPlusOne(redirect.Host)
			if err != nil {
				log.Warnf("SSO redirect invalid URL domain: %s", err)
				return "unknown"
			}
			suffix, icann := publicsuffix.PublicSuffix(domain)
			if icann {
				suffix = "." + suffix
			}
			return strings.Title(strings.TrimSuffix(domain, suffix))
		},
	}
}
