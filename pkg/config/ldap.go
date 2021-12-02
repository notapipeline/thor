package config

type LdapConfig struct {
	Server      string `yaml:"server"`
	Port        int    `yaml:"port"`
	BindAccount string `yaml:"bindAccount"`
	Password    string `yaml:"password"`
	BaseDN      string `yaml:"baseDn"`
	FilterDN    string `yaml:"filterDn"`
}

func (ldap *LdapConfig) Configure() {}
