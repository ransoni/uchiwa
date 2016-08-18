package config

import (
	"github.com/ransoni/uchiwa/uchiwa/authentication"
//	"github.com/ransoni/uchiwa/uchiwa/auth"
	"github.com/ransoni/uchiwa/uchiwa/structs"
)

// Config struct contains []SensuConfig and UchiwaConfig structs
type Config struct {
	Dashboard *GlobalConfig `json:",omitempty"`
	Sensu     []SensuConfig
	Uchiwa    GlobalConfig
}

// SensuConfig struct contains conf about a Sensu API
type SensuConfig struct {
	Name     string
	Host     string
	Port     int
	Ssl      bool
	Insecure bool
	URL      string
	User     string
	Path     string
	Pass     string
	Timeout  int
}

// GlobalConfig struct contains conf about Uchiwa
type GlobalConfig struct {
	Host       string
	Port       int
	LogLevel   string
	Refresh    int
	Pass       string
	User       string
	Users      []authentication.User
	Audit      Audit
	Auth       structs.Auth
	Db         Db
	Email      Email
	Enterprise bool
	FreeIPA    FreeIPA
	Github     Github
	Gitlab     Gitlab
	Ldap       Ldap
	reCAPTCHA  reCAPTCHA
	SSL        SSL
}

// Audit struct contains the config of the Audit logger
type Audit struct {
	Level   string
	Logfile string
}

// Db struct contains the SQL driver configuration
type Db struct {
	Driver string
	Scheme string
}

// Email struct contains the Email configuration for sending notifications
type Email struct {
	Host         string
	Port         int
	Email        string
	Name         string
	Subject      string
	TemplatePath string
	TemplateFile string
}

// FreeIPA struct contains the FreeIPA driver configuration
type FreeIPA struct {
	Server       string
	Port         int
	Domain       string
	BaseDN       string
	User         string
	Pass         string
	Roles        []authentication.Role
}

// Github struct contains the GitHub driver configuration
type Github struct {
	ClientID     string
	ClientSecret string
	Roles        []authentication.Role
	Server       string
}

// Gitlab struct contains the Gitlab driver configuration
type Gitlab struct {
	ApplicationID string
	Secret        string
	RedirectURL   string
	Roles         []authentication.Role
	Server        string
}

// Ldap struct contains the LDAP driver configuration
type Ldap struct {
	Server               string
	Port                 int
	BaseDN               string
	BindUser             string
	BindPass             string
	Debug                bool
	Dialect              string
	GroupBaseDN          string
	GroupObjectClass     string
	GroupMemberAttribute string
	Insecure             bool
	Roles                []authentication.Role
	Security             string
	UserAttribute        string
	UserBaseDN           string
	UserObjectClass      string
}

// reCAPTCHA struct contains the reCAPTCHA url and key
type reCAPTCHA struct {
	Url        string
	SecretKey  string
}

// SMS struct contains the SMS configuration for sending notifications
type SMS struct {
    Url              string
    User             int
    Pass             string
    NewUserText      string
    ResetPasswdText  string
    TemplatePath     string
    TemplateFile     string
}

// SSL struct contains the path the SSL certificate and key
type SSL struct {
	CertFile string
	KeyFile  string
}

