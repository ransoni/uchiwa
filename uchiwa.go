package main

import (
	"flag"

//<<<<<<< HEAD
	"github.com/ransoni/uchiwa/uchiwa"
	"github.com/ransoni/uchiwa/uchiwa/audit"
	"github.com/ransoni/uchiwa/uchiwa/authentication"
	"github.com/ransoni/uchiwa/uchiwa/authorization"
	"github.com/ransoni/uchiwa/uchiwa/config"
	"github.com/ransoni/uchiwa/uchiwa/filters"
//=======
//	"github.com/ransoni/uchiwa/uchiwa"
//	"github.com/ransoni/uchiwa/uchiwa/audit"
//	"github.com/ransoni/uchiwa/uchiwa/auth"
//	"github.com/ransoni/uchiwa/uchiwa/config"
//	"github.com/ransoni/uchiwa/uchiwa/filters"
	"fmt"
//>>>>>>> origin/FreeIPA_Auth
)


func main() {
	configFile := flag.String("c", "./config.json", "Full or relative path to the configuration file")
	configDir := flag.String("d", "", "Full or relative path to the configuration directory, or comma delimited directories")
	publicPath := flag.String("p", "public", "Full or relative path to the public directory")
	flag.Parse()

	config := config.Load(*configFile, *configDir)

	u := uchiwa.Init(config)

//<<<<<<< HEAD
	auth := authentication.New(config.Uchiwa.Auth)
//	if config.Uchiwa.Auth.Driver == "simple" {
//		auth.Simple(config.Uchiwa.Users)
//=======
//    fmt.Printf("\nAUTHENTICATION: %s\n", config.Uchiwa.Auth.Driver)

//	authentication := auth.New(config.Uchiwa.Auth)
	if config.Uchiwa.Auth.Driver == "simple" {
		auth.Simple(config.Uchiwa.Users)
	} else if config.Uchiwa.Auth.Driver == "freeipa" {
		fmt.Printf("\n\nAuthenticate with FreeIPA!!\n\n")
		auth.FreeIPA(config.Uchiwa.User, config.Uchiwa.Pass)
//>>>>>>> origin/FreeIPA_Auth
	} else {
		auth.None()
	}

	// Audit
	audit.Log = audit.LogMock

	// Authorization
	uchiwa.Authorization = &authorization.Uchiwa{}

	// Filters
	uchiwa.Filters = &filters.Uchiwa{}

	u.WebServer(publicPath, auth)
}
