package main

import (
	"flag"

	"github.com/ransoni/uchiwa/uchiwa"
	"github.com/ransoni/uchiwa/uchiwa/audit"
	"github.com/ransoni/uchiwa/uchiwa/auth"
	"github.com/ransoni/uchiwa/uchiwa/config"
	"github.com/ransoni/uchiwa/uchiwa/filters"
	"fmt"
)

func main() {
	configFile := flag.String("c", "./config.json", "Full or relative path to the configuration file")
	configDir := flag.String("d", "", "Full or relative path to the configuration directory, or comma delimited directories")
	publicPath := flag.String("p", "public", "Full or relative path to the public directory")
	flag.Parse()

	config := config.Load(*configFile, *configDir)

	u := uchiwa.Init(config)

    fmt.Printf("\nAUTHENTICATION: %s\n", config.Uchiwa.Auth.Driver)

	authentication := auth.New(config.Uchiwa.Auth)
	if config.Uchiwa.Auth.Driver == "simple" {
		authentication.Simple(config.Uchiwa.Users)
	} else if config.Uchiwa.Auth.Driver == "freeipa" {
		fmt.Printf("\n\nAuthenticate with FreeIPA!!\n\n")
		authentication.FreeIPA(config.Uchiwa.User, config.Uchiwa.Pass)
	} else {
		authentication.None()
	}

	// Audit
	audit.Log = audit.LogMock

	// filters
	uchiwa.FilterAggregates = filters.FilterAggregates
	uchiwa.FilterChecks = filters.FilterChecks
	uchiwa.FilterClients = filters.FilterClients
	uchiwa.FilterDatacenters = filters.FilterDatacenters
	uchiwa.FilterEvents = filters.FilterEvents
	uchiwa.FilterStashes = filters.FilterStashes
	uchiwa.FilterSubscriptions = filters.FilterSubscriptions

	uchiwa.FilterGetRequest = filters.GetRequest
	uchiwa.FilterPostRequest = filters.PostRequest
	uchiwa.FilterSensuData = filters.SensuData

	u.WebServer(publicPath, authentication)
}
