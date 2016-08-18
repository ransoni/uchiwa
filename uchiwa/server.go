package uchiwa

import (
    "compress/gzip"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"

    "github.com/ransoni/uchiwa/uchiwa/authentication"
    "github.com/ransoni/uchiwa/uchiwa/authorization"
    "github.com/ransoni/uchiwa/uchiwa/filters"
    "github.com/ransoni/uchiwa/uchiwa/logger"
    "github.com/ransoni/uchiwa/uchiwa/structs"

    "github.com/dgrijalva/jwt-go"
    "reflect"
)

// Authorization contains the available authorization methods
var Authorization authorization.Authorization

// Filters contains the available filters for the Sensu data
var Filters filters.Filters

// aggregateHandler serves the /aggregates/:check/:issued endpoint
func (u *Uchiwa) aggregateHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    resources := strings.Split(r.URL.Path, "/")
    if len(resources) < 3 || resources[2] == "" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    name := resources[2]
    token := authentication.GetJWTFromContext(r)

    // Get the datacenter name, passed as a query string
    dc := r.URL.Query().Get("dc")

    if dc == "" {
        checks, err := u.findCheck(name)
        if err != nil {
            http.Error(w, fmt.Sprint(err), http.StatusNotFound)
            return
        }

        visibleChecks := Filters.Checks(&checks, token)

        if len(visibleChecks) > 1 {
            // Create header
            w.Header().Add("Accept-Charset", "utf-8")
            w.Header().Add("Content-Type", "application/json")

            // If GZIP compression is not supported by the client
            w.WriteHeader(http.StatusMultipleChoices)

            if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
                encoder := json.NewEncoder(w)
                if err := encoder.Encode(visibleChecks); err != nil {
                    http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                    return
                }
                return
            }

            w.Header().Add("Content-Encoding", "gzip")
            w.WriteHeader(http.StatusMultipleChoices)

            gz := gzip.NewWriter(w)
            defer gz.Close()
            if err := json.NewEncoder(gz).Encode(visibleChecks); err != nil {
                http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                return
            }

            return
        }

        c, ok := checks[0].(map[string]interface{})
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
        dc, ok = c["dc"].(string)
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
    }

    unauthorized := Filters.GetRequest(dc, token)
    if unauthorized {
        http.Error(w, fmt.Sprint(""), http.StatusNotFound)
        return
    }

    var aggregate *map[string]interface{}
    var err error

    if len(resources) == 3 {
        aggregate, err = u.GetAggregate(name, dc)
        if err != nil {
            http.Error(w, fmt.Sprint(err), 500)
            return
        }
    } else {
        issued := resources[3]
        aggregate, err = u.GetAggregateByIssued(name, issued, dc)
        if err != nil {
            http.Error(w, fmt.Sprint(err), 500)
            return
        }
    }

    encoder := json.NewEncoder(w)
    if err := encoder.Encode(aggregate); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }

    return
}

// aggregatesHandler serves the /aggregates endpoint
func (u *Uchiwa) aggregatesHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    token := authentication.GetJWTFromContext(r)
    aggregates := Filters.Aggregates(&u.Data.Aggregates, token)
    if len(aggregates) == 0 {
        aggregates = make([]interface{}, 0)
    }

    // Create header
    w.Header().Add("Accept-Charset", "utf-8")
    w.Header().Add("Content-Type", "application/json")

    // If GZIP compression is not supported by the client
    if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
        encoder := json.NewEncoder(w)
        if err := encoder.Encode(aggregates); err != nil {
            http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
            return
        }
        return
    }

    w.Header().Set("Content-Encoding", "gzip")

    gz := gzip.NewWriter(w)
    defer gz.Close()
    if err := json.NewEncoder(gz).Encode(aggregates); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }

    return
}

// checksHandler serves the /checks endpoint
func (u *Uchiwa) checksHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    token := authentication.GetJWTFromContext(r)

    tok, _ := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
        }

        return nil, nil
    })

    tenantDc := tok.Claims["Role"].(map[string]interface{})["Name"]

    checks := Filters.Checks(&u.Data.Checks, token)
    if len(checks) == 0 {
        checks = make([]interface{}, 0)
    }

    ulos := make([]interface{}, 0)
    for _, check := range checks {
        c, ok := check.(map[string]interface{})
        if !ok {
            fmt.Printf("Could not assert... %+v\n", c)
        }
//        fmt.Printf("\n%v", check)
        for k, v := range c {
//            fmt.Printf("\nCHECK: %v, %v\n", k, v)
            if k == "dc" && v == tenantDc {
//                fmt.Printf("\nTenant CHECK: %v, %v\n", k, v)
                ulos = append(ulos, c)
            }
        }
    }
    fmt.Printf("\nULOS: %v (%v)", ulos, len(ulos))

    // Create header
    w.Header().Add("Accept-Charset", "utf-8")
    w.Header().Add("Content-Type", "application/json")

    // If GZIP compression is not supported by the client
    if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
        encoder := json.NewEncoder(w)
        if err := encoder.Encode(ulos); err != nil {
            http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
            return
        }
        return
    }

    w.Header().Set("Content-Encoding", "gzip")

    gz := gzip.NewWriter(w)
    defer gz.Close()
    if err := json.NewEncoder(gz).Encode(ulos); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }
    return
}

// clientHandler serves the /clients/:client(/history) endpoint
func (u *Uchiwa) clientHandler(w http.ResponseWriter, r *http.Request) {
    // We only support DELETE & GET requests
    if r.Method != "DELETE" && r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    token := authentication.GetJWTFromContext(r)

    // Get the client name
    resources := strings.Split(r.URL.Path, "/")
    if len(resources) < 3 || resources[2] == "" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }
    name := resources[2]

    // Get the datacenter name, passed as a query string
    dc := r.URL.Query().Get("dc")

    if dc == "" {
        clients, err := u.findClient(name)
        if err != nil {
            http.Error(w, fmt.Sprint(err), http.StatusNotFound)
            return
        }

        visibleClients := Filters.Clients(&clients, token)

        if len(visibleClients) > 1 {
            // Create header
            w.Header().Add("Accept-Charset", "utf-8")
            w.Header().Add("Content-Type", "application/json")

            // If GZIP compression is not supported by the client
            if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
                w.WriteHeader(http.StatusMultipleChoices)

                encoder := json.NewEncoder(w)
                if err := encoder.Encode(visibleClients); err != nil {
                    http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                    return
                }

                return
            }

            w.Header().Add("Content-Encoding", "gzip")
            w.WriteHeader(http.StatusMultipleChoices)

            gz := gzip.NewWriter(w)
            defer gz.Close()
            if err := json.NewEncoder(gz).Encode(visibleClients); err != nil {
                http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                return
            }

            return
        }

        c, ok := clients[0].(map[string]interface{})
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
        dc, ok = c["dc"].(string)
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
    }

    // Verify that an authenticated user is authorized to access this resource
    unauthorized := Filters.GetRequest(dc, token)
    if unauthorized {
        http.Error(w, fmt.Sprint(""), http.StatusNotFound)
        return
    }

    // DELETE on /clients/:client
    if r.Method == "DELETE" {
        err := u.DeleteClient(dc, name)
        if err != nil {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusAccepted)
        return
    }

    // GET on /clients/:client/history
    if len(resources) == 4 {
        data, err := u.GetClientHistory(dc, name)
        if err != nil {
            http.Error(w, fmt.Sprint(err), http.StatusNotFound)
            return
        }

        encoder := json.NewEncoder(w)
        if err := encoder.Encode(data); err != nil {
            http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
            return
        }

        return
    }

    // GET on /clients/:client
    data, err := u.GetClient(dc, name)
    if err != nil {
        http.Error(w, fmt.Sprint(err), http.StatusNotFound)
        return
    }

    encoder := json.NewEncoder(w)
    if err := encoder.Encode(data); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }

    return
}

// clientsHandler serves the /clients endpoint
func (u *Uchiwa) clientsHandler(w http.ResponseWriter, r *http.Request) {
    // We only support GET requests
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    token := authentication.GetJWTFromContext(r)

    tok, _ := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
        }

        return nil, nil
    })

    tenantDc := tok.Claims["Role"].(map[string]interface{})["Name"]
    fmt.Printf("\nTenantDC: %v", tenantDc)

    clients := Filters.Clients(&u.Data.Clients, token)
    if len(clients) == 0 {
        clients = make([]interface{}, 0)
    }

    //      Filter clients for Tenant
    ulos := make([]interface{}, 0)
    for _, item := range clients {
        c, ok := item.(map[string]interface{})
        if !ok {
            fmt.Printf("Could not assert... %+v\n", c)
        }

        for k, v := range c {
            if k == "dc" && v == tenantDc {
                ulos = append(ulos, c)
            }
        }
    }

    // Create header
    w.Header().Add("Accept-Charset", "utf-8")
    w.Header().Add("Content-Type", "application/json")

    // If GZIP compression is not supported by the client
    if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
        encoder := json.NewEncoder(w)
        if err := encoder.Encode(clients); err != nil {
            http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
            return
        }
        return
    }

    w.Header().Set("Content-Encoding", "gzip")
    gz := gzip.NewWriter(w)
    defer gz.Close()
    if err := json.NewEncoder(gz).Encode(ulos); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }

    return
}

// configHandler serves the /config endpoint
func (u *Uchiwa) configHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    resources := strings.Split(r.URL.Path, "/")

    if len(resources) == 2 {
        encoder := json.NewEncoder(w)
        if err := encoder.Encode(u.PublicConfig); err != nil {
            http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
            return
        }
    } else {
        if resources[2] == "auth" {
            fmt.Fprintf(w, "%s", u.PublicConfig.Uchiwa.Auth.Driver)
        } else {
            http.Error(w, "", http.StatusNotFound)
            return
        }
    }
}

// datacentersHandler serves the /datacenters endpoint
func (u *Uchiwa) datacentersHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    token := authentication.GetJWTFromContext(r)

    tok, _ := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
        }

        return nil, nil
    })

    tenantDc := tok.Claims["Role"].(map[string]interface{})["Name"]

    datacenters := Filters.Datacenters(u.Data.Dc, token)

    // Filter datacenters for tenant
    var outDatacenter []*structs.Datacenter

    for _, dc := range datacenters {
        //        fmt.Printf("\nDatacenter: %v", dc.Name)
        //        itemDc := reflect.ValueOf(dc)
        //        fmt.Printf("\nitemDC: %v", reflect.TypeOf(dc))
        //        fmt.Printf("\nitemDC Value: %v", itemDc)

        if dc.Name == tenantDc {
            outDatacenter = append(outDatacenter, dc)
        }
        //        append([]interface{}{}, c)

        //        for k, v := range itemDc {
        //            fmt.Printf("\n%v: %v", k, v)
        //        }

    }

    // Create header
    w.Header().Add("Accept-Charset", "utf-8")
    w.Header().Add("Content-Type", "application/json")

    // If GZIP compression is not supported by the client
    if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
        encoder := json.NewEncoder(w)
        if err := encoder.Encode(datacenters); err != nil {
            http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
            return
        }
        return
    }

    w.Header().Set("Content-Encoding", "gzip")

    gz := gzip.NewWriter(w)
    defer gz.Close()
    if err := json.NewEncoder(gz).Encode(outDatacenter); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }
    return
}

// eventHandler serves the /events/:client/:check endpoint
func (u *Uchiwa) eventHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "DELETE" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    resources := strings.Split(r.URL.Path, "/")
    if len(resources) != 4 {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    check := resources[3]
    client := resources[2]
    token := authentication.GetJWTFromContext(r)

    // Get the datacenter name, passed as a query string
    dc := r.URL.Query().Get("dc")

    if dc == "" {
        clients, err := u.findClient(client)
        if err != nil {
            http.Error(w, fmt.Sprint(err), http.StatusNotFound)
            return
        }

        visibleClients := Filters.Clients(&clients, token)

        if len(visibleClients) > 1 {
            // Create header
            w.Header().Add("Accept-Charset", "utf-8")
            w.Header().Add("Content-Type", "application/json")

            // If GZIP compression is not supported by the client
            if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
                w.WriteHeader(http.StatusMultipleChoices)

                encoder := json.NewEncoder(w)
                if err := encoder.Encode(visibleClients); err != nil {
                    http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                    return
                }
                return
            }

            w.Header().Add("Content-Encoding", "gzip")
            w.WriteHeader(http.StatusMultipleChoices)

            gz := gzip.NewWriter(w)
            defer gz.Close()
            if err := json.NewEncoder(gz).Encode(visibleClients); err != nil {
                http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                return
            }

            return
        }

        c, ok := clients[0].(map[string]interface{})
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
        dc, ok = c["dc"].(string)
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
    }

    unauthorized := Filters.GetRequest(dc, token)
    if unauthorized {
        http.Error(w, fmt.Sprint(""), http.StatusNotFound)
        return
    }

    // DELETE on /events/:client/:check
    err := u.ResolveEvent(check, client, dc)
    if err != nil {
        http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusAccepted)
    return
}

// eventsHandler serves the /events endpoint
func (u *Uchiwa) eventsHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    token := authentication.GetJWTFromContext(r)

    tok, _ := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
        }

        return nil, nil
    })

    tenantDc := tok.Claims["Role"].(map[string]interface{})["Name"]

    events := Filters.Events(&u.Data.Events, token)
    if len(events) == 0 {
        events = make([]interface{}, 0)
    }

    ulos := make([]interface{}, 0)
    for _, event := range events {
        e, ok := event.(map[string]interface{})
        if !ok {
            fmt.Printf("Could not assert... %+v\n", e)
        }
        //            if c["dc"] == "lamaani" {
        //                fmt.Printf("%v\n", c["dc"])
        //            }
        for k, v := range e {
            //                fmt.Printf("Key: %v, Value: %v", k, v)
            if k == "dc" && v == tenantDc {
                //                    fmt.Printf("IF?\n")
                ulos = append(ulos, e)
            }
        }
        // else {
        //   ulos = append(ulos, c)
        //}

    }

    // Create header
    w.Header().Add("Accept-Charset", "utf-8")
    w.Header().Add("Content-Type", "application/json")

    // If GZIP compression is not supported by the client
    if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
        encoder := json.NewEncoder(w)
        if err := encoder.Encode(events); err != nil {
            http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
            return
        }
        return
    }

    w.Header().Set("Content-Encoding", "gzip")

    gz := gzip.NewWriter(w)
    defer gz.Close()
    if err := json.NewEncoder(gz).Encode(ulos); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }

    return
}

// healthHandler serves the /health endpoint
func (u *Uchiwa) healthHandler(w http.ResponseWriter, r *http.Request) {
    encoder := json.NewEncoder(w)
    var err error
    if r.URL.Path[1:] == "health/sensu" {
        err = encoder.Encode(u.Data.Health.Sensu)
    } else if r.URL.Path[1:] == "health/uchiwa" {
        err = encoder.Encode(u.Data.Health.Uchiwa)
    } else {
        err = encoder.Encode(u.Data.Health)
    }

    if err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }
}

// metricsHandler serves the /metrics endpoint
func (u *Uchiwa) metricsHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    fmt.Printf("\nMetrics Type: %v\n", reflect.TypeOf(&u.Data.Metrics))

    var outMetrics []*structs.Metrics
    fmt.Printf("\noutMetrics: %v", outMetrics)

    encoder := json.NewEncoder(w)
    if err := encoder.Encode(&u.Data.Metrics); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }
}

// requestHandler serves the /request endpoint
func (u *Uchiwa) requestHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    decoder := json.NewDecoder(r.Body)
    var data structs.CheckExecution
    err := decoder.Decode(&data)
    if err != nil {
        http.Error(w, "Could not decode body", http.StatusInternalServerError)
        return
    }

    // verify that the authenticated user is authorized to access this resource
    token := authentication.GetJWTFromContext(r)
    unauthorized := Filters.GetRequest(data.Dc, token)
    if unauthorized {
        http.Error(w, fmt.Sprint(""), http.StatusNotFound)
        return
    }

    err = u.IssueCheckExecution(data)
    if err != nil {
        http.Error(w, "", http.StatusNotFound)
        return
    }

    return
}

// resultsHandler serves the /results/:client/:check endpoint
func (u *Uchiwa) resultsHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "DELETE" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    resources := strings.Split(r.URL.Path, "/")
    if len(resources) != 4 {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    check := resources[3]
    client := resources[2]
    token := authentication.GetJWTFromContext(r)

    // Get the datacenter name, passed as a query string
    dc := r.URL.Query().Get("dc")

    if dc == "" {
        clients, err := u.findClient(client)
        if err != nil {
            http.Error(w, fmt.Sprint(err), http.StatusNotFound)
            return
        }

        visibleClients := Filters.Clients(&clients, token)

        if len(visibleClients) > 1 {
            // Create header
            w.Header().Add("Accept-Charset", "utf-8")
            w.Header().Add("Content-Type", "application/json")

            // If GZIP compression is not supported by the client
            if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
                w.WriteHeader(http.StatusMultipleChoices)

                encoder := json.NewEncoder(w)
                if err := encoder.Encode(visibleClients); err != nil {
                    http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                    return
                }
                return
            }

            w.Header().Add("Content-Encoding", "gzip")
            w.WriteHeader(http.StatusMultipleChoices)

            gz := gzip.NewWriter(w)
            defer gz.Close()
            if err := json.NewEncoder(gz).Encode(visibleClients); err != nil {
                http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                return
            }

            return
        }

        c, ok := clients[0].(map[string]interface{})
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
        dc, ok = c["dc"].(string)
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
    }

    unauthorized := Filters.GetRequest(dc, token)
    if unauthorized {
        http.Error(w, fmt.Sprint(""), http.StatusNotFound)
        return
    }

    err := u.DeleteCheckResult(check, client, dc)
    if err != nil {
        http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusAccepted)
    return
}

// stashHandler serves the /stashes/:path endpoint
func (u *Uchiwa) stashHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "DELETE" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    resources := strings.Split(r.URL.Path, "/")
    if len(resources) < 2 || resources[2] == "" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    path := strings.Join(resources[2:], "/")
    token := authentication.GetJWTFromContext(r)

    // Get the datacenter name, passed as a query string
    dc := r.URL.Query().Get("dc")

    if dc == "" {
        stashes, err := u.findStash(path)
        if err != nil {
            http.Error(w, fmt.Sprint(err), http.StatusNotFound)
            return
        }

        visibleStashes := Filters.Stashes(&stashes, token)

        if len(visibleStashes) > 1 {
            // Create header
            w.Header().Add("Accept-Charset", "utf-8")
            w.Header().Add("Content-Type", "application/json")

            // If GZIP compression is not supported by the client
            if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
                w.WriteHeader(http.StatusMultipleChoices)

                encoder := json.NewEncoder(w)
                if err := encoder.Encode(visibleStashes); err != nil {
                    http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                    return
                }
                return
            }

            w.Header().Add("Content-Encoding", "gzip")
            w.WriteHeader(http.StatusMultipleChoices)

            gz := gzip.NewWriter(w)
            defer gz.Close()
            if err := json.NewEncoder(gz).Encode(visibleStashes); err != nil {
                http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                return
            }

            return
        }

        c, ok := stashes[0].(map[string]interface{})
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
        dc, ok = c["dc"].(string)
        if !ok {
            http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
            return
        }
    }

    unauthorized := Filters.GetRequest(dc, token)
    if unauthorized {
        http.Error(w, fmt.Sprint(""), http.StatusNotFound)
        return
    }

    err := u.DeleteStash(dc, path)
    if err != nil {
        logger.Warningf("Could not delete the stash '%s': %s", path, err)
        http.Error(w, "Could not create the stash", http.StatusNotFound)
        return
    }

    w.WriteHeader(http.StatusAccepted)
    return
}

// stashesHandler serves the /stashes endpoint
func (u *Uchiwa) stashesHandler(w http.ResponseWriter, r *http.Request) {
    token := authentication.GetJWTFromContext(r)

    if r.Method == "GET" || r.Method == "HEAD" {
        // GET on /stashes
        stashes := Filters.Stashes(&u.Data.Stashes, token)
        if len(stashes) == 0 {
            stashes = make([]interface{}, 0)
        }

        // Create header
        w.Header().Add("Accept-Charset", "utf-8")
        w.Header().Add("Content-Type", "application/json")

        // If GZIP compression is not supported by the client
        if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
            encoder := json.NewEncoder(w)
            if err := encoder.Encode(stashes); err != nil {
                http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
                return
            }
            return
        }

        w.Header().Set("Content-Encoding", "gzip")

        gz := gzip.NewWriter(w)
        defer gz.Close()
        if err := json.NewEncoder(gz).Encode(stashes); err != nil {
            http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
            return
        }

        return
    } else if r.Method == "POST" {
        // POST on /stashes
        decoder := json.NewDecoder(r.Body)
        var data stash
        err := decoder.Decode(&data)
        if err != nil {
            http.Error(w, "Could not decode body", http.StatusInternalServerError)
            return
        }

        // verify that the authenticated user is authorized to access this resource
        unauthorized := Filters.GetRequest(data.Dc, token)
        if unauthorized {
            http.Error(w, fmt.Sprint(""), http.StatusNotFound)
            return
        }

        if token != nil && token.Claims["Username"] != nil {
            data.Content["username"] = token.Claims["Username"]
        }

        err = u.PostStash(data)
        if err != nil {
            http.Error(w, "Could not create the stash", http.StatusNotFound)
            return
        }
    } else {
        http.Error(w, "", http.StatusBadRequest)
        return
    }
}

// subscriptionsHandler serves the /subscriptions endpoint
func (u *Uchiwa) subscriptionsHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" && r.Method != "HEAD" {
        http.Error(w, "", http.StatusBadRequest)
        return
    }

    token := authentication.GetJWTFromContext(r)
    subscriptions := Filters.Subscriptions(&u.Data.Subscriptions, token)
    if len(subscriptions) == 0 {
        subscriptions = make([]string, 0)
    }

    encoder := json.NewEncoder(w)
    if err := encoder.Encode(subscriptions); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
        return
    }
}

// WebServer starts the web server and serves GET & POST requests
func (u *Uchiwa) WebServer(publicPath *string, auth authentication.Config) {
    // Private endpoints
    http.Handle("/aggregates", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.aggregatesHandler))))
    http.Handle("/aggregates/", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.aggregateHandler))))
    http.Handle("/checks", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.checksHandler))))
    http.Handle("/clients", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.clientsHandler))))
    http.Handle("/clients/", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.clientHandler))))
    http.Handle("/config", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.configHandler))))
    http.Handle("/datacenters", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.datacentersHandler))))
    http.Handle("/events", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.eventsHandler))))
    http.Handle("/events/", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.eventHandler))))
    http.Handle("/request", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.requestHandler))))
    http.Handle("/results/", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.resultsHandler))))
    http.Handle("/stashes", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.stashesHandler))))
    http.Handle("/stashes/", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.stashHandler))))
    http.Handle("/subscriptions", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.subscriptionsHandler))))
    if u.Config.Uchiwa.Enterprise == false {
        http.Handle("/metrics", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.metricsHandler))))
    }

    // Static files
    http.Handle("/", http.FileServer(http.Dir(*publicPath)))

    // Public endpoints
    http.Handle("/config/", http.HandlerFunc(u.configHandler))
    http.Handle("/health", http.HandlerFunc(u.healthHandler))
    http.Handle("/health/", http.HandlerFunc(u.healthHandler))
    http.Handle("/login", auth.Login())

    listen := fmt.Sprintf("%s:%d", u.Config.Uchiwa.Host, u.Config.Uchiwa.Port)
    logger.Warningf("Uchiwa is now listening on %s", listen)

    if u.Config.Uchiwa.SSL.CertFile != "" && u.Config.Uchiwa.SSL.KeyFile != "" {
        logger.Fatal(http.ListenAndServeTLS(listen, u.Config.Uchiwa.SSL.CertFile, u.Config.Uchiwa.SSL.KeyFile, nil))
    }

    logger.Fatal(http.ListenAndServe(listen, nil))
}