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
//    "github.com/ransoni/uchiwa/uchiwa/helpers"

    "github.com/dgrijalva/jwt-go"
    _ "reflect"
    "net/url"
)

var debug = true

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
        var empty struct{}
//        if err := encoder.Encode(u.PublicConfig); err != nil {
        if err := encoder.Encode(empty); err != nil {
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
        if dc.Name == tenantDc {
            outDatacenter = append(outDatacenter, dc)
        }
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

    tok, _ := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
        }

        return nil, nil
    })

    tenantDc := tok.Claims["Role"].(map[string]interface{})["Name"]

    var err error

    out := &structs.Health{}
    out.Sensu = make(map[string]structs.SensuHealth, 0)
    if r.URL.Path[1:] == "health/sensu" {

        for key, val := range u.Data.Health.Sensu {

            if key == "Lamaani" {
                out.Sensu[key] = val
            }
        }
        err = encoder.Encode(out.Sensu)
//        err = encoder.Encode("{}")
    } else if r.URL.Path[1:] == "health/uchiwa" {
        err = encoder.Encode(u.Data.Health.Uchiwa)
//        err = encoder.Encode("{}")
    } else {
        out.Uchiwa = u.Data.Health.Uchiwa

        for key, val := range u.Data.Health.Sensu {
            if key == tenantDc {
                out.Sensu[key] = val
            }
        }
//        err = encoder.Encode(u.Data.Health)
        err = encoder.Encode(out)
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

    token := authentication.GetJWTFromContext(r)

//    Get Tenant DC from cookie for filtering
    tok, _ := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
        }

        return nil, nil
    })

    tenantDc := tok.Claims["Role"].(map[string]interface{})["Name"]

//  Clients metrics
    clients := Filters.Clients(&u.Data.Clients, token)

    //      Filter clients for metrics
    clientsFiltered := make([]interface{}, 0)
    for _, item := range clients {
        c, ok := item.(map[string]interface{})
        if !ok {
            fmt.Printf("Could not assert... %+v\n", c)
        }

        for k, v := range c {
            if k == "dc" && v == tenantDc {
                clientsFiltered = append(clientsFiltered, c)
            }
        }
    }

    metrics := structs.Metrics{}

    metrics.Clients.Total = len(clientsFiltered)

    for _, c := range clientsFiltered {
        client := c.(map[string]interface{})

        status, ok := client["status"].(int)
        if !ok {
            logger.Warningf("Could not assert this status to an int: %+v", client["status"])
            continue
        }

        if status == 2.0 {
            metrics.Clients.Critical++
            continue
        } else if status == 1.0 {
            metrics.Clients.Warning++
            continue
        } else if status == 0.0 {
            continue
        }
        metrics.Clients.Unknown++
    }

//  Events Metrics
    events := Filters.Events(&u.Data.Events, token)
    if len(events) == 0 {
        events = make([]interface{}, 0)
    }

    filteredEvents := make([]interface{}, 0)
    for _, event := range events {
        e, ok := event.(map[string]interface{})
        if !ok {
            fmt.Printf("Could not assert... %+v\n", e)
        }
        for k, v := range e {
            if k == "dc" && v == tenantDc {
                filteredEvents = append(filteredEvents, e)
            }
        }
    }

    metrics.Events.Total = len(filteredEvents)

    for _, e := range filteredEvents {
        event := e.(map[string]interface{})

        check, ok := event["check"].(map[string]interface{})
        if !ok {
            logger.Warningf("Could not assert this check to an interface: %+v", event["check"])
            continue
        }

        status, ok := check["status"].(float64)
        if !ok {
            logger.Warningf("Could not assert this status to a flot64: %+v", check["status"])
            continue
        }

        if status == 2.0 {
            metrics.Events.Critical++
            continue
        } else if status == 1.0 {
            metrics.Events.Warning++
            continue
        }
        metrics.Events.Unknown++
    }

    datacenters := Filters.Datacenters(u.Data.Dc, token)

    // Filter datacenters for tenant

    for _, dc := range datacenters {
        if dc.Name == tenantDc {
            metrics.Datacenters.Total++
        }
    }

//   Checks Metrics
    checks := Filters.Checks(&u.Data.Checks, token)
//    if len(checks) == 0 {
//        metrics.Checks.Total = make([]interface{}, 0)
//    }

    for _, check := range checks {
        c, ok := check.(map[string]interface{})
        if !ok {
            fmt.Printf("Could not assert... %+v\n", c)
        }
        for k, v := range c {
            if k == "dc" && v == tenantDc {
                metrics.Checks.Total++
            }
        }
    }

//    Stashes Metrics
//    stashes := Filters.Stashes(&u.Data.Stashes, token)

//    if len(stashes) == 0 {
//        metrics.Stashes.Total = make([]interface{}, 0)
//    }

    for _, stash := range Filters.Stashes(&u.Data.Stashes, token) {
        s, ok := stash.(map[string]interface{})
        if !ok {
            fmt.Printf("Could not assert... %+v\n", s)
        }
        for k, v := range s {
            if k == "dc" && v == tenantDc {
                metrics.Stashes.Total++
            }
        }
    }

    encoder := json.NewEncoder(w)
//    if err := encoder.Encode(&u.Data.Metrics); err != nil {
    if err := encoder.Encode(metrics); err != nil {
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

    tok, _ := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
        }

        return nil, nil
    })

    tenantDc := tok.Claims["Role"].(map[string]interface{})["Name"]

    if r.Method == "GET" || r.Method == "HEAD" {
        // GET on /stashes
        stashes := Filters.Stashes(&u.Data.Stashes, token)
        if len(stashes) == 0 {
            stashes = make([]interface{}, 0)
        }

        ulos := make([]interface{}, 0)

        for _, stash := range stashes {
            s, ok := stash.(map[string]interface{})
            if !ok {
                fmt.Printf("Could not assert... %+v\n", s)
            }
            for k, v := range s {
                if k == "dc" && v == tenantDc {
                    ulos = append(ulos, s)
                }
            }
        }

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

// getTenantHandler serves the /tenant endpoint
func (u *Uchiwa) getTenantHandler(w http.ResponseWriter, r *http.Request) {
//    encoder := json.NewEncoder(w)

    fmt.Printf("\n---TENANT HANDLER ---")

    tok, _ := jwt.ParseFromRequest(r, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
        }

        return nil, nil
    })

    tenantDc := tok.Claims["Role"].(map[string]interface{})["Name"]

    // EXTRACT DATA FROM COOKIE
    cookie, _ := r.Cookie("uchiwa_auth")
    cookieValue := "payload="
    cookieValue += cookie.Value

    c, _ := url.ParseQuery(cookieValue)

    var data map[string]interface{}

    json.Unmarshal([]byte(c["payload"][0]), &data)
    // END OF COOKIE HANDLING

    if debug {
        logger.Infof("DEBUG: Org:", tenantDc)
    }

    var tenantOut map[string]string
    tenantOut = make(map[string]string)
//    tenantOut = getTenantInfo(u.PublicConfig, data["Org"].(string))
    tenantOut = u.getTenantInfo(tenantDc.(string))

    if debug {
        logger.Infof("DEBUG: TenantOut:", tenantOut)
    }

    encoder := json.NewEncoder(w)
    if err := encoder.Encode(tenantOut); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
    }
}

// getUserHandler serves the /user endpoint, providing logged in user
func (u *Uchiwa) getUserHandler(w http.ResponseWriter, r *http.Request) {
    var data map[string]interface{}

    encoder := json.NewEncoder(w)

    // Extract data from cookie
    authCookie, _ := r.Cookie("uchiwa_auth")
    cookieValue := "payload="
    cookieValue += authCookie.Value

    cookie, _ := url.ParseQuery(cookieValue)

    json.Unmarshal([]byte(cookie["payload"][0]), &data)
    fmt.Printf("\nData: %v", data)

    var userOut map[string]string
    userOut = make(map[string]string)
    userOut, _ = u.getUserInfo(data["Org"].(string), data["Email"].(string), data["Username"].(string))

    fmt.Println("TenantOut:", userOut)

    if err := encoder.Encode(userOut); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
    }
}

// getUsersHandler serves the /users endpoint, providing info about organisations users to admin user
func (u *Uchiwa) getUsersHandler(w http.ResponseWriter, r *http.Request) {
    var data map[string]interface{}

    encoder := json.NewEncoder(w)

    if debug {
        fmt.Println("==== USER HANDLER ====\n\n")
    }

    // HAETAAN KEKSISTÄ DATAA
    cookie, _ := r.Cookie("uchiwa_auth")
    cookieValue := "payload="
    cookieValue += cookie.Value

    c, _ := url.ParseQuery(cookieValue)
    //	fmt.Println("C:", c)

    json.Unmarshal([]byte(c["payload"][0]), &data)
    // KEKSIN KÄSITTELY LOPPU

    fmt.Println("ORG:", data["Org"])
    fmt.Println("User email:", data["Email"])

    //	var usersOut map[int]map[string]string
    //	usersOut = make(map[int]map[string]string)
    //userOut = getUserInfo(data["Org"].(string), data["Email"].(string))
    //	conf := PublicConfig
    usersOut, _ := u.getUsers(data["Org"].(string))

    //	FOR TESTING
    /*
        userOut["name"] = "Testi Taina"
        userOut["tel"] = "+358505057890"
        userOut["city"] = "Helsinki"
    */

    fmt.Println("TenantOut:", usersOut)

    //fmt.Println(outResults)
    if err := encoder.Encode(usersOut); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
    }
}

// postAddUserHandler serves /post_user endpoint, which adds user to LDAP
func (u *Uchiwa) postAddUserHandler(w http.ResponseWriter, r *http.Request) {
    var data map[string]interface{}

    encoder := json.NewEncoder(w)

    decoder := json.NewDecoder(r.Body)
    var req map[string]string
    err := decoder.Decode(&req)
    if err != nil {
        http.Error(w, fmt.Sprint("Could not decode body"), http.StatusInternalServerError)
    }
    if debug {
        fmt.Println("REQUEST:", req)
    }
    if debug {
        for key, value := range req {
            fmt.Printf("Key: %s\nValue: %s", key, value)
        }
    }

    // HAETAAN KEKSISTÄ DATAA
    cookie, _ := r.Cookie("uchiwa_auth")
    cookieValue := "payload="
    cookieValue += cookie.Value

    c, _ := url.ParseQuery(cookieValue)
    //	fmt.Println("***COOKIE***\nC:", c)

    json.Unmarshal([]byte(c["payload"][0]), &data)
    // KEKSIN KÄSITTELY LOPPU


    //	var resp map[string]string
    //	resp = make(map[string]string)
    response, err := u.addUser(data["Username"].(string), data["Org"].(string), req)

    //	fmt.Println("FORM DATA:", r.FormValue("oldPassword"))
    if debug {
        if err != nil {
            fmt.Println("addUser response: ", err)
            fmt.Printf("err.Error: %v\n", err.Error())
        }
    }

    if debug {
        fmt.Println("ORG:", data["Org"])
        fmt.Println("User email:", data["Email"])
    }

    var userOut map[string]string
    userOut = make(map[string]string)
    //userOut = getUserInfo(data["Org"].(string), data["Email"].(string))
    //	conf := PublicConfig
    //	userOut, _ = getUserInfo(PublicConfig, data["Org"].(string), data["Email"].(string))

    //	FOR TESTING
    userOut["status"] = response["status"]
    userOut["error"] = err.Error()

    //fmt.Println(outResults)
    if err := encoder.Encode(userOut); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
    }
}

// Serves /post_user endpoint
func (u *Uchiwa) postUserHandler(w http.ResponseWriter, r *http.Request) {
    //	fmt.Println("****** ENTERING postUserHandler ******")
    var data map[string]interface{}

    encoder := json.NewEncoder(w)

    decoder := json.NewDecoder(r.Body)
    var req map[string]string
    err := decoder.Decode(&req)
    if err != nil {
        fmt.Printf("Decode error: %v\n", err)
        http.Error(w, fmt.Sprint("Could not decode body"), http.StatusInternalServerError)
    }
    if debug {
        fmt.Println("REQUEST:", req)
    }
    if debug {
        for key, value := range req {
            fmt.Printf("Key: %s\nValue: %s", key, value)
        }
    }

    // HAETAAN KEKSISTÄ DATAA
    cookie, _ := r.Cookie("uchiwa_auth")
    cookieValue := "payload="
    cookieValue += cookie.Value

    c, _ := url.ParseQuery(cookieValue)
    //	fmt.Println("***COOKIE***\nC:", c)

    json.Unmarshal([]byte(c["payload"][0]), &data)
    // KEKSIN KÄSITTELY LOPPU


    //	var resp map[string]string
    //	resp = make(map[string]string)
    response, err := u.editUser(data["Username"].(string), data["Org"].(string), req)

    //	fmt.Println("FORM DATA:", r.FormValue("oldPassword"))
    if debug {
        if err != nil {
            fmt.Println("addUser response: ", err)
            fmt.Printf("err.Error: %v\n", err.Error())
        }
        //		fmt.Println("METHOD:", r.Method)
        //		fmt.Println("BODY:", r.Body)
        //		fmt.Println("\n\n\n==== ADDUSER POST HANDLER ====\n")
        //		fmt.Printf("REQUEST: %s", r)
    }

    if debug {
        fmt.Println("ORG:", data["Org"])
        fmt.Println("User email:", data["Email"])
    }

    var userOut map[string]string
    userOut = make(map[string]string)
    //userOut = getUserInfo(data["Org"].(string), data["Email"].(string))
    //	conf := PublicConfig
    //	userOut, _ = getUserInfo(PublicConfig, data["Org"].(string), data["Email"].(string))

    //	FOR TESTING
    userOut["status"] = response["status"]
    userOut["error"] = err.Error()

    fmt.Println("UserOut:", userOut)

    //fmt.Println(outResults)
    if err := encoder.Encode(userOut); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
    }
}

// Serves /post_passwd endpoint
func (u *Uchiwa) postPasswdHandler(w http.ResponseWriter, r *http.Request) {
    var data map[string]interface{}

    encoder := json.NewEncoder(w)

    decoder := json.NewDecoder(r.Body)
    var req map[string]string
    err := decoder.Decode(&req)
    if err != nil {
        http.Error(w, fmt.Sprint("Could not decode body"), http.StatusInternalServerError)
    }
    if debug {
        fmt.Println("REQUEST:", req)
        fmt.Println("OLDPASSWORD:", req)
    }
    if debug {
        for key, value := range req {
            fmt.Printf("Key: %s\nValue: %s", key, value)
        }
    }

    // HAETAAN KEKSISTÄ DATAA
    cookie, _ := r.Cookie("uchiwa_auth")
    cookieValue := "payload="
    cookieValue += cookie.Value

    c, _ := url.ParseQuery(cookieValue)
    //	fmt.Println("C:", c)

    json.Unmarshal([]byte(c["payload"][0]), &data)
    // KEKSIN KÄSITTELY LOPPU

    // Username from cookie to req
    req["userName"] = data["Username"].(string)

    if debug {
        fmt.Println("ORG:", data["Org"])
        fmt.Println("User email:", data["Email"])
        fmt.Printf("Username: %s\n", data["Username"])
    }

    //	var resp map[string]string
    //	resp = make(map[string]string)
    response, err := u.changePasswd(req)

    //	fmt.Println("FORM DATA:", r.FormValue("oldPassword"))
    if debug {
        fmt.Println("FORM DATA:", r.PostForm)
        fmt.Println("METHOD:", r.Method)
        fmt.Println("BODY:", r.Body)

        fmt.Println("\n\n\n==== PASSWORD POST HANDLER ====\n")
        fmt.Printf("REQUEST: %s", r)
    }

    var userOut map[string]string
    userOut = make(map[string]string)
    //userOut = getUserInfo(data["Org"].(string), data["Email"].(string))
    //	conf := PublicConfig
    //	userOut, _ = getUserInfo(PublicConfig, data["Org"].(string), data["Email"].(string))

    //	FOR TESTING
    userOut["status"] = response["status"]
    userOut["error"] = err.Error()

    //	fmt.Println("TenantOut:", userOut)

    //fmt.Println(outResults)
    if err := encoder.Encode(userOut); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
    }
}

// Serves /post_forgotpasswd endpoint
func (u *Uchiwa) postForgotPasswdHandler(w http.ResponseWriter, r *http.Request) {
    if debug {
        fmt.Println("**** Func: server.go/postForgotPasswdHandler ****")
    }

    encoder := json.NewEncoder(w)

    decoder := json.NewDecoder(r.Body)
    var req map[string]string
    err := decoder.Decode(&req)
    if err != nil {
        http.Error(w, fmt.Sprint("Could not decode body"), http.StatusInternalServerError)
    }
    //	if debug {
    //		fmt.Println("REQUEST:", req)
    //	}
    if debug {
        for key, value := range req {
            fmt.Printf("Key: %s\nValue: %s\n", key, value)
        }
    }

    //	Lets see what the request contains...
    fmt.Printf("Client IP: %v", r.RemoteAddr)
    clientIP := r.RemoteAddr
    challenge := req["response"]
    fmt.Printf("\n\nRESPONSE: %v\n\n", challenge)
    fmt.Printf("\n\nVERIFY URL: %v\n\n", u.Config.Uchiwa.ReCaptcha.Url)
    fmt.Printf("\n\nVERIFY SECRETKEY: %v\n\n", u.Config.Uchiwa.ReCaptcha.SecretKey)
    //	Verify the reCAPTCHA, needed: VerifyUrl, captchaReques, (clientIP)

    type Verify struct {
        Success			bool
        Challenge_ts	string
        Hostname		string
        Errorcodes		map[string]string
    }
    resp, err := http.PostForm(u.Config.Uchiwa.ReCaptcha.Url,
    url.Values{"secret": {u.Config.Uchiwa.ReCaptcha.SecretKey}, "remoteip": {clientIP}, "response": {req["response"]}})
    if err != nil {
        fmt.Println("Post error: %s", err)
    }
    defer resp.Body.Close()
    verifyDecoder := json.NewDecoder(resp.Body)
    //	var verifyResponse map[string]string
    var verifyResponse Verify
    verifyErr := verifyDecoder.Decode(&verifyResponse)
    if verifyErr != nil {
        http.Error(w, fmt.Sprint("Could not decode body"), http.StatusInternalServerError)
    }
    fmt.Printf("\nVERIFY RESPONSE: %v", verifyResponse)

    //	if debug {
    //		for key, value := range verifyResponse {
    //			fmt.Printf("Key: %s\nValue: %s\n", key, value)
    //		}
    //	}
    //
    //	s := ""
    //	body, err := ioutil.ReadAll(resp.Body)
    //	if err != nil {
    //		fmt.Println("Read error: could not read body: %s", err)
    //	} else {
    //		s = string(body)
    //		fmt.Printf("\nverify Response: %v\n", s)
    //	}

    var resetOut map[string]string
    resetOut = make(map[string]string)

    if verifyResponse.Success == false {

        //	FOR TESTING
        resetOut["status"] = "Could not verify reCAPTCHA"
        //		resetOut["error"] = err.Error()

    } else if verifyResponse.Success == true {
        response, err := u.resetPassword(req)

        if debug {
            if err != nil {
                fmt.Println("resetPassword response: ", err)
                fmt.Printf("err.Error: %v\n", err.Error())
            }
        }

        resetOut["status"] = response["status"]
        resetOut["error"] = err.Error()

        //		fmt.Println("UserOut:", resetOut)
    }

    if err := encoder.Encode(resetOut); err != nil {
        http.Error(w, fmt.Sprintf("Cannot encode response data: %v", err), http.StatusInternalServerError)
    }
}

// healthHandler serves the /health endpoint
func (u *Uchiwa) helpHandler(w http.ResponseWriter, r *http.Request) {
    encoder := json.NewEncoder(w)
    var err error
    out := &structs.Health{}
    out.Sensu = make(map[string]structs.SensuHealth, 0)
    if r.URL.Path[1:] == "health/sensu" {

        for key, val := range u.Data.Health.Sensu {

            if key == "Lamaani" {
                out.Sensu[key] = val
            }
        }
        err = encoder.Encode(out.Sensu)
        //        err = encoder.Encode("{}")
    } else if r.URL.Path[1:] == "health/uchiwa" {
        err = encoder.Encode(u.Data.Health.Uchiwa)
        //        err = encoder.Encode("{}")
    } else {
        out.Uchiwa = u.Data.Health.Uchiwa

        for key, val := range u.Data.Health.Sensu {
            if key == "Lamaani" {
                out.Sensu[key] = val
            }
        }
        //        err = encoder.Encode(u.Data.Health)
        err = encoder.Encode(out)
    }

    if err != nil {
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
    http.Handle("/get_tenant", auth.Authenticate(http.HandlerFunc(u.getTenantHandler)))
    http.Handle("/get_user", auth.Authenticate(http.HandlerFunc(u.getUserHandler)))
    http.Handle("/get_users", auth.Authenticate(http.HandlerFunc(u.getUsersHandler)))
//    http.Handle("/get_zip", auth.Authenticate(http.HandlerFunc(getCustomerZipHandler)))
    http.Handle("/post_user", auth.Authenticate(http.HandlerFunc(u.postUserHandler)))
    http.Handle("/post_passwd", auth.Authenticate(http.HandlerFunc(u.postPasswdHandler)))
    http.Handle("/post_forgotpasswd", http.HandlerFunc(u.postForgotPasswdHandler))
    http.Handle("/post_adduser", auth.Authenticate(http.HandlerFunc(u.postAddUserHandler)))
    http.Handle("/health", auth.Authenticate(http.HandlerFunc(u.healthHandler)))
    if u.Config.Uchiwa.Enterprise == false {
        http.Handle("/metrics", auth.Authenticate(Authorization.Handler(http.HandlerFunc(u.metricsHandler))))
    }

    // Static files
    http.Handle("/", http.FileServer(http.Dir(*publicPath)))

    // Public endpoints
    http.Handle("/config/", http.HandlerFunc(u.configHandler))
    http.Handle("/health/", http.HandlerFunc(u.healthHandler))
    http.Handle("/help", http.HandlerFunc(u.helpHandler))
    http.Handle("/login", auth.Login())

    listen := fmt.Sprintf("%s:%d", u.Config.Uchiwa.Host, u.Config.Uchiwa.Port)
    logger.Warningf("Uchiwa is now listening on %s", listen)

    if u.Config.Uchiwa.SSL.CertFile != "" && u.Config.Uchiwa.SSL.KeyFile != "" {
        logger.Fatal(http.ListenAndServeTLS(listen, u.Config.Uchiwa.SSL.CertFile, u.Config.Uchiwa.SSL.KeyFile, nil))
    }

    logger.Fatal(http.ListenAndServe(listen, nil))
}