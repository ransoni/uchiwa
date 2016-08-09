package filters

import (
    "github.com/dgrijalva/jwt-go"
	"github.com/ransoni/uchiwa/uchiwa/structs"
)

// FilterAggregates based on role's datacenters
func FilterAggregates(data *[]interface{}, token *jwt.Token) []interface{} {
	return *data
}

// FilterChecks based on role's datacenters and subscriptions
func FilterChecks(data *[]interface{}, token *jwt.Token) []interface{} {
	return *data
}

// FilterClients based on role's datacenters and subscriptions
//func FilterTenantClients(data []interface{}, token *jwt.Token) []interface{} {
//    ulos := make([]interface{}, 0)
//    for _, client := range data {
//        c, ok := client.(map[string]interface{})
//        if !ok {
//            fmt.Printf("Could not assert... %+v\n", c)
//        }
//        for k, v := range c {
//            if k == "dc" && v == "lamaani" {
//                fmt.Printf("IF?\n")
//                ulos = append([]interface{}{}, c)
//            }
//        }
//        // else {
//        //   ulos = append(ulos, c)
//        //}
//
//    }
//    return ulos
//    return *data
//}

// THIS IS THE ORIGINAL UNMODIFIED FilterClients-function
func FilterClients(data *[]interface{}, token *jwt.Token) []interface{} {
    return *data
}


// FilterDatacenters based on role's datacenters
func FilterDatacenters(data []*structs.Datacenter, token *jwt.Token) []*structs.Datacenter {
	return data
}

// FilterEvents based on role's datacenters and subscriptions
func FilterEvents(data *[]interface{}, token *jwt.Token) []interface{} {
	return *data
}

// FilterStashes based on role's datacenters
func FilterStashes(data *[]interface{}, token *jwt.Token) []interface{} {
	return *data
}

// FilterSubscriptions based on role's subscriptions
func FilterSubscriptions(data *[]string, token *jwt.Token) []string {
	return *data
}

// GetRequest is a function that filters GET requests.
func GetRequest(dc string, token *jwt.Token) bool {
	return false
}

// PostRequest is a function that filters POST requests.
func PostRequest(token *jwt.Token, data *interface{}) bool {
	return false
}

// SensuData is a function that filters Sensu Data.
func SensuData(token *jwt.Token, data *structs.Data) *structs.Data {
	return data
}
