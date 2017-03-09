package uchiwa

import (
    "fmt"

//    "github.com/palourde/logger"
    "github.com/ransoni/uchiwa/uchiwa/logger"
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)


/*type tenant struct {
    Dn      string
    Email   string
}*/

var (
    id			int
    ip			string
    name		string
    created		string
    vhost_name	string
    vhost_user	string
    vhost_pass	string
    vhost_address	string
    vhost_port	string
    vhost_cert	string
    tenant map[string]string
)

//func  getTenantInfo(c *Config) {
func (u *Uchiwa) getTenantInfo(o string) map[string]string {
    fmt.Printf("\n*-- getTenantInfo --*")

    var query string

//    query = "select vhost_name, vhost_user, vhost_pass, vhost_address, vhost_port, vhost_cert from sensuclientvapp where vhost_name = '" + o + "'"
    query = "select vhost_name, vhost_user, vhost_pass, vhost_address, vhost_port, vhost_cert from sensuclientvapp where vhost_name = ?"
    fmt.Println("QUERY:", query)

    tenant = make(map[string]string)

//    dataSource := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v", c.Uchiwa.Sql.User, c.Uchiwa.Sql.Pass, c.Uchiwa.Sql.Host, c.Uchiwa.Sql.Port, c.Uchiwa.Sql.Db)
    dataSource := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v", u.Config.Uchiwa.Sql.User, u.Config.Uchiwa.Sql.Pass, u.Config.Uchiwa.Sql.Host, u.Config.Uchiwa.Sql.Port, u.Config.Uchiwa.Sql.Db)
    db, err := sql.Open("mysql", dataSource)
    if err != nil {
        logger.Fatalf("Database connection error.\n", err)
    }
    defer db.Close()

    rows, err := db.Query(query, o)
    //err = db.QueryRow("select id, ip, name from sensuclientvapp").Scan(&str)

    if err != nil && err != sql.ErrNoRows {
        logger.Warningf("Error on query.\n", err)
    } else {
        fmt.Println("Query succeeded.")
    }

    //fmt.Println("STR:", str)

    defer rows.Close()

    for rows.Next() {
        err := rows.Scan(&vhost_name, &vhost_user, &vhost_pass, &vhost_address, &vhost_port, &vhost_cert)
        if err != nil {
            fmt.Println("Fetching data from row went haywire.\n", err)
        }
        if debug {
            fmt.Printf("NAME: %v\nVHOST_NAME: %v\nVHOST_USER: %v\nVHOST_PASS: %v\nVHOST_ADDRESS: %v\nVHOST_PORT: %v\nVHOST:CERT: %v\n\n", name, vhost_name, vhost_user, vhost_pass, vhost_address, vhost_port, vhost_cert)
        }

//        tenant["name"] = name
        tenant["MQ vhost name"] = "/" + vhost_name
        tenant["MQ vhost user name"] = vhost_user
        tenant["MQ vhost user password"] = vhost_pass
        tenant["MQ server address"] = vhost_address
        tenant["MQ server port"] = vhost_port
//        tenant["Vhost cert"] = vhost_cert

        fmt.Println("TENANT:", tenant)



    }

    return tenant

}

//func updateUser() {
//    // DO SOMETHING
//}