package auth

import (
    "fmt"
    "log"
    "crypto/tls"
    "github.com/go-ldap/ldap"
)

var (
    server string = "192.168.1.10"
    port   uint16 = 636
    base_dn     string = "dc=monni,dc=local"
    attributes []string = []string{
        "givenName",
        "sn",
        "mail",
        "uid",
        "ou",
        "dn",
        "cn",
        //		"distinguishedName",
        "memberOf",
        "employeeType",
        "mepManagedBy",
        //		"krbLastSuccessfulAuth",
        //		"description",
        //		"company"
    }

    fn		string = ""
    email	string = ""
    org		string = ""
    role	string = ""
    debug   bool = true
)

func none(u, p string) (*User, error) {
	return &User{}, nil
}

func simple(u, p string) (*User, error) {
	for _, user := range users {
		if u == user.Username && p == user.Password {
			return &user, nil
		}
	}
	return &User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
}

func freeipa(u, p string) (*User, error) {
	fmt.Printf("This is freeipa-function!")

    if debug {
        fmt.Println("ALARMAA!! \nLDAPIPA in drivers.go")
        fmt.Printf("User: %s, Pass: %s", u, p)
    }
    //	fmt.Printf("\nConf dumppi: %s", )

    //	Configure TLS connection parameters
    config := tls.Config{InsecureSkipVerify: true}

    if debug {
        fmt.Printf("TestConnect: starting...\n")
    }
    l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", server, port), &config)
    //	l.Debug = true
    if err != nil {
        log.Printf("Error: %s\n", err.Error())
        //return
    } else {
        log.Printf("Connected: %s\n", l) // TODO: LOGGING
    }

    //	fmt.Printf("Type: %T\n", *l)

    //	u += "@lemonitor.local" // For AD with RDN
    unp := "uid=" + u + ",cn=users,cn=accounts,dc=monni,dc=local" // FreeIPA without RDN

    errBind := l.Bind(unp, p)
    if errBind != nil {
        log.Printf("Bind error: %s\n", errBind.Error()) // TODO: LOGGING
    } else {
        log.Printf("Bind worked!\n")
        if debug {
            fmt.Println("Bind:", errBind)
        }

        //	OMIEN TIETOJEN HAKU
        fltr := "(&(objectClass=person)(uid="
        fltr += u
        fltr += "))"

        if debug {
            fmt.Println("Fltr:", fltr)
        }

        if err == nil {
            search_request := ldap.NewSearchRequest(
            base_dn,
            ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, //CHANGE: ldap.DerefAlways -> ldap.NeverDerefAliases
            fltr,
            attributes,
            nil)

            sr, err := l.Search(search_request)
            if err != nil {
                log.Printf(err.Error())
                //return
            }

            for i := range sr.Entries {
                //if

                //				fmt.Println(sr.Entries[i])
                //				fmt.Println(sr.Entries[i].Attributes[0].Name, "Length:", len(sr.Entries[i].Attributes))
                for key, value := range sr.Entries[i].Attributes {

                    if debug {
                        fmt.Printf("\nKey: %v Name: %s Values(%v): %v", key, value.Name, len(value.Values), value.Values[0])
                    }

                    switch {
                        case value.Name == "cn":
                        //						fmt.Println("CN:", value.Values[0])
                        fn = value.Values[0]
                        //						fmt.Println("case cn:", value.Values[0])
                        case value.Name == "mail":
                        //						fmt.Println("MAIL:", value.Values[0])
                        email = value.Values[0]
                        //						fmt.Println("case email:", value.Values[0])
                        case value.Name == "ou":
                        //						fmt.Println("OU:", value.Values[0])
                        org = value.Values[0]
                        //						fmt.Println("case company:", value.Values[0])
                        //						case value.Name == "memberOf":
                        case value.Name == "employeeType":
                        //						fmt.Println("AUTH/DRIVERS, employeeType:", value.Values[0])
                        role = value.Values[0]
                        //						fmt.Println("case role:", value.Values[0])

                    }

                }

            }
        }

        defer l.Close()

        // TIETOJEN HAKU PÄÄTTYY
        /* USER INFO MAPPINGS
            struct = ldap attribute
            ID = ??
            Username = u
            FullName = givenName + sn || cn
            Email = mail
            Organization = company
            Role = memberOf

         */

        return &User{ID: 0, Username: u, FullName: fn, Email: email, PasswordHash: "", PasswordSalt: "", Role: Role{Name: org}, Org: org, SesID: "1234567890qwertyuiopasdfghjkl"}, nil
    }

    /*	if u == user && p == pass {
            return &User{ID: 0, Username: u, FullName: u, PasswordHash: "", PasswordSalt: "", Role: "operator"}, nil
        }
    */

    return &User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
}