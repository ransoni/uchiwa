package uchiwa

import (
    "fmt"
    "log"
    "net/http"
    "net/url"

    "crypto/tls"
    "github.com/go-ldap/ldap"
    "github.com/ransoni/uchiwa/uchiwa/logger"
    "strings"
    "time"
    "strconv"
    "crypto/rand"
    "errors"
    "net/mail"
    "net/smtp"
    "io/ioutil"
    "regexp"
)

//type UserInfo struct {
//    Name	string
//    Org		string
//    Email	string
//    Tel		string
//    Addr	string
//    City	string
//    Zip		string
//
//}


var (
    user map[string]string
)

type Attribute struct {
    attrType string
    attrVals []string
}


//func  getTenantInfo(c *Config) {
//func getUserInfo(c *Config, o string, e string) (*UserInfo, error) {
func (u *Uchiwa) getUserInfo(org string, email string, username string) (map[string]string, error) {
    userInfo := make(map[string]string)
//    user := new(UserInfo)
//    ldapConf := u.Config.Uchiwa.Ldap
    ldapConf := u.Config.Uchiwa.FreeIPA

//  START USER SEARCH
    fmt.Printf("Tenant: %s\nUser: %s", org, user)

    //	Configure TLS connection parameters
    config := tls.Config{InsecureSkipVerify: true}

//    fmt.Printf("TestConnect: starting...\n")
    fmt.Printf("LDAP Server: %s\nLDAP Port: %s", ldapConf.Server, ldapConf.Port)
    l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ldapConf.Server, ldapConf.Port), &config)
    //	l.Debug = true
    if err != nil {
        logger.Warningf("Cannot connect to LDAP", err)
//        log.Printf("Error: %s\n", err.Error())
        //return // TODO: Fix this to return if error exists
    } else {
        log.Printf("Connected: %s\n", l)
    }

    //	unp := "mail=" + e + ",cn=users,cn=accounts,dc=monni,dc=local" // FreeIPA without RDN
    fmt.Printf("LDAP User: %s\nLDAP Pass: %s", ldapConf.User, ldapConf.Pass)
    errBind := l.Bind(ldapConf.User, ldapConf.Pass)
    if errBind != nil {
        logger.Warningf("Cannot bind to LDAP", errBind)
        log.Printf("Bind error: %s\n", errBind.Error())
        return nil, errBind
    } else {
        logger.Infof("Binded to LDAP succesfully")
        log.Printf("Bind worked!\n")
    }

    var fltr string
    //	START USER SEARCH
    if org == "" {
        fmt.Printf("\ngetUserInfo IF(UID)")
        fltr = "(&(objectClass=person)(uid=" + username + "))"
    } else {
        fmt.Printf("\ngetUserInfo ELSE(mail|org|user")
        fltr = "(&(objectClass=person)(&(uid=" + username + ")(ou=" + org + ")))"

//        fltr = "(&(objectClass=person)(|(&(mail=" + email + ")(ou=" + org + "))(uid=" + username + ")))"

        //	fltr := "(&(objectClass=person)(|(uid=*" + u + "*)(sn=" + u + ")(givenname=*" + u + "*)(mail=*" + u + "*)))"
//        fltr = "(&(objectClass=person)(&(mail=" + user + ")(ou=" + org + ")))"
        //fltr := "(&(objectClass=user)(sAMAccountName=*)(memberOf=CN=*,OU=*,DC=*,DC=*))"
    }

    fmt.Printf("FILTER: %s", fltr)

    attributes := []string{
        "displayName",
        "givenName",
        "sn",
        "mail",
        "mobile",
        "ou",
        "street",
        "postalCode",
        "l",
        "st",
        "employeeType",
//        "dn",
        //		"distinguishedName",
//        "memberOf",
//        "mepManagedBy",
        "krblastsuccessfulauth",
        "krbLastPwdChange",
        "krbPasswordExpiration",
        //		"description",
        //		"company"
    }
/*
    attributes := []string{
        "*",
    }
*/

    if err == nil { // TODO: Change that not checking err, since it shouldn't get to here, if there is err present previously
        search_request := ldap.NewSearchRequest(
        ldapConf.BaseDn,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, //CHANGE: ldap.DerefAlways -> ldap.NeverDerefAliases
        fltr,
        attributes,
        nil)

        sr, err := l.Search(search_request)
        if err != nil {
            log.Printf(err.Error())
            //			return dn, err
        }



/*
        if len(sr.Entries) == 1 {
            dn = sr.Entries[0].DN
        } else {
            l.Close()
            return dn, err
        }
*/



        for i := range sr.Entries {
            //			fmt.Printf("\nENTRY NRO: %v\nDN: %v\n------------------------\n", i+1, sr.Entries[i].DN)
            for key, value := range sr.Entries[i].Attributes {
                //		fmt.Println("Key: ", key, "Value: ", value)
                fmt.Printf("   Key: %v Name: %s Values(%v): ", key, value.Name, len(value.Values))
                
                // PUT IT TO MAP
//                user[value.Name] = value.Values[0]

                for i := range value.Values {
                    if i > 0 {
                        fmt.Printf("                                 ")
                        //user[value.Name] = user[value.Name + ´
                        //]
                    }
                    userInfo[value.Name] = userInfo[value.Name] + value.Values[i]
                    fmt.Println(value.Values[i])
                }
                fmt.Println("Value:", userInfo[value.Name])
            }
        }
    }
    l.Close()

    //	END OF USER SEARCH

//    return user{ID: 0, Username: e, FullName: fn, Email: email, PasswordHash: "", PasswordSalt: "", Role: "operator", Org: org}, nil

//  END USER SEARCH

/*
        user["name"] = name
        user["vhost_name"] = vhost_name
        user["vhost_user"] = vhost_user
        user["vhost_pass"] = vhost_pass
        user["vhost_address"] = vhost_address
        user["vhost_port"] = vhost_port
        user["vhost_cert"] = vhost_cert
*/

        if debug {
            fmt.Println("USER:", userInfo)
        }


    return userInfo, err

}

// GET ORGANIZATION USERS
func (u *Uchiwa) getUsers(o string) (map[string]map[string]string, error) {
    users := make(map[string]map[string]string)
    //    user := new(UserInfo)
    ldapConf := u.Config.Uchiwa.FreeIPA

    //  START USER SEARCH
//    fmt.Printf("Tenant: %s\n", o)

    //	Configure TLS connection parameters
    config := tls.Config{InsecureSkipVerify: true}

    //    fmt.Printf("TestConnect: starting...\n")
    l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ldapConf.Server, ldapConf.Port), &config)
    //	l.Debug = true
    if err != nil {
        logger.Warningf("Cannot connect to LDAP", err)
        //        log.Printf("Error: %s\n", err.Error())
        //return // TODO: Fix this to return if error exists
    } else {
        log.Printf("Connected: %s\n", l)
    }

    //	unp := "mail=" + e + ",cn=users,cn=accounts,dc=monni,dc=local" // FreeIPA without RDN

    errBind := l.Bind(ldapConf.User, ldapConf.Pass)
    if errBind != nil {
        logger.Warningf("Cannot bind to LDAP", errBind)
        return nil, errBind
    } else {
        logger.Infof("Binded to LDAP succesfully")
    }

    //	START USER SEARCH
    //	fltr := "(&(objectClass=person)(|(uid=*" + u + "*)(sn=" + u + ")(givenname=*" + u + "*)(mail=*" + u + "*)))"
    fltr := "(&(objectClass=person)((ou=" + o + ")))"
    //fltr := "(&(objectClass=user)(sAMAccountName=*)(memberOf=CN=*,OU=*,DC=*,DC=*))"

    attributes := []string{
        "uid",
        "displayName",
        "givenName",
        "sn",
        "mail",
        "mobile",
        "ou",
        "street",
        "postalCode",
        "l",
        "st",
        "employeeType",
        //        "dn",
        //		"distinguishedName",
        //        "memberOf",
        //        "mepManagedBy",
//        "krblastsuccessfulauth",
        "krbLastPwdChange",
        "krbPasswordExpiration",
        //		"description",
        //		"company"
    }
    /*
        attributes := []string{
            "*",
        }
    */

    if err == nil { // TODO: Change that not checking err, since it shouldn't get to here, if there is err present previously
        search_request := ldap.NewSearchRequest(
        ldapConf.BaseDn,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, //CHANGE: ldap.DerefAlways -> ldap.NeverDerefAliases
        fltr,
        attributes,
        nil)

        sr, err := l.Search(search_request)
        if err != nil {
            log.Printf(err.Error())
            //			return dn, err
        }

        for u := range sr.Entries {
            //			fmt.Printf("\nENTRY NRO: %v\nDN: %v\n------------------------\n", i+1, sr.Entries[i].DN)
            item := fmt.Sprintf("%v",u)
            users[item] = make(map[string]string)
            for _, value := range sr.Entries[u].Attributes {
                //		fmt.Println("Key: ", key, "Value: ", value)
//                fmt.Printf("   Key: %v Name: %s Values(%v): ", key, value.Name, len(value.Values))

                // PUT IT TO MAP
                //                user[value.Name] = value.Values[0]

                for i := range value.Values {
//                    if i > 0 {
//                        fmt.Printf("                                 ")
//                        //user[value.Name] = user[value.Name + ´
//                        //]
//                    }
                    users[item][value.Name] = users[item][value.Name] + value.Values[i]
//                    fmt.Println(value.Values[i])
                }
//                fmt.Println("Value:", users[item][value.Name])
            }
        }
    }
    l.Close()

    //	END OF USER SEARCH

    //    return user{ID: 0, Username: e, FullName: fn, Email: email, PasswordHash: "", PasswordSalt: "", Role: "operator", Org: org}, nil

    //  END USER SEARCH

    /*
            user["name"] = name
            user["vhost_name"] = vhost_name
            user["vhost_user"] = vhost_user
            user["vhost_pass"] = vhost_pass
            user["vhost_address"] = vhost_address
            user["vhost_port"] = vhost_port
            user["vhost_cert"] = vhost_cert
    */

//    if debug {
//        fmt.Println("USER:", users)
//    }


    return users, err

}

// PASSWORD CHANGE
func (u *Uchiwa) changePasswd(user map[string]string) (map[string]string, error) {
    un := user["userName"]
    pw := user["oldPassword"]
    npw := user["newPassword"]
    fmt.Println("OLDPASS:", user["oldPassword"])
    fmt.Printf("\n\nchangePasswd user map: %v\n\n", user)

    //	Let's connect...err, bind that is
    l, err := u.Login(un, pw)
    fmt.Printf("%s", l)
    fmt.Printf("\n\n")
    //	defer l.Close()

    /*	errBind := l.Bind(un, pw)
        if errBind != nil {
            log.Printf("Bind: %s\n", errBind.Error())
        } else {
            log.Printf("Bind worked!\n")
        }*/
    //	End of mutual binding

    //	useri := "UID=testita,OU=Users,OU=Accounts,DC=monni,DC=local"
    useri := "uid=" + user["userName"] + ",cn=users,cn=accounts,dc=monni,dc=local"
    passwdModifyRequest := ldap.NewPasswordModifyRequest(useri, pw, npw)
    _, err = l.PasswordModify(passwdModifyRequest)

    if err != nil {
        logger.Warningf("ERROR: Cannot change password: %s", err)
        fmt.Println("ERROR: Cannot change password: %s\n", err)
    } else {
        fmt.Println("Password changed succesfully.")
        err = errors.New("Password changed.")
    }
    //	End of change
    l.Close()
    return nil, err
}

// RESET PASSWORD
func (u *Uchiwa) resetPassword(user map[string]string) (map[string]string, error) {
    resetResult := make(map[string]string)
    resetResult["status"] = "0"
//    l, err := c.Login("admin", c.Uchiwa.Ldap.Pass)
    l, err := u.Login("admin", u.Config.Uchiwa.FreeIPA.Pass)
    defer l.Close()
    if err != nil {
        log.Fatal(err)
        return resetResult, errors.New("Could not reset password.")
    }

    userInfo := make(map[string]string)

    userInfo, err = u.getUserInfo("", "", user["username"])

    if len(userInfo) == 0 {
        logger.Warningf("user.getUserInfo error: %v", err)
        err = errors.New("Could not find user.")
        return resetResult, err
    }

    newPassword := generatePasswd(8)
    dn := "uid=" + user["username"] + ",cn=users,cn=accounts,dc=monni,dc=local"

    passwordModifyRequest := ldap.NewPasswordModifyRequest(dn, "", newPassword)
    result, err := l.PasswordModify(passwordModifyRequest)
    if err != nil {
        log.Fatalf("Password could not be reseted: %s", err.Error())
    } else {
        logger.Infof("RESULT: %s\nERR: %s", result, err)
        resetResult["status"] = "1"
        err = errors.New("New password sent by SMS.")
    }
    sms := u.sendSMS(userInfo["mobile"], newPassword)
    logger.Infof("SMS: %V", sms)
    return resetResult, err
}

// EDIT USER INFO
func (u *Uchiwa) editUser(adminUser string, org string, user map[string]string) (map[string]string, error) {
    addUser := make(map[string]string)
    //    var wait string
    firstName := user["givenName"]
    lastName := user["sn"]
    email := user["mail"]
    phone := user["mobile"]
    cn := firstName + " " + lastName

    //    company := user["ou"]


    // PROCESS TO EDIT USER
    // 1. CHECK IF USER HAS ROLE TO ADD USERS
    // 2. GET INFO
    // 3. SEARCH FIRST AVAILABLE GID NUMBER
    // 4. CREATE DEFAULT PASSWORD
    // 5. MAKE ADD REQUEST

    //	First we connect to LDAP
    //	Let's connect...err, bind that is
    l, err := u.Login("admin", "") // ADD USERNAME AND PASSWD
    if err != nil {
        logger.Warningf("Not binding", err)
        return nil, err
    }

    // CHECK USER ROLE
//    isAdmin, errRole := getUserRole(l, adminUser ) // TODO: This should be moved to login role assignment -> to cookie
//    if errRole != nil {
//        logger.Warningf("Could not resolve user role.", errRole)
//    } else {
//        if isAdmin == true {
//            fmt.Println("Is admin: %s\n", isAdmin)
//        } else if isAdmin == false {
//            logger.Info("User %s is not an admin.", adminUser)
//            addUser["status"] = "0"
//            return addUser, errors.New("You're not an admin.")
//        }
//    }

//    //	uid := strings.ToLower(lastName[0:5] + firstName[0:2]) // TODO: Fix if lastname under 5 letters, now it breaks
//    var uid string
//    if len(lastName) >= 5 {
//        uid = strings.ToLower(lastName[0:5] + firstName[0:2])
//    } else {
//        length := len(lastName)
//        uid = strings.ToLower(lastName[0:length] + firstName[0:7-length])
//    }
//    fmt.Println("UID created: %s", uid)
//    //    fmt.Scanln(&wait)

//    cn := firstName + " " + lastName
//

    attrlist := []Attribute{
        {"givenName", []string{firstName}},
        {"sn", []string{lastName}},
        {"cn", []string{cn}},
        {"displayName", []string{cn}},
        {"mail", []string{email}},
        {"mobile", []string{phone}},
    }

    dn := "uid=" + adminUser + ",cn=users,cn=accounts,dc=monni,dc=local"
    //	uid := maxUid()+1

    // FINALLY EDITING THE USER
    modifyRequest := ldap.NewModifyRequest(dn)
    for _, attr := range attrlist {
//        fmt.Println(attr.attrType)
        modifyRequest.Replace(attr.attrType, attr.attrVals)
        //		addUserRequest.Attribute(attr.attrType, []string{"testi"})
    }

//    fmt.Println("addRequest:", modifyRequest)

    //	Let's add the user

    if errMod := l.Modify(modifyRequest); err != nil {
        logger.Warningf("ERROR: Cannot add user: %s\n", errMod)
        l.Close()
        addUser["status"] = "0"
        return addUser, errMod
    } else {
        logger.Infof("Editing user %v succesfully.\n", email)
        l.Close()
        addUser["status"] = "1"
        return addUser, errors.New("User edited succesfully.")
    }

    //	End of Add
    //	End of change
    //    l.Close()
    //    return nil, err
}

// ADD NEW USER TO ORGANIZATION
func (u *Uchiwa) addUser(adminUser string, org string, user map[string]string) (map[string]string, error) {
    addUser := make(map[string]string)
//    var wait string
    firstName := user["givenName"]
    lastName := user["sn"]
    email := user["mail"]
    phone := user["mobile"]

//    REMOVE UNWANTED CHARS FROM PHONE NUMBER
    phone = strings.Replace(phone, "+", "", -1)
    phone = strings.Replace(phone, "-", "", -1)
    phone = strings.Replace(phone, "(", "", -1)
    phone = strings.Replace(phone, ")", "", -1)
    fmt.Printf("PHONE NUMBER: %v\n\n", phone)

//    company := user["ou"]


    // PROCESS TO ADD USER
    // 1. CHECK IF USER HAS ROLE TO ADD USERS
    // 2. GET INFO
    // 3. SEARCH FIRST AVAILABLE GID NUMBER
    // 4. CREATE DEFAULT PASSWORD
    // 5. MAKE ADD REQUEST
    // 6. ADD USER
    // 7. SEND USERNAME VIA EMAIL
    // 8. DEFAULT PASSWORD VIA SMS

    if !validateName(firstName) {
        addUser["status"] = "0"
        return addUser, errors.New("Please check the first name!")
    }

    if !validateName(lastName) {
        addUser["status"] = "0"
        return addUser, errors.New("Please check the last name!")
    }

    if !validateEmail(email) {
        addUser["status"] = "0"
        return addUser, errors.New("Please check the email address!")
    }

    if !validateNumber(phone) {
        addUser["status"] = "0"
        return addUser, errors.New("Please check the mobile number!")
    }


    //	First we connect to LDAP
    //	Let's connect...err, bind that is
    l, err := u.Login("admin", "") // ADD USERNAME AND PASSWD
    if err != nil {
        logger.Warningf("Not binding", err)
        return nil, err
    }

    defer l.Close()
//    else {
//        fmt.Println("Binded!")
//        //		fmt.Print(l)
//    }


    // CHECK USER ROLE
    isAdmin, errRole := getUserRole(l, adminUser ) // TODO: This should be moved to login role assignment -> to cookie
    if errRole != nil {
        logger.Warningf("Could not resolve user role.", errRole)
    } else {
        if isAdmin == true {
//            fmt.Println("Is admin: %s\n", isAdmin)
        } else if isAdmin == false {
            logger.Info("User %s is not an admin.", adminUser)
            addUser["status"] = "0"
            return addUser, errors.New("You're not an admin.")
        }
    }

    //	uid := strings.ToLower(lastName[0:5] + firstName[0:2]) // TODO: Fix if lastname under 5 letters, now it breaks
    var uid string
    if len(lastName) >= 5 {
        uid = strings.ToLower(lastName[0:5] + firstName[0:2])
    } else {
        length := len(lastName)
        uid = strings.ToLower(lastName[0:length] + firstName[0:7-length])
    }

    res := 0
    uidOrg := uid

    for i := 0; res == 0; i++ {
        if i > 0 {
            uid = uidOrg + strconv.Itoa(i)
        }
        res = searchUser(l, uid)
    }

    cn := firstName + " " + lastName
    var uidNum int = 0
//  Get maxUid for new user account
    if  uidNum = maxUid(l); uidNum == 1 {
        //		uidNum = strconv.FormatInt(time.Now().Unix(), 10)
        uidNum = int(time.Now().Unix())
    } else {
        uidNum = uidNum+1
    }

    passwd := generatePasswd(8)

    attrlist := []Attribute{
        {"objectClass", []string{"person", "top", "ipaobject", "inetorgperson", "organizationalperson",
            "krbticketpolicyaux", "krbprincipalaux", "inetuser", "posixaccount",
            "ipaSshGroupOfPubKeys"}},
        {"uid", []string{uid}},
        {"givenName", []string{firstName}},
        {"sn", []string{lastName}},
        {"cn", []string{cn}},
        {"displayName", []string{cn}},
        {"krbPrincipalName", []string{uid+"@MONNI.LOCAL"}},
        {"ipaUniqueId", []string{"autogenerate"}},
        {"mail", []string{email}},
        {"mobile", []string{phone}},
        {"ou", []string{org}},
        {"uidNumber", []string{strconv.Itoa(uidNum)}}, // Get this by searching current max UID
        {"gidNumber", []string{strconv.Itoa(uidNum)}},
        {"loginShell", []string{"/bin/bash"}},
        {"homeDirectory", []string{"/home/"+uid}},
        {"userPassword", []string{passwd}},
    }

    dn := "uid=" + uid + ",cn=users,cn=accounts,dc=monni,dc=local"
    //	uid := maxUid()+1

    // WORKFLOW
    addUserRequest := ldap.NewAddRequest(dn)
    for _, attr := range attrlist {
//        fmt.Println(attr.attrType)
        addUserRequest.Attribute(attr.attrType, attr.attrVals)
        //		addUserRequest.Attribute(attr.attrType, []string{"testi"})
    }

//    fmt.Println("addRequest:", addUserRequest)

    //	Let's add the user

    if errAdd := l.Add(addUserRequest); err != nil {
        logger.Warningf("ERROR: Cannot add user: %s\n", errAdd)
        l.Close()
        addUser["status"] = "0"
        return addUser, errAdd
    } else {
        logger.Infof("Adding user " + uid + " succesfully.\n")
        l.Close()

//      SEND SMS FOR ACCOUNT CREATION
//        smsBody := fmt.Sprintf(c.Uchiwa.Email.NewUserText, passwd)
        smsBody := u.Config.Uchiwa.SMS.NewUserText + passwd
        statusSMS := u.sendSMS(phone, smsBody)

//       SEND EMAIL FOR ACCOUNT CREATION
        emailTemplate, err := ioutil.ReadFile(fmt.Sprintf("%v%v", u.Config.Uchiwa.Email.TemplatePath, u.Config.Uchiwa.Email.TemplateFile))
        if err != nil {
            logger.Fatalf("Email template error!", err)
        }
        emailBody := fmt.Sprintf(string(emailTemplate), firstName, uid)

        emailSubject := u.Config.Uchiwa.Email.Subject

        statusMail := u.sendMail(email, firstName, lastName, emailSubject, emailBody)
        addUser["status"] = "1"
        return addUser, errors.New("User added succesfully.\n" + statusSMS + "\n" + statusMail)
    }

    //	End of Add
//    l.Close()
//    return nil, err
}

// SEND SMS
func (u *Uchiwa) sendSMS(to string, body string) (status string) {
    baseUrl := u.Config.Uchiwa.SMS.Url
    params := url.Values{}
    params.Add("to", to)
    params.Add("text", body)

    finalUrl := fmt.Sprintf("%s&%s", baseUrl, params.Encode())
    response, err := http.Get(finalUrl)
    defer response.Body.Close()

    if err != nil {
        log.Fatalf("Error: %s", err)
        return response.Status
    }

    return "SMS sent"
}

// SEND EMAIL
func (u *Uchiwa) sendMail(email string, firstname string, lastname string, subject string, body string) (status string) {
    // the basics
    from := mail.Address{u.Config.Uchiwa.Email.Name, u.Config.Uchiwa.Email.Email}
    to   := mail.Address{firstname + " " + lastname, email}

    // setup the remote smtpserver
    smtpserver := fmt.Sprintf("%v:%v", u.Config.Uchiwa.Email.Host, u.Config.Uchiwa.Email.Port)
//    smtpserver := "smtp.ecloud.fi:25"

    // setup a map for the headers
    header := make(map[string]string)
    header["From"] = from.String()
    header["To"] = to.String()
    header["Subject"] = subject

    // setup the message
    message := ""
    for k, v := range header {
        message += fmt.Sprintf("%s: %s\r\n", k, v)
    }
//    message += "\r\n" + fmt.Sprintf(body, firstname, username)
    message += "\r\n" + body

    // create the smtp connection
    conn, err := smtp.Dial(smtpserver)
    if err != nil {
        log.Panic(err)
    }
    defer conn.Close()

    // To && From
    if err = conn.Mail(from.Address); err != nil {
        log.Panic(err)
    }
    if err = conn.Rcpt(to.Address); err != nil {
        log.Panic(err)
    }

    // Data
    w, err := conn.Data()
    if err != nil {
        log.Panic(err)
    }
    defer w.Close()
    _, err = w.Write([]byte(message))
    if err != nil {
        log.Panic(err)
    }
    err = w.Close()
    if err != nil {
        log.Panic(err)
    }
    return "Email sent"
}

// GET USER ROLE TRIES TO ADD USER
func getUserRole(l *ldap.Conn, user string) (bool, error) {
    // Get user memberOf list, to check if person is admin of it's organization
    fltr := "(&(objectClass=person)(uid=*"+user+"*))"

    searchRequest := ldap.NewSearchRequest(
    "dc=monni,dc=local",
    ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
    fltr,
    []string{"uid", "cn", "mail", "memberOf", "employeeType"},
    nil,
    )

    if sr, err := l.Search(searchRequest); err != nil {
        log.Println("Could not execute LDAP search", err)
        return false, err
    } else {
        for i := range sr.Entries {
            //			fmt.Printf("Entry: %v\n", sr.Entries[i])
            for _, value := range sr.Entries[i].Attributes {
                //				fmt.Printf("Key: %s", key)
                if value.Name == "employeeType" {
                    if value.Values[0] == "admin" {
                        return true, nil
                    } else {
                        return false, nil
                    }
                }
                //				for i := range value.Values {
                //					fmt.Printf(" , Value: %s\n", value.Values[i])
                //				}
            }
        }
        //		fmt.Printf("\nmaxUid is: %v\n", maxUid)
        return false, err

    }
}

// SEARCH TO FIND IF USERNAME ALREADY EXISTS
func searchUser(l *ldap.Conn, uid string) int {
    // To search if username exists already
    fltr := "(&(objectClass=person)(uid=" + uid + "))"

    searchRequest := ldap.NewSearchRequest(
    "cn=users,cn=accounts,dc=monni,dc=local",
    ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
    fltr,
    []string{"uid", "cn"},
    nil,
    )

    if sr, err := l.Search(searchRequest); err != nil {
        log.Println("Could not execute LDAP search", err)
        return 1
    } else if len(sr.Entries) > 0 {
        return 0 // Return 0 if searched username exists
    } else {
        return 1 // Return 1 if searched username does not exist
    }

}

// SEARCH CURRENT MAX UID FROM IPA USER ACCOUNTS
func maxUid(l *ldap.Conn) int {
    var maxUid int = 0
    var max int = 0
    // To search max used uidNumber in FreeIPA
    fltr := "(&(objectClass=person)(uid=*))"

    searchRequest := ldap.NewSearchRequest(
    "dc=monni,dc=local",
    ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
    fltr,
    []string{"uidNumber"},
    nil,
    )

    if sr, err := l.Search(searchRequest); err != nil {
        logger.Warningf("Could not execute LDAP search", err)
        return 0
    } else {
        for i := range sr.Entries {
            for _, value := range sr.Entries[i].Attributes {
                for i := range value.Values {
                    max, _ = strconv.Atoi(value.Values[i])
                    if max >= maxUid {
                        maxUid = max
                    }
                }
            }
        }
        return maxUid
    }

}

// GENERATE RANDON ALPHANUMERIC PASSWORD
func generatePasswd(strSize int) string {

    var dictionary string

    dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    var bytes = make([]byte, strSize)
    rand.Read(bytes)
    for k, v := range bytes {
        bytes[k] = dictionary[v%byte(len(dictionary))]
    }
    return string(bytes)
}

// VALIDATE EMAIL
func validateEmail(email string) bool {
    Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
    return Re.MatchString(email)
}

// VALIDATE NAME
func validateName(name string) bool{
    Re := regexp.MustCompile(`^[A-Z][a-z]*$`)
    return Re.MatchString(name)
}

// VALIDATE NUMBER
func validateNumber(number string) bool{
    Re := regexp.MustCompile(`^[0-9]*$`)
    return Re.MatchString(number)
}

// LOGIN FUNC
// TODO: Should there be separate login for admin???
func (u *Uchiwa) Login(user string, passwd string) (*ldap.Conn, error) {
//    ldapConf := u.Config.Uchiwa.FreeIPA
    config := tls.Config{InsecureSkipVerify: true}
    l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", u.Config.Uchiwa.FreeIPA.Server, u.Config.Uchiwa.FreeIPA.Port), &config)
    if err != nil {
        return nil, err
    }

    //	Needed for FreeIPA, since it doesn't support RDN
    var loginuser string
    if (user == "admin") {
        loginuser = u.Config.Uchiwa.FreeIPA.User
        passwd = u.Config.Uchiwa.FreeIPA.Pass
    } else {
        loginuser = "uid=" + user + ",cn=users,cn=accounts,dc=monni,dc=local"
    }


    errBind := l.Bind(loginuser, passwd)
    if errBind != nil {
        logger.Warningf("Bind: %s\n", errBind.Error())
    }
//    else {
//        log.Printf("Bind worked!\n")
//    }

    return l, errBind
}