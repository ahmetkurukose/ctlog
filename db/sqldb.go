package sqldb

import (
	"container/list"
	"database/sql"
	"errors"
	"gopkg.in/gomail.v2"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CertInfo struct {
	CN string
	DN string
	SerialNumber string
	SAN string
}

type CTLogInfo struct {
	OldHeadIndex int64
	NewHeadIndex int64
}

type SMTPInfo struct {
	host string
	port int
	username string
	password string
}

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
var domainRegex = regexp.MustCompile("^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9])).([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$")
var emailConst = "<head>\n    <style>\n        body {\n            font-family: monospace;\n        }\n        ul {\n            font-weight: bold;\n            list-style-type: none;\n        }\n        li {\n            font-weight: lighter;\n        }\n    </style>\n</head>\n<body>\n    <h2>TENTO EMAIL BYL AUTOMATICKY VYGENEROVÁN / THIS IS EMAIL HAS BEEN AUTOMATICALLY GENERATED</h2>\n    <h2>NA TENTO EMAIL NEODPOVÍDEJTE / DO NOT REPLY TO THIS EMAIL</h2>\n\n    <a>Dobrý den,</a><br><br>\n        <a>Služba CTLog identifikovala vydání těchto nových certifikátů:</a>\n"


// Creates a connection to the database and returns it.
func ConnectToDatabase(database string) *sql.DB {
	db, err := sql.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

// Closes the database connection.
func CloseConnection(db *sql.DB) {
	db.Close()
}

// Deletes the downloaded certificates.
func CleanupDownloadTable(db *sql.DB) {
	db.Exec("DELETE FROM Downloaded")
}

func isEmailValid(e string) bool {
	if len(e) < 3 && len(e) > 254 {
		return false
	}

	return emailRegex.MatchString(e)
}

func isDomainValid(d string) bool {
	return domainRegex.MatchString(d)
}

// Add monitors to the database
func AddMonitors(email string, domains []string, db *sql.DB) error {
	if !isEmailValid(email) {
		return errors.New("First argument is not an email address")
	}

	for i := range domains {
		if !isDomainValid(domains[i]) {
			return errors.New("One of the domains is not a valid domain name")
		}
	}

	for i := range domains {
		_, err := db.Exec("INSERT OR IGNORE INTO Monitor VALUES (?, ?)", email, domains[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// Remove monitor from the database
func RemoveMonitors(email string, domain string, db *sql.DB) error {
	if !isEmailValid(email) {
		return errors.New("First argument is not an email address")
	}

	if !isDomainValid(domain) {
		return errors.New("Second argument is not a valid domain name")
	}

	_, err := db.Exec("DELETE FROM Monitor WHERE Email = ? AND Domain = ?", email, domain)

	return err
}

// Send out the certificate informations to the email monitoring them.
func SendEmail(smtpInfo SMTPInfo, email string, certList *list.List) {
	t := time.Now().Add(-24 * time.Hour)
	date := strings.Join([]string{strconv.Itoa(t.Day()), strconv.Itoa(int(t.Month())), strconv.Itoa(t.Year())}, ".")

	m := gomail.NewMessage()
	m.SetHeader("From", "no-reply@cesnet.cz")
	m.SetHeader("To", email)
	m.SetHeader("Subject", "[CTLog] Nové certifikáty " + date)

	var sb strings.Builder

	sb.WriteString(emailConst)

	for cert := certList.Front(); cert != nil; cert = cert.Next() {
		sb.WriteString("<ul>")
		cur := cert.Value.(CertInfo)
		sb.WriteString(cur.CN)
		sb.WriteString("<li>Subject DN: " + cur.DN + "</li>" +
						"<li>Serial: " + cur.SerialNumber + "</li>" +
						"<li>Names: " + cur.SAN + "</li>")
		sb.WriteString("</ul>")
	}

	sb.WriteString("<a href=\"pki.cesnet.cz\">O službě</a>")
	sb.WriteString("<img src=\"https://www.cesnet.cz/wp-content/uploads/2018/01/cesnet-malelogo.jpg\"><br></body>")
	m.SetBody("text/html", sb.String())

	d := gomail.NewDialer(smtpInfo.host, smtpInfo.port, smtpInfo.username, smtpInfo.password)

	// Send the email to Bob, Cora and Dan.
	if err := d.DialAndSend(m); err != nil {
		log.Printf("[-] Failed sending email, %s\n", err)
	}
}

// Returns previous head index of a log.
func GetLogIndex(url string, db *sql.DB) (int64, error) {
	row := db.QueryRow("SELECT HeadIndex FROM CTLog WHERE Url = ?", url)
	var lastIndex int64
	err := row.Scan(&lastIndex)

	return lastIndex, err
}

func checkSMTP(smtpInfo string) (SMTPInfo, bool) {
	arr := strings.Split(smtpInfo," ")
	if len(arr) != 4 {
		log.Printf("[-] Cannot send emails, argument count mismatch\n")
		return SMTPInfo{}, false
	}

	port, err := strconv.ParseInt(arr[1],10,0)

	if err != nil {
		log.Printf("[-] Cannot send emails, port is not a number\n")
		return SMTPInfo{}, false
	}
	
	d := gomail.NewDialer(arr[0], int(port), arr[2],arr[3])
	s, err := d.Dial()
	if s != nil {
		defer s.Close()
	}

    if err != nil {
    	log.Printf("[-] Could not connect to the SMTP server -> %s\n", err)
	}

	ret := SMTPInfo{
		host:     arr[0],
		port:     int(port),
		username: arr[2],
		password: arr[3],
	}

	return ret, err == nil
}


// Find monitored certificates, create a map of email -> certificate attributes and send out emails
func ParseDownloadedCertificates(smtpInfo string, db *sql.DB) {
	//cesnet.cz should check only *cesnet.cz*
	query := `
		SELECT Email, CN, DN, Serialnumber, SAN
		FROM Downloaded
		INNER JOIN Monitor M ON INSTR(DN, M.Domain) > 0 OR
		                        INSTR(SAN, M.Domain) > 0;`

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("[-] Error while parsing downloaded certificates -> %s\n", err)
	}
	defer rows.Close()

	certsForEmail := make(map[string]*list.List)

	for rows.Next() {
		var (
			email        string
			CN           string
			DN           string
			serialnumber string
			SAN          string
		)

		rows.Scan(&email, &CN, &DN, &serialnumber, &SAN)
		// If key in map then...
		if val, ok := certsForEmail[email]; ok {
			val.PushBack(CertInfo{CN, DN, serialnumber, SAN})
		} else {
			certsForEmail[email] = list.New()
			certsForEmail[email].PushBack(CertInfo{CN, DN, serialnumber, SAN})
		}
	}

	smtp, canSendEmails := checkSMTP(smtpInfo)

	log.Println("CERTS ARE IN MAP, INSERTING INTO DATABASE")
	for email, certList := range certsForEmail {
		if canSendEmails {
			SendEmail(smtp, email, certList)
		}

		for e := certList.Front(); e != nil; e = e.Next() {
			cert := e.Value.(CertInfo)
			db.Exec("INSERT OR IGNORE INTO Certificate VALUES (?, ?, ?, ?)", cert.CN, cert.DN, cert.SerialNumber, cert.SAN)
		}
	}
}
