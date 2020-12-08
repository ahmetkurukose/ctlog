package sqldb

import (
	"container/list"
	"database/sql"
	"log"
	"strings"
    "gopkg.in/gomail.v2"
	"time"
	"strconv"
	"regexp"
	"errors"
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

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
var domainRegex = regexp.MustCompile("^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9])).([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$")

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
func SendEmail(email string, certList *list.List) {
	t := time.Now()
	date := strings.Join([]string{strconv.Itoa(t.Day()), strconv.Itoa(int(t.Month())), strconv.Itoa(t.Year())}, ".")
	m := gomail.NewMessage()
	m.SetHeader("From", "ctlog@cesnet.cz")
	m.SetHeader("To", email)
	m.SetHeader("Subject", "New certificates " + date)

	certificates := ""
	for cert := certList.Front(); cert != nil; cert = cert.Next() {
		cur := cert.Value.(CertInfo)
		certificates += strings.Join([]string{cur.CN, cur.DN, cur.SAN, cur.SerialNumber},"\n")
	}
	certificates += "\n\n"

	//TESTING
	println(email)
	println(certificates)

	//
	//m.SetBody("text/html", "")
	//
	//d := gomail.NewDialer("ctlog@", 587, "user", "123456")
	//
	//// Send the email to Bob, Cora and Dan.
	//if err := d.DialAndSend(m); err != nil {
	//	log.Printf("[-] Failed sending email, %s\n", err)
	//}
}

// Returns previous head index of a log.
func GetLogIndex(url string, db *sql.DB) (int64, error) {
	row := db.QueryRow("SELECT HeadIndex FROM CTLog WHERE Url = ?", url)
	var lastIndex int64
	err := row.Scan(&lastIndex)

	return lastIndex, err
}


// Find monitored certificates, create a map of email -> certificate attributes and send out emails
func ParseDownloadedCertificates(db *sql.DB) {
	//TODO: possibly trim ends? For example cesnet.cz -> cesnet, to check cesnet.us

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

	log.Println("CERTS ARE IN MAP, INSERTING INTO DATABASE")
	for email, certList := range certsForEmail {
		SendEmail(email, certList)
		for e := certList.Front(); e != nil; e = e.Next() {
			cert := e.Value.(CertInfo)
			db.Exec("INSERT OR IGNORE INTO Certificate VALUES (?, ?, ?, ?)", cert.CN, cert.DN, cert.SerialNumber, cert.SAN)
		}
	}

	//CleanupDownloadTable(db)
}
