package sqldb

import (
	"container/list"
	"database/sql"
	"log"
	"strings"
    "gopkg.in/gomail.v2"
	"time"
	"strconv"
)

type CertInfo struct {
	CN string
	DN string
	SerialNumber string
	DNS string
}

type CTLogInfo struct {
	OldHeadIndex int64
	NewHeadIndex int64
}


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
		certificates += strings.Join([]string{cur.CN, cur.DN, cur.DNS, cur.SerialNumber},"\n")
	}

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
	row := db.QueryRow("SELECT lastIndex FROM CTLog WHERE url = ?", url)
	var lastIndex int64
	err := row.Scan(&lastIndex)

	return lastIndex, err
}


// Find monitored certificates, create a map of email -> certificate attributes and send out emails
func ParseDownloadedCertificates(db *sql.DB) {
	//TODO: possibly trim ends? For example cesnet.cz -> cesnet, to check cesnet.us
	query := `
		SELECT email, CN, DN, serialnumber, DNS
		FROM Downloaded
		INNER JOIN Monitor M ON INSTR(DN, M.domain) > 0 OR
		                        INSTR(DNS, M.domain) > 0;`

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
			DNS			 string
		)

		rows.Scan(&email, &CN, &DN, &serialnumber, &DNS)
		if val, ok := certsForEmail[email]; ok {
			val.PushBack(CertInfo{CN, DN, serialnumber,DNS})
		} else {
			certsForEmail[email] = list.New()
			certsForEmail[email].PushBack(CertInfo{CN, DN, serialnumber, DNS})
		}
	}

	log.Println("CERTS ARE IN MAP, INSERTING INTO DATABASE")
	for email, certList := range certsForEmail {
		SendEmail(email, certList)
		for e := certList.Front(); e != nil; e = e.Next() {
			cert := e.Value.(CertInfo)
			db.Exec("INSERT OR IGNORE INTO Certificate VALUES (?, ?, ?, ?)", cert.CN, cert.DN, cert.SerialNumber, cert.DNS)
		}
	}

	//CleanupDownloadTable(db)
}
