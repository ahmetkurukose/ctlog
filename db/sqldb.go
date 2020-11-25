package sqldb

import (
	"container/list"
	"database/sql"
	"fmt"
	"log"
	"strings"
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


// Creates a connection to the database and returns it
func ConnectToDatabase() *sql.DB {
	db, err := sql.Open("sqlite3", "./db/certdb.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	return db
}

// Closes the database connection
func CloseConnection(db *sql.DB) {
	db.Close()
}

func CleanupDownloadTable(db *sql.DB) {
	db.Exec("DELETE FROM Downloaded")
}

func SendEmail(email string, certList *list.List) {

}

// Returns previous head index of a log
func GetLogIndex(url string, db *sql.DB) (int64, error) {
	row := db.QueryRow("SELECT lastIndex FROM CTLog WHERE url = ?", url)
	var lastIndex int64
	err := row.Scan(&lastIndex)

	return lastIndex, err
}

// Efficiently builds SQL query for IsDomainMonitored
func buildIsDomainMonitored(names map[string]struct{}) string {
	var builder strings.Builder

	fmt.Fprintf(&builder,"SELECT COUNT(DISTINCT domain) FROM Monitor WHERE")
	for name := range names {
		fmt.Fprintf(&builder, " domain = \"%s\" OR", name)
	}
	s := builder.String()
	return s[:builder.Len()-2]
}

// Checks if domain is being monitored
func IsDomainMonitored(names map[string]struct{}, db *sql.DB) (bool, error) {
	q := buildIsDomainMonitored(names)
	row := db.QueryRow(q)

	var result int64
	err := row.Scan(&result)
	if err != nil {
		log.Printf("[-] Error while fetching domain being monitored -> %s\n", err)
		return false, err
	}

	if result == 0 {
		return false, err
	} else {
		return true, err
	}
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
