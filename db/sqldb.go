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

// Returns a map of log URLs and their head indexes
func GetLogURLsAndIndexes(db *sql.DB) (map[string]int64, error) {
	resultMap := make(map[string]int64)
	rows, err := db.Query("SELECT url, lastIndex FROM CTLog")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var url string
		var lastIndex int64
		err := rows.Scan(&url, &lastIndex)
		if err != nil {
			return nil, err
		}
		resultMap[url] = lastIndex
	}

	return resultMap, err
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

func ParseDownloadedCertificates(db *sql.DB) {
	println("PARSING")

	query := `
		SELECT email, CN, DN, serialnumber
		FROM Downloaded
		INNER JOIN Monitor M ON INSTR(CN, M.domain) > 0;`

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
		)

		rows.Scan(&email, &CN, &DN, &serialnumber)
		if val, ok := certsForEmail[email]; ok {
			val.PushBack(CertInfo{CN, DN, serialnumber})
		} else {
			certsForEmail[email] = list.New()
			certsForEmail[email].PushBack(CertInfo{CN, DN, serialnumber})
		}
	}

	log.Println("CERTS ARE IN MAP, INSERTING INTO DATABASE")
	for email, certList := range certsForEmail {
		SendEmail(email, certList)
		for e := certList.Front(); e != nil; e = e.Next() {
			cert := e.Value.(CertInfo)
			db.Exec("INSERT OR IGNORE INTO Certificate VALUES (?, ?, ?)", cert.CN, cert.DN, cert.SerialNumber)
		}
	}

	//CleanupDownloadTable(db)
}
