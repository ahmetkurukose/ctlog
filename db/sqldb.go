package sqldb

import (
	"database/sql"
	"encoding/json"
	_ "github.com/jackc/pgx/v4/stdlib"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

type MonitoredCerts struct {
	Email        string     `json:"email"`
	Certificates []CertInfo `json:"certs"`
}

type CertInfo struct {
	CN           string
	DN           string
	SerialNumber string
	SAN          string
	NotBefore    string
	NotAfter     string
	Issuer       string
}

type APIData struct {
	CN        string
	SAN       []string
	NotBefore string
	NotAfter  string
}

type CTLogInfo struct {
	OldHeadIndex int64
	NewHeadIndex int64
}

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
var domainRegex = regexp.MustCompile("^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9])).([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$")

// Creates a connection to the database and returns it.
func ConnectToDatabase(database string) *sql.DB {
	db, err := sql.Open("pgx", database)
	if err != nil {
		log.Fatal(err)
	}

	if err = db.Ping(); err != nil {
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

// Create a temporary table to save new CT log head indexes, so we can reroll in case of an error
func CreateTempLogTable(db *sql.DB) {
	// Delete the table if it's still here from the last run
	_, err := db.Exec("DROP TABLE IF EXISTS TMPCtlog")
	if err != nil {
		log.Fatal(err.Error())
	}

	_, err = db.Exec("SELECT * INTO TmpCTLog FROM CTLog")
	if err != nil {
		log.Fatal(err.Error())
	}
}

// No error occurred during the program running, update the logs
func UpdateLogIndexes(db *sql.DB) {
	_, err := db.Exec("DROP TABLE CTLog")
	if err != nil {
		log.Fatal(err.Error())
	}
	_, err = db.Exec("ALTER TABLE TmpCTLog RENAME TO CTLog")
	if err != nil {
		log.Fatal(err.Error())
	}
}

// Find monitored certificates, create a map of email -> certificate attributes and send out emails
func ParseDownloadedCertificates(db *sql.DB) {
	// Super ugly, but it is the only way to remove duplicates after the join I've found
	rows, err := db.Query(`
	WITH
	INSERTED AS (
		INSERT INTO Certificate
		SELECT DISTINCT CN, DN, SerialNumber, SAN, NotBefore, NotAfter, Issuer
		FROM Downloaded
		INNER JOIN Monitor M ON CN = M.Domain OR
			CN = concat('www.', M.Domain) OR
			CN LIKE concat('%.', M.Domain) OR
			SAN LIKE concat(',', M.Domain, '%') OR
			position(concat('.', M.Domain) IN SAN) > 0
		ON CONFLICT DO NOTHING
		RETURNING CN, DN, SerialNumber, SAN, NotBefore, NotAfter, Issuer
	),
	CERTS AS (
		SELECT DISTINCT CN, DN, SerialNumber, SAN, NotBefore, NotAfter, Issuer, Email
		FROM INSERTED
		INNER JOIN Monitor M ON CN = M.Domain OR
			CN = concat('www.', M.Domain) OR
			CN LIKE concat('%.', M.Domain) OR
			SAN LIKE concat(',', M.Domain, '%') OR
			position(concat('.', M.Domain) IN SAN) > 0
	)
	
	SELECT json_build_object(
		'email', Email,
		'certs', json_agg(CERTS.*))
	FROM CERTS
	GROUP BY Email;
	`)

	if err != nil {
		log.Fatal(err.Error())
	}
	defer rows.Close()

	var results []MonitoredCerts
	count := 0
	for rows.Next() {
		var res MonitoredCerts
		var tmp []byte
		err = rows.Scan(&tmp)
		if err != nil {
			log.Fatal(err)
		}

		err := json.Unmarshal(tmp, &res)
		if err != nil {
			log.Fatal(err)
		}

		count += len(res.Certificates)
		results = append(results, res)
	}

	log.Println("FOUND ", count, " CERTIFICATES")
	log.Println("SENDING EMAILS")
	for _, r := range results {
		SendEmail(r)
	}
}

func CreateDownloadedFile(db *sql.DB) {
	fname := "/var/www/html/" + time.Now().Format("02_01_06") + ".jsonl"

	// Create file
	tmp, err := os.OpenFile(fname, os.O_CREATE, 0777)
	if err != nil {
		log.Printf("[-] Failed opening dump file -> %s\n", err)
		return
	}
	tmp.Close()

	query := "SELECT DISTINCT CN, SAN, NotBefore, NotAfter FROM Downloaded WHERE CN!='' OR SAN!=''"
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("[-] Failed creating query for data dump -> %s\n", err)
		return
	}

	file, err := os.OpenFile(fname, os.O_TRUNC|os.O_WRONLY, 060)
	if err != nil {
		log.Printf("[-] Failed opening file for writing -> %s\n", err)
		return
	}
	defer file.Close()

	for rows.Next() {
		var (
			CN        string
			SAN       string
			notBefore string
			notAfter  string
		)

		err := rows.Scan(&CN, &SAN, &notBefore, &notAfter)

		if err != nil {
			log.Printf("[-] Failed retrieving data for data dump -> %s\n", err)
			continue
		}

		sanArr := strings.Split(strings.TrimSuffix(SAN, ","), ",")

		tmp, err := json.Marshal(APIData{
			CN:        CN,
			SAN:       sanArr,
			NotBefore: notBefore,
			NotAfter:  notAfter,
		})

		if err != nil {
			log.Printf("[-] Failed creating json -> %s\n", err)
		}

		tmp = append(tmp, '\n')
		if _, err := file.Write(tmp); err != nil {
			log.Printf("[-] Failed writing to file -> %s\n", err)
		}
	}
}

func DeleteExpiredCertificates(db *sql.DB) {
	_, err := db.Exec("DELETE FROM Certificate WHERE now() > to_date(NotAfter, 'YYYY-MM-DD HH24:MI:SS');")
	if err != nil {
		log.Fatal(err.Error())
	}
}
