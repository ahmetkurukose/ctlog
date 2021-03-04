package sqldb

import (
	"database/sql"
	"encoding/json"
	"errors"
	_ "github.com/jackc/pgx/v4/stdlib"
	"log"
	"os"
	"regexp"
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
	SAN       string
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
		_, err := db.Exec("INSERT INTO Monitor VALUES ($1, $2) ON CONFLICT DO NOTHING", email, domains[i])
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

	_, err := db.Exec("DELETE FROM Monitor WHERE Email = $1 AND Domain = $2", email, domain)

	return err
}

// Create a temporary table to save new CT log head indexes, so we can reroll in case of an error
func CreateTempLogTable(db *sql.DB) {
	// delete the table if it's still here from the last run
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
	rows, err := db.Query(`
	WITH CERTS AS (
		INSERT INTO Certificate
		SELECT DISTINCT CN, DN, SerialNumber, SAN, NotBefore, NotAfter, Issuer
		FROM Downloaded
		INNER JOIN Monitor M ON CN = M.Domain OR
			CN = concat('www.', M.Domain) OR
			CN LIKE concat('%.', M.Domain) OR
			SAN LIKE concat(E'\n', M.Domain, '%') OR
			position(concat('.', M.Domain) IN SAN) > 0
		ON CONFLICT DO NOTHING
		RETURNING CN, DN, SerialNumber, SAN, NotBefore, NotAfter, Issuer
	)

	SELECT json_build_object(
		'email', Email,
		'certs', json_agg(CERTS.*)
	)
	FROM CERTS
	INNER JOIN Monitor M ON CN = M.Domain OR
		CN = concat('www.', M.Domain) OR
		CN LIKE concat('%.', M.Domain) OR
		SAN LIKE concat(E'\n', M.Domain, '%') OR
		position(concat('.', M.Domain) IN SAN) > 0
	GROUP BY Email;`)

	if err != nil {
		log.Fatal(err.Error())
	}
	defer rows.Close()

	var results []MonitoredCerts
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

		println(res.Email)

		results = append(results, res)
	}

	log.Println("INSERTING INTO DATABASE AND SENDING OUT EMAILS")
	for _, r := range results {
		SendEmail(r)
	}
}

func CreateDownloadedFile(dumpFile string, db *sql.DB) {
	first := true

	query := "SELECT CN, SAN, NotBefore, NotAfter FROM Downloaded"
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("[-] Failed creating query for data dump -> %s\n", err)
		return
	}

	file, err := os.OpenFile(dumpFile, os.O_TRUNC|os.O_WRONLY, 060)
	if err != nil {
		log.Println("")
	}
	defer file.Close()

	toWrite := "{ \"Created\": \"" + time.Now().Format("2.1.2006") + "\", \"data\" : ["

	if _, err := file.Write([]byte(toWrite)); err != nil {
		log.Printf("[-] Failed writing to file -> %s\n", err)
	}

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
		}

		tmp, err := json.Marshal(APIData{
			CN:        CN,
			SAN:       SAN,
			NotBefore: notBefore,
			NotAfter:  notAfter,
		})

		if err != nil {
			log.Printf("[-] Failed creating json -> %s\n", err)
		}

		if !first {
			if _, err := file.Write([]byte(",")); err != nil {
				log.Printf("[-] Failed writing to file -> %s\n", err)
			}
		}

		if _, err := file.Write(tmp); err != nil {
			log.Printf("[-] Failed writing to file -> %s\n", err)
		}

		first = false
	}

	if _, err := file.Write([]byte("]}")); err != nil {
		log.Printf("[-] Failed writing to file -> %s\n", err)
	}
}
