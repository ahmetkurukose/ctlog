package sqldb

import (
	"container/list"
	"database/sql"
	"encoding/json"
	"errors"
	_ "github.com/jackc/pgx/v4/stdlib"
	"log"
	"os"
	"regexp"
	"time"
)

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

// Returns previous head index of a log.
func GetLogIndex(url string, db *sql.DB) (int64, error) {
	row := db.QueryRow("SELECT HeadIndex FROM CTLog WHERE Url = $1", url)
	var lastIndex int64
	err := row.Scan(&lastIndex)

	return lastIndex, err
}

// Find monitored certificates, create a map of email -> certificate attributes and send out emails
func ParseDownloadedCertificates(db *sql.DB) {
	//If we check cesnet.cz, we should check: 'cesnet.cz',
	//										  'www.cesnet.cz',
	//										  '*.cesnet.cz'
	// and the SAN for '*\ncesnet.cz' and '*.cesnet.cz*'

	//INSTR -> POSITION
	query := `
SELECT DISTINCT Email, CN, DN, SerialNumber, SAN, NotBefore, NotAfter, Issuer
		FROM Downloaded
        INNER JOIN Monitor M ON CN = concat('www.', M.Domain) OR
                                CN LIKE concat('%.', M.Domain) OR
                                SAN LIKE concat(E'\n', M.Domain, '%') OR
                                position(concat('.', M.Domain) IN SAN) > 0;`

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("[-] Error while parsing downloaded certificates -> %s\n", err)
	}
	defer rows.Close()

	certsForEmail := make(map[string]*list.List)

	count := 0
	for rows.Next() {
		var (
			email        string
			CN           string
			DN           string
			serialNumber string
			SAN          string
			notBefore    string
			notAfter     string
			issuer       string
		)

		rows.Scan(&email, &CN, &DN, &serialNumber, &SAN, notBefore, notAfter)

		if val, ok := certsForEmail[email]; ok {
			val.PushBack(CertInfo{CN, DN, serialNumber, SAN, notBefore, notAfter, issuer})
		} else {
			certsForEmail[email] = list.New()
			certsForEmail[email].PushBack(CertInfo{CN, DN, serialNumber, SAN, notBefore, notAfter, issuer})
		}

		count++
	}

	log.Println("FOUND ", count, " CERTIFICATES")
	log.Println("INSERTING INTO DATABASE AND SENDING OUT EMAILS")
	for email, certList := range certsForEmail {
		SendEmail(email, certList)

		for e := certList.Front(); e != nil; e = e.Next() {
			cert := e.Value.(CertInfo)
			db.Exec("INSERT OR IGNORE INTO Certificate VALUES ($1, $2, $3, $4, $5, $6, $7)", cert.CN, cert.DN, cert.SerialNumber, cert.SAN, cert.NotBefore, cert.NotAfter, cert.Issuer)
		}
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
