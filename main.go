package main

import (
	ct "ctlog/ct"
	sqldb "ctlog/db"
	"database/sql"
	"flag"
	"fmt"
	ct_tls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"
)

// MatchIPv6 is a regular expression for validating IPv6 addresses
var MatchIPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

// MatchIPv4 is a regular expression for validating IPv4 addresses
var MatchIPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

var outputCount int64 = 0
var inputCount int64 = 0
var startTime time.Time

const INSERT_BUFFER_SIZE = 10000
const DOWNLOADER_COUNT = 30
const PARSE_BUFFER_SIZE = 1000
const PARSER_COUNT = 4

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Downloads certificates from certificate transparency logs and filters them")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

// For testing purposes, updates the log head index, reducing the amount of data to the minimum
func updateHeads(logInfoMap *map[string]sqldb.CTLogInfo, db *sql.DB) {
	for url, logInfo := range *logInfoMap {
		if _, err := db.Exec("UPDATE CTLog SET HeadIndex = $1 WHERE Url = $2", logInfo.NewHeadIndex, url); err != nil {
			log.Printf("[-] Failed updating head -> %s\n", err)
		}
	}
}

// Downloads the new STHs from the logs, returns a map of log url -> old and new index
func downloadHeads(db *sql.DB) (*map[string]sqldb.CTLogInfo, error) {
	resultMap := make(map[string]sqldb.CTLogInfo)
	rows, err := db.Query("SELECT Url, HeadIndex FROM public.CTLog")
	if err != nil {
		log.Fatal("[-] Failed to query logurls from database -> ", err, "\n")
	}
	for rows.Next() {
		var url string
		var headIndex int64
		err = rows.Scan(&url, &headIndex)
		if err != nil {
			return nil, err
		}

		sth, err := DownloadSTH(url)
		if err != nil {
			return nil, err
		}
		resultMap[url] = sqldb.CTLogInfo{headIndex, sth.TreeSize - 1}
	}

	return &resultMap, err
}

// Removes items from the inserter channel and inserts them into the database
// Duplicates from multiple logs get ignored
func inserter(o <-chan sqldb.CertInfo, db *sql.DB) {
	q, _ := db.Prepare("INSERT INTO Downloaded VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING ")
	defer q.Close()
	count := 0
	for name := range o {
		_, err := q.Exec(name.CN, name.DN, name.SerialNumber, name.SAN, name.NotBefore, name.NotAfter, name.Issuer)
		if err != nil {
			log.Printf("Failed saving cert with CN: %s\nDN: %s\nDNS: %s\nSerialNumber: %s\n-> %s", name.CN, name.DN, name.SAN, name.SerialNumber, err)
		}
		atomic.AddInt64(&outputCount, 1)

		count++
		if count%1000000 == 0 {
			end := time.Now()
			println("O", end.Sub(startTime).String(), count/1000000)
		}
	}

	log.Printf("TOTAL INSERTED %d\n", count)
	Wo.Done()
}

// Takes out and parses Merkle tree leaf into a certificate info struct
// Sends the result into the database inserter
func parser(c <-chan CTEntry, o chan<- sqldb.CertInfo, db *sql.DB) {
	defer Wp.Done()
	sum := 0.0
	sum_extra := 0.0
	cnt := 0

	// Represents <1000, 1001 - 2000, 2001 - 3000, 3001 - 4000, 4001<
	cnts := [5]int{0, 0, 0, 0, 0}
	for e := range c {
		var leaf ct.MerkleTreeLeaf

		if rest, err := ct_tls.Unmarshal(e.LeafInput, &leaf); err != nil {
			log.Printf("[-] Failed to unmarshal MerkleTreeLeaf: %v (%v)", err, e)
			continue
		} else if len(rest) > 0 {
			log.Printf("[-] Trailing data (%d bytes) after MerkleTreeLeaf: %q", len(rest), rest)
			continue
		}

		var cert *x509.Certificate
		var err error

		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			cert, err = x509.ParseCertificate(leaf.TimestampedEntry.X509Entry.Data)
			if err != nil && !strings.Contains(err.Error(), "NonFatalErrors:") {
				log.Printf("[-] Failed to parse cert: %s\n", err.Error())
				continue
			}

		case ct.PrecertLogEntryType:
			cert, err = x509.ParseTBSCertificate(leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil && !strings.Contains(err.Error(), "NonFatalErrors:") {
				log.Printf("[-] Failed to parse precert: %s\n", err.Error())
				continue
			}

		default:
			log.Printf("[-] Unknown entry type: %v (%v)", leaf.TimestampedEntry.EntryType, e)
			continue
		}

		if _, err := publicsuffix.EffectiveTLDPlusOne(cert.Subject.CommonName); err == nil {
			// Make sure this looks like an actual hostname or IP address
			if !(MatchIPv4.Match([]byte(cert.Subject.CommonName)) ||
				MatchIPv6.Match([]byte(cert.Subject.CommonName))) &&
				(strings.Contains(cert.Subject.CommonName, " ") ||
					strings.Contains(cert.Subject.CommonName, ":") ||
					strings.TrimSpace(cert.Subject.CommonName) == "") {
				continue
			}
		}

		// Valid input
		atomic.AddInt64(&inputCount, 1)

		san := ""
		if len(cert.DNSNames) > 0 {
			san = strings.Join(cert.DNSNames, ",")
			san += ","
		}

		size := len(cert.Raw)
		size_extra := size + 4*(len(cert.Subject.CommonName)+
			len(cert.SerialNumber.Text(16))+
			len(san)+
			len(cert.NotBefore.Format("2006-01-02 15:04:05"))+
			len(cert.NotAfter.Format("2006-01-02 15:04:05")))

		sum += float64(size) / 1000
		sum_extra += float64(size_extra) / 1000
		cnt++

		if size < 1000 {
			cnts[0]++
		} else if size < 2000 {
			cnts[1]++
		} else if size < 3000 {
			cnts[2]++
		} else if size < 4000 {
			cnts[3]++
		}

		o <- sqldb.CertInfo{
			CN:           cert.Subject.CommonName,
			DN:           cert.Subject.String(),
			SerialNumber: cert.SerialNumber.Text(16),
			SAN:          san,
			NotBefore:    cert.NotBefore.Format("2006-01-02 15:04:05"),
			NotAfter:     cert.NotAfter.Format("2006-01-02 15:04:05"),
			Issuer:       cert.Issuer.String(),
		}
	}

	log.Println("Total size: ", sum*PARSER_COUNT)
	log.Println("Total size plus what we want to save: ", sum_extra*PARSER_COUNT)
	log.Println("Average size: ", sum/float64(cnt))
}

func run(dumpFile bool, db *sql.DB) {
	var logInfos *map[string]sqldb.CTLogInfo
	var err error

	logInfos, err = downloadHeads(db)
	if err != nil {
		// Try to recover
		sec := 1
		for err != nil {
			time.Sleep(time.Duration(sec) * time.Second)
			logInfos, err = downloadHeads(db)
			sec += 1
			if sec == 50 {
				log.Fatal("[-] Timed out while downloading heads")
			}
		}
	}

	// FOR TESTING PURPOSES
	updateHeads(logInfos, db)

	// Print the amounts to download from each log and then the sum
	var all int64 = 0
	for u, i := range *logInfos {
		all += i.NewHeadIndex - i.OldHeadIndex
		fmt.Printf("%sct/v1/get-entries?start=%d&end=%d      %d\n", u, i.OldHeadIndex, i.NewHeadIndex, i.NewHeadIndex-i.OldHeadIndex)
	}
	println("TO DOWNLOAD: ", all)

	sqldb.CreateTempLogTable(db)

	// Create channels

	// Parsing
	c_parse := make(chan CTEntry, PARSE_BUFFER_SIZE)

	// Inserting into database
	c_insert := make(chan sqldb.CertInfo, INSERT_BUFFER_SIZE)

	// Launch parsers
	for i := 0; i < PARSER_COUNT; i++ {
		go parser(c_parse, c_insert, db)
	}
	Wp.Add(PARSER_COUNT)

	// Launch a database inserter
	go inserter(c_insert, db)
	Wo.Add(1)

	// Start timer for download
	startTime = time.Now()

	// Start queueing downloads for each log
	for url, headInfo := range *logInfos {
		Wg.Add(1)
		go distributeWork(headInfo.OldHeadIndex, headInfo.NewHeadIndex, DOWNLOADER_COUNT, url, c_parse, db)
	}

	// Wait for work distributors
	Wg.Wait()

	// Wait for downloaders
	Wd.Wait()

	// Update log indexes
	for url, headInfo := range *logInfos {
		saveLogIndex(headInfo.NewHeadIndex, url, db)
	}

	downloadEndTime := time.Now()
	log.Println("FINISHED DOWNLOADING")
	log.Println("Download duration = ", downloadEndTime.Sub(startTime))

	// Everything downloaded, close to-parse channel
	close(c_parse)

	// Wait for parsers
	Wp.Wait()
	log.Println("FINISHED PARSING")

	// Everything parsed, close to-insert channel
	close(c_insert)

	// Wait for the inserter
	Wo.Wait()

	// Finished inserting, start working with the data
	log.Println("FINISHED INSERTING")

	insertTimeLength := time.Now().Sub(startTime).Hours()
	log.Println("THROUGHPUT: ", float64(inputCount)/insertTimeLength)

	if dumpFile {
		log.Println("CREATING FILE FOR API")
		sqldb.CreateDownloadedFile(db)
		log.Println("FILE CREATED")
	}

	log.Println("PARSING")
	sqldb.ParseDownloadedCertificates(db)
	log.Println("FINISHED SENDING EMAILS")

	sqldb.UpdateLogIndexes(db)
	sqldb.DeleteExpiredCertificates(db)
	log.Println("THE END")
}

func main() {
	log.Println("STARTING")
	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	database := flag.String("db", "", "REQUIRED, path to database")
	norun := flag.Bool("norun", false, "Do not run the scan")
	dumpFile := flag.Bool("dump", false, "Dump the downloaded certificate to a dump file")

	flag.Parse()

	if *database == "" {
		log.Fatal("[-] No database")
	}

	db := sqldb.ConnectToDatabase(*database)
	defer sqldb.CloseConnection(db)
	sqldb.CleanupDownloadTable(db)

	// Create http client
	CreateClient()

	if *norun {
		log.Printf("NORUN")
	} else {
		run(*dumpFile, db)
	}
}
