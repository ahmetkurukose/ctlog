package main

import (
	sqldb "ctlog/db"
	"database/sql"
	"flag"
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	ct_tls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"
)

// MatchIPv6 is a regular expression for validating IPv6 addresses
var MatchIPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

// MatchIPv4 is a regular expression for validating IPv4 addresses
var MatchIPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)


var CTLogs = []string{
	"https://ct.googleapis.com/logs/argon2019/",
	"https://ct.googleapis.com/logs/argon2020/",
	"https://ct.googleapis.com/logs/argon2021/",
	"https://ct.googleapis.com/logs/xenon2019/",
	"https://ct.googleapis.com/logs/xenon2020/",
	"https://ct.googleapis.com/logs/xenon2021/",
	"https://ct.googleapis.com/logs/xenon2022/",
	"https://ct.googleapis.com/aviator/",
	"https://ct.googleapis.com/icarus/",
	"https://ct.googleapis.com/pilot/",
	"https://ct.googleapis.com/rocketeer/",
	"https://ct.googleapis.com/skydiver/",
	"https://oak.ct.letsencrypt.org/2020/",
	"https://oak.ct.letsencrypt.org/2021/",
	"https://oak.ct.letsencrypt.org/2022/",
	"https://oak.ct.letsencrypt.org/2023/",
	//"https://ct.cloudflare.com/logs/nimbus2019/",
	//"https://ct.cloudflare.com/logs/nimbus2020/",
	//"https://ct.cloudflare.com/logs/nimbus2021/",
	//"https://ct.cloudflare.com/logs/nimbus2022/",
	//"https://ct.cloudflare.com/logs/nimbus2023/",
	//"https://ct1.digicert-ct.com/log/",
	//"https://ct2.digicert-ct.com/log/",
	//"https://yeti2019.ct.digicert.com/log/",
	//"https://yeti2020.ct.digicert.com/log/",
	//"https://yeti2021.ct.digicert.com/log/",
	//"https://yeti2022.ct.digicert.com/log/",
	//"https://yeti2023.ct.digicert.com/log/",
	//"https://nessie2019.ct.digicert.com/log/",
	//"https://nessie2020.ct.digicert.com/log/",
	//"https://nessie2021.ct.digicert.com/log/",
	//"https://nessie2022.ct.digicert.com/log/",
	//"https://nessie2023.ct.digicert.com/log/",
	//"https://ct.ws.symantec.com/",
	//"https://vega.ws.symantec.com/",
	//"https://sirius.ws.symantec.com/",
	//"https://log.certly.io/",
	//"https://ct.izenpe.com/",
	//"https://ctlog.wosign.com/",
	//"https://ctlog.api.venafi.com/",
	//"https://ctlog-gen2.api.venafi.com/",
	//"https://ctserver.cnnic.cn/",
	//"https://ct.startssl.com/",
	//"https://sabre.ct.comodo.com/",
	//"https://mammoth.ct.comodo.com/",
}

// BEST RESULTS SO FAR
//const INSERT_BUFFER_SIZE = 10000
//const DOWNLOADER_COUNT = 90
//const PARSE_BUFFER_SIZE = 1000
// THROUGHPUT 350k/10min, no visible throttling from log


var outputCount int64 = 0
var inputCount int64 = 0
var db *sql.DB
var startTime time.Time

const INSERT_BUFFER_SIZE = 10000
const DOWNLOADER_COUNT = 90
const DOWNLOAD_BUFFER_SIZE = DOWNLOADER_COUNT * BATCH_SIZE
const PARSE_BUFFER_SIZE = 1000
const BATCH_SIZE = 10
const PARSER_COUNT = 4

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Synchronizes data from one or more CT logs and extract hostnames")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

//FOR TESTING PURPOSES
func downloadAndUpdateHeads(db *sql.DB) {
	for l := range CTLogs {
		head, err := DownloadSTH(CTLogs[l])
		if err != nil {
			log.Fatal("Failed downloading log")
		}
		db.Exec("UPDATE CTLog SET lastIndex = ? WHERE url = ?", head.TreeSize, CTLogs[l])
	}
}


// Downloads the new STHs from the logs, returns a map of log url -> old and new index
func downloadHeads(db *sql.DB) (*map[string]sqldb.CTLogInfo, error){
	resultMap := make(map[string]sqldb.CTLogInfo)
	rows, err := db.Query("SELECT url, lastIndex FROM CTLog")
	if err != nil {
		log.Fatal("[-] Failed to query logurls from database -> ", err, "\n")
	}
	for rows.Next() {
		var url string
		var lastIndex int64
		err = rows.Scan(&url, &lastIndex)
		if err != nil {
			return nil, err
		}

		sth, err := DownloadSTH(url)
		if err != nil {
			return nil, err
		}
		resultMap[url] = sqldb.CTLogInfo{lastIndex, sth.TreeSize}
	}

	return &resultMap, err
}

// Removes items from the inserter channel and inserts them into the database
// Duplicates from multiple logs get ignored
// TODO: Maybe insert in batches?
func inserter(o <-chan sqldb.CertInfo, db *sql.DB) {
	q, _ := db.Prepare("INSERT OR IGNORE INTO Downloaded VALUES (?, ?, ?, ?)")
	defer q.Close()
	count := 0
	for name := range o {
		_, err := q.Exec(name.CN, name.DN, name.SerialNumber, name.DNS)
		if err != nil {
			log.Printf("Failed saving cert with CN: %s\nDN: %s\nDNS: %s\nSerialNumber: %s\n-> %s", name.CN, name.DN, name.DNS, name.SerialNumber, err)
		}
		atomic.AddInt64(&outputCount, 1)

		count++
		if count % 1000 == 0 {
			end := time.Now()
			println("O", end.Sub(startTime).String(), count / 1000)
		}
	}
	Wo.Done()
}


// Takes out and parses Merkle tree leaf into a certificate info struct
// Sends the result into the database inserter
func parser(id int, c <-chan CTEntry, o chan<- sqldb.CertInfo, db *sql.DB) {
	//count := 0
	defer Wp.Done()
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

		o <- sqldb.CertInfo{
			CN:           cert.Subject.CommonName,
			DN:           cert.Subject.String(),
			SerialNumber: cert.SerialNumber.String(),
			DNS:		  strings.Join(cert.DNSNames, " "),
		}

		//count++
		//println(count)
	}
}

func main() {
	log.Println("STARTING")
	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	logurl := flag.String("logurl", "", "Only read from the specified CT log url")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")

	flag.Parse()

	//-------PROFILING---------
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	//-------------------------


	db = sqldb.ConnectToDatabase()
	defer sqldb.CloseConnection(db)
	sqldb.CleanupDownloadTable(db)

	// Create http client
	CreateClient()

	// FOR TESTING PURPOSES
	downloadAndUpdateHeads(db)

	var logInfos *map[string]sqldb.CTLogInfo
	var err error
	// Distinguish between single and all log check
	// TODO: simplify this
	if *logurl != "" {
		index, err := sqldb.GetLogIndex(*logurl, db)
		if err != nil {
			log.Fatal("[-] Error while fetching log, closing -> err", err)
		}
		sth, err := DownloadSTH(*logurl)
		if err != nil {
			log.Fatal("[-] Error while fetching log, closing -> err", err)
		}
		*logInfos = make(map[string]sqldb.CTLogInfo)
		(*logInfos)[*logurl] = sqldb.CTLogInfo{index, sth.TreeSize}
	} else {
		logInfos, err = downloadHeads(db)
		if err != nil {
			log.Fatal("[-] Error while fetching logs, closing -> ", err)
		}
	}

	var all int64 = 0
	for u, i := range *logInfos {
		all += i.NewHeadIndex - i.OldHeadIndex
		fmt.Printf("%sct/v1/get-entries?start=%d&end=%d      %d\n", u, i.OldHeadIndex, i.NewHeadIndex - 1, i.NewHeadIndex - i.OldHeadIndex)
	}
	println("TO DOWNLOAD: ", all)


	// Create channels

	// Downloading
	//c_down := make(chan string, DOWNLOAD_BUFFER_SIZE)

	// Parsing
	c_parse := make(chan CTEntry, PARSE_BUFFER_SIZE)

	// Inserting into database
	c_insert := make(chan sqldb.CertInfo, INSERT_BUFFER_SIZE)

	// Launch parsers
	for i := 0; i < PARSER_COUNT; i++ {
		go parser(i, c_parse, c_insert, db)
	}
	Wp.Add(PARSER_COUNT)

	// Launch downloaders, not sure about the number
	//for i:= 0; i < DOWNLOADER_COUNT; i++ {
	//	go BatchDownloader(c_down, c_parse)
	//}
	//Wd.Add(DOWNLOADER_COUNT)

	// Launch a single output writer
	go inserter(c_insert, db)
	Wo.Add(1)

	// Start timer for download
	startTime = time.Now()

	// Start queueing downloads for each log
 	for url, headInfo := range *logInfos {
 		//go BatchGenerator(c_down, url, headInfo.OldHeadIndex, headInfo.NewHeadIndex, db, BATCH_SIZE)
		go distributeWork(headInfo.OldHeadIndex, headInfo.NewHeadIndex, 25, url, c_parse)
 		Wg.Add(1)
	}

	// Wait for generators
	Wg.Wait()

 	// Everything generated, close to-download channel
 	//close(c_down)

 	// Wait for downloaders
 	Wd.Wait()
	downloadEndTime := time.Now()
	log.Println("FINISHED DOWNLOADING")
	log.Println("Download duration = ", downloadEndTime.Sub(startTime))

 	// Everything downloaded, close to-parse channel
	close(c_parse)

 	// Wait for parsers
 	Wp.Wait()
	//parserEndTime := time.Now()
	log.Println("FINISHED PARSING")


 	// Everything parsed, close to-insert channel
 	close(c_insert)

 	// Wait for the inserter
 	Wo.Wait()
	//insertEndTime := time.Now()

 	// Finished inserting, start working with the data
 	log.Println("FINISHED INSERTING")
	sqldb.ParseDownloadedCertificates(db)
 	log.Println("FINISHED SENDING EMAILS, EXITING")
}