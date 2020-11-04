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
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"
)

// MatchIPv6 is a regular expression for validating IPv6 addresses
var MatchIPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

// MatchIPv4 is a regular expression for validating IPv4 addresses
var MatchIPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

type CertInfo struct {
	CN string
	DN string
	SerialNumber string
}

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

var outputCount int64 = 0
var inputCount int64 = 0
var db *sql.DB


func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Synchronizes data from one or more CT logs and extract hostnames")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func downloadHeads() {
	for l := range CTLogs {
		head, err := DownloadSTH(CTLogs[l])
		if err != nil {
			log.Fatal("Failed downloading log")
		}
		db.Exec("UPDATE CTLog SET lastIndex = ? WHERE url = ?", head.TreeSize, CTLogs[l])
	}
}

//TODO: Probably not needed
func outputWriter(o <-chan CertInfo, db *sql.DB) {
	for name := range o {
		_, err := db.Exec("INSERT OR IGNORE INTO Downloaded VALUES (?, ?, ?)", name.CN, name.DN, name.SerialNumber)
		if err != nil {
			log.Printf("Failed saving cert with CN: %s\nDN: %s\nSerialNumber: %s\n-> %s", name.CN, name.DN, name.SerialNumber, err)
		}
		atomic.AddInt64(&outputCount, 1)
	}
	Wo.Done()
}

func inputParser(c <-chan CTEntry, o chan<- CertInfo, db *sql.DB) {
	for entry := range c {
		var leaf ct.MerkleTreeLeaf

		if rest, err := ct_tls.Unmarshal(entry.LeafInput, &leaf); err != nil {
			log.Printf("[-] Failed to unmarshal MerkleTreeLeaf: %v (%v)", err, entry)
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
			log.Printf("[-] Unknown entry type: %v (%v)", leaf.TimestampedEntry.EntryType, entry)
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

		o <- CertInfo{
			CN:           cert.Subject.CommonName,
			DN:           cert.Subject.String(),
			SerialNumber: cert.SerialNumber.String(),
		}
	}

	Wi.Done()
}

func main() {
	startTime := time.Now()
	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	logurl := flag.String("logurl", "", "Only read from the specified CT log url")

	flag.Parse()
	db = sqldb.ConnectToDatabase()
	defer sqldb.CloseConnection(db)

	logIndexes := make(map[string]int64)
	var err error
	// Distinguish between single and all log check
	if *logurl != "" {
		index, err := sqldb.GetLogIndex(*logurl, db)
		if err != nil {
			log.Fatal("[-] Error while fetching log, closing -> err", err)
		}
		logIndexes[*logurl] = index
	} else {
		logIndexes, err = sqldb.GetLogURLsAndIndexes(db)
		if err != nil {
			log.Fatal("[-] Error while fetching logs, closing -> ", err)
		}
	}


	// Input
	c_inp := make(chan CTEntry)

	// Output
	c_out := make(chan CertInfo)

	// Launch one input parser per core
	for i := 0; i < runtime.NumCPU(); i++ {
		go inputParser(c_inp, c_out, db)
	}
	Wi.Add(runtime.NumCPU())

	// Launch a single output writer
	go outputWriter(c_out, db)
	Wo.Add(1)

	// Start downloading for each log
 	for url, headIndex := range logIndexes {
		go DownloadLog(url, c_inp, headIndex, db)
		Wd.Add(1)
	}


	// Wait for downloaders
	Wd.Wait()

	// Close the input channel
	close(c_inp)

	// Wait for the input parsers
	Wi.Wait()

	// Close the output handle
	close(c_out)

	// Wait for the output goroutine
	Wo.Wait()


 	// Finished downloading, start working with the data
 	downloadEndTime := time.Now()
 	log.Println("Download duration = ", downloadEndTime.Sub(startTime))
	if inputCount != outputCount {
 		log.Printf("Input doesn't match output\n")
	} else {
		log.Printf("Input matches output, %d\n", inputCount)
	}

	sqldb.ParseDownloadedCertificates(db)
}