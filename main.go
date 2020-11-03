package main

import (
	sqldb "ctlog/db"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"

	ct "github.com/google/certificate-transparency-go"
	ct_tls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/net/publicsuffix"
)

// MatchIPv6 is a regular expression for validating IPv6 addresses
var MatchIPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

// MatchIPv4 is a regular expression for validating IPv4 addresses
var MatchIPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

//TODO: create map Log->Index
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

func scrubX509Value(bit string) string {
	bit = strings.Replace(bit, "\x00", "[0x00]", -1)
	bit = strings.Replace(bit, " ", "_", -1)
	return bit
}

func logNameToPath(name string) string {
	bits := strings.SplitN(name, "//", 2)
	return strings.Replace(bits[1], "/", "_", -1)
}

func outputWriter(o <-chan string) {
	for name := range o {
		fmt.Print(name)
		atomic.AddInt64(&outputCount, 1)
	}
	Wo.Done()
}

func inputParser(c <-chan CTEntry, o chan<- string, db *sql.DB) {
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

		// Valid input
		atomic.AddInt64(&inputCount, 1)

		var names = make(map[string]struct{})

		if suffix, err := publicsuffix.EffectiveTLDPlusOne(cert.Subject.CommonName); err == nil {
			// Make sure this looks like an actual hostname or IP address
			if !(MatchIPv4.Match([]byte(cert.Subject.CommonName)) ||
				MatchIPv6.Match([]byte(cert.Subject.CommonName))) &&
				(strings.Contains(cert.Subject.CommonName, " ") ||
					strings.Contains(cert.Subject.CommonName, ":")) {
				continue
			}
			//names[strings.ToLower(cert.Subject.CommonName)] = struct{}{}
			names[suffix] = struct{}{}
		}

		//get DNS names
		for _, alt := range cert.DNSNames {
			if _, err := publicsuffix.EffectiveTLDPlusOne(alt); err == nil {
				// Make sure this looks like an actual hostname or IP address
				if !(MatchIPv4.Match([]byte(cert.Subject.CommonName)) ||
					MatchIPv6.Match([]byte(cert.Subject.CommonName))) &&
					(strings.Contains(alt, " ") ||
						strings.Contains(alt, ":")) {
					continue
				}
				names[strings.ToLower(alt)] = struct{}{}
			}
		}

		//TODO: Postupy
		// a) stejne stahuju vsechny, nahrat do tmp tabulky, pak je vyfiltrovat, pak je poslat
		// b) kdyz ho stahnu, tak zkontroluju jestli ho monitoruju a nahraju ho do databaze, pak projedu databazi a poslu maily
		// za a) je lepsi

		isMonitored, err := sqldb.IsDomainMonitored(names, db)
		if err != nil {
			log.Printf("[-] Error while fetching domain being monitored -> %s\n", err)
			continue
		}


		if isMonitored {
			//thumbprint := sha1.Sum(cert.Raw)
			//sha1hash := hex.EncodeToString(thumbprint[:])

			//cert.Subject.String()
			o <- fmt.Sprintf("%s, subject: %s\n", names, cert.Subject.String())
		}
	}

	Wi.Done()
}

func main() {
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
	c_out := make(chan string)

	// Launch one input parser per core
	for i := 0; i < runtime.NumCPU(); i++ {
		go inputParser(c_inp, c_out, db)
	}
	Wi.Add(runtime.NumCPU())

	// Launch a single output writer
	go outputWriter(c_out)
	Wo.Add(1)

	// Make temp table for downloaded entries
	//sqldb.MakeTempTable(db)

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
}