package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var Wd sync.WaitGroup
var Wp sync.WaitGroup
var Wo sync.WaitGroup
var Wg sync.WaitGroup

type CTBatchData struct {
	Url string
	StartIndex int64
	StopIndex int64
}

type CTEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type CTEntries struct {
	Entries []CTEntry `json:"entries"`
}

type CTEntriesError struct {
	ErrorMessage string `json:"error_message"`
	Success      bool   `json:"success"`
}

type CTHead struct {
	TreeSize          int64  `json:"tree_size"`
	Timestamp         int64  `json:"timestamp"`
	SHA256RootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

// Downloads the entries as JSON.
//TODO: create only one transport and one client
func downloadJSON(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, err
	}

	req.Header.Set("Accept", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	return content, err
}

// Downloads entries and returns them.
func DownloadEntries(url string) (CTEntries, error) {
	var entries CTEntries
	var entriesError CTEntriesError

	data, err := downloadJSON(url)
	if err != nil {
		return entries, err
	}

	if strings.Contains(string(data), "\"error_message\":") {
		err = json.Unmarshal(data, &entriesError)
		if err != nil {
			return entries, err
		}
		return entries, errors.New(entriesError.ErrorMessage)
	}

	err = json.Unmarshal(data, &entries)
	return entries, err
}

// Downloads the CT Head of the log.
func DownloadSTH(logurl string) (CTHead, error) {
	var sth CTHead
	url := fmt.Sprintf("%sct/v1/get-sth", logurl)
	data, err := downloadJSON(url)
	if err != nil {
		return sth, err
	}

	err = json.Unmarshal(data, &sth)
	return sth, err
}


func UpdateLogIndex(index int64, logurl string) {
	_, err := db.Exec("UPDATE CTLog SET lastIndex = ? WHERE url = ?", index, logurl)
	if err != nil {
		log.Printf("[-] Failed to update head index of log %s -> %s\n", logurl, err)
		return
	}
}


// Generates urls batches of data, sends them to the download channel
func BatchGenerator(c_down chan<- string, logurl string, startIndex int64, stopIndex int64, db *sql.DB, batchSize int64) {
	defer Wg.Done()
	for cur := startIndex; cur < stopIndex; cur += batchSize {
		curStop := cur + batchSize - 1
		if curStop >= stopIndex {
			curStop = stopIndex - 1
		}

		c_down <- fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d", logurl, cur, curStop)
	}
}


// Removes url, start and stop index from to-download channel,
// downloads the entries and sends them over to the parsers.
func BatchDownloader(c_down <-chan string, c_parse chan<- CTEntry) {
	defer Wd.Done()
	const RETRY_WAIT int = 1
	for url := range c_down {
		entries, err := DownloadEntries(url)

		attempts := 0
		for err != nil {
			time.Sleep(time.Duration(RETRY_WAIT * attempts) * time.Second)
			log.Printf("[-] (%d) Failed to download entries for %s -> %s\n", attempts, url, err)
			entries, err = DownloadEntries(url)
			attempts++
			if attempts >= 10 {
				log.Printf("[-] Failed to download entries for %s -> %s\n", url, err)
			}
		}

		for i := range entries.Entries {
			c_parse <- entries.Entries[i]
		}

		// Throttle download speed
		// TODO: optimize this, so far 1 second worked the best
		time.Sleep(time.Duration(1) * time.Second)
	}
}