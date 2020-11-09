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
var Wi sync.WaitGroup
var Wo sync.WaitGroup

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
func DownloadJSON(url string) ([]byte, error) {
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
func DownloadEntries(logurl string, startIndex int64, stopIndex int64) (CTEntries, error) {
	var entries CTEntries
	var entriesError CTEntriesError

	url := fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d", logurl, startIndex, stopIndex)
	data, err := DownloadJSON(url)
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
	data, err := DownloadJSON(url)
	if err != nil {
		return sth, err
	}

	err = json.Unmarshal(data, &sth)
	return sth, err
}

func downloadBatch(logurl string ,index int64, stopIndex int64, c_inp chan<- CTEntry) {
	const RETRY_WAIT int = 1
	entries, err := DownloadEntries(logurl, index, stopIndex)

	//Keep retrying
	attempts := 0
	for err != nil {
		time.Sleep(time.Duration(RETRY_WAIT) * time.Second)
		//log.Printf("[-] (%d) Failed to download entries for %s: index %d -> %s\n", attempts, logurl, index, err)
		entries, err = DownloadEntries(logurl, index, stopIndex)
		attempts++
		if attempts >= 10 {
			log.Printf("[-] Canceling, failed to download entries for %s: index %d -> %s\n", logurl, index, err)
			return
		}
	}
	for entryIndex := range entries.Entries {
		c_inp <- entries.Entries[entryIndex]
	}
}

// Goroutine that downloads log entries in batches of ENTRY_COUNT.
// Updates the log's head index in the database.
func DownloadLog(logurl string, c_inp chan<- CTEntry, startIndex int64, db *sql.DB, batchSize int64) {
	defer Wd.Done()

	sth, err := DownloadSTH(logurl)
	if err != nil {
		log.Printf("[-] Failed to download STH for %s -> %s\n", logurl, err)
		return
	}

	// Start the downloading
	//TODO: make it concurrent
	for index := startIndex; index < sth.TreeSize; index += batchSize {
		stopIndex := index + batchSize - 1
		if stopIndex >= sth.TreeSize {
			stopIndex = sth.TreeSize - 1
		}

		downloadBatch(logurl, index, stopIndex, c_inp)
	}

	// Update head index
	_, err = db.Exec("UPDATE CTLog SET lastIndex = ? WHERE url = ?", sth.TreeSize, logurl)
	if err != nil {
		log.Printf("[-] Failed to update head index of log %s -> %s\n", logurl, err)
		return
	}
}