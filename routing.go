package main

import (
	sqldb "ctlog/db"
	"database/sql"
	"encoding/json"
	"github.com/go-martini/martini"
	"io/ioutil"
	"log"
	"net/http"
)

type PutReq struct {
	Email   string   `json:"email"`
	Domains []string `json:"domains"`
}

type DelReq struct {
	Email  string `json:"email"`
	Domain string `json:"domain"`
}

// Trying out routing
func createRoutes(m *martini.ClassicMartini, db *sql.DB) {
	m.Put("/app/v1/monitor", func(res http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		if err != nil {
			log.Printf("[-] Could not read PUT request body, %s\n", err)
			return
		}

		var m PutReq
		err = json.Unmarshal(body, &m)
		if err != nil {
			log.Printf("[-] Invalid JSON in PUT request, %s\n", err)
			return
		}

		res.Write([]byte("put"))

		sqldb.AddMonitors(m.Email, m.Domains, nil)
	})

	m.Delete("/app/v1/monitor", func(res http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		defer req.Body.Close()
		if err != nil {
			log.Printf("[-] Could not read DELETE request body, %s\n", err)
			return
		}
		var m DelReq
		err = json.Unmarshal(body, &m)
		if err != nil {
			log.Printf("[-] Invalid JSON in DELETE request, %s\n", err)
			return
		}

		res.Write([]byte("delete"))

		sqldb.RemoveMonitors(m.Email, m.Domain, nil)
	})

	m.Get("/", func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("get"))
	})
}

func doRouting(db *sql.DB) {
	//Setup API, teaching myself routing
	m := martini.Classic()
	createRoutes(m, db)
	m.Run()
}
