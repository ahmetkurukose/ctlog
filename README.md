# CTlog
Program, that sends emails to users regarding new certificates issued to their domains or domains that could be used for a MITM attack.

## Instalation
Easiest way to install is to run `go get github.com/AdamTrn/ctlog`
### Requirements
- Go 15.3
- SQLite3

To download the dependencies run:

`go get -d path-to-ctlog/...`

(... is a `go` wildcard when describing package lists)

The program requires a database, currently it is running on SQLite.
To create the database run these commands:
```
sqlite3 path-to-ctlog/db/certdb.sqlite
.read create_database.sql
.quit
```

## Usage
### Parameters
- `-logurl url` - used when we only want to scan one log
- `-db path` - path to SQLite3 database
- `-add "email domain1 domain2..."` - add monitor to domain, has to be surrounded by double quotes
- `-remove "email domain"` - remove monitor, has to be surrounded by double quotes

## Architecture
For used keywords refer to [Certificate Transparency RFC](https://tools.ietf.org/html/rfc6962)

The database consists of 4 tables:
- CTLog - pairs of CT log urls and their last downloaded index 
- Monitor - emails of users and the domains they want to monitor
- Downloaded - CN, DN, SN and SAN of certificates downloaded in the last run of the program
- Certificate - downloaded certificates of domains that are monitored

For each log we fetch the previous highest index and we download the STH, that gives us the range and the number of certificates we have to download.

For each log we distribute the range to the downloaders, who we launch in parallel using goroutines.

We send the downloaded certificates to the parsing channel, from which the parsers remove it, parse it and send it over the inserting channel to the database inserter.



# CTlog
Program, který upozorňuje uživatele na vydané certifikáty pro jejich domény a na certifikáty, které by mohly být použity pro MITM útoky.

## Instalation
## Instalace
Nejjednošší způsob instalace je pomocí `go get github.com/AdamTrn/ctlog`

### Requirements
### Požadavky
- Go 15.3
- SQLite3

Pro stažení závislostí:
`go get -d path-to-ctlog/...`

(`...` je pro `go get` wildcard)

Program vyžaduje databázi, byla zvolena SQLite3.
Pro vytvoření databáze:
```
sqlite3 path-to-ctlog/db/certdb.sqlite
.read create_database.sql
.quit
```

## Použití
### Argumenty
- `-logurl url` - kontrola jen jednoho logu
- `-db path` - cesta k SQLite3 databázi
- `-add "email domain1 domain2..."` - přidání monitoru do databáze, musí být v uvozovkách
- `-remove "email domain"` - odebrání monitoru, musí být v uvozovkách
- `-smtp "host port username password"` - argumenty pro SMTP připojení

## Architektura
Použitá klíčová slova lze nalézt v [RFC6962](https://tools.ietf.org/html/rfc6962)

Databáze je tvořena 4 tabulkami
- CTLog - url CT logů a index posledního staženého certifikátu
- Monitor - emaily uživatelů a domény, které chtějí monitorovat
- Downloaded - CN, DN, SN a SAN certifikátů stažených během posledního spuštění
- Certificate - stažené certifikáty domén, které jsou monitorovány

Pro každý log zjistíme předchozí index posledního staženého certifikátu a stáhneme současnou STH, to nám vytvoří rozmezí indexů.

Poté pro každý log rozdělíme rozmezí indexů pro downloadery, ty spustíme paralelně díky goroutinám.

Stažené certifikáty pošleme do parsovacího kanály, parsery vyndavají z tohoto kanálu certifikáty, zparsují je a pošlou je do insertovacího kanálu, ze kterého je vyndavá inserter a vkládá je do databáze.