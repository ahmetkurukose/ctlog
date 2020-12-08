# ctlog
Program, that sends emails to users regarding new certificates issued to their domains or domains that could be used for a MITM attack.
##Requirements
- Go 15.3
- SQLite3

To download the dependencies run:

`go get -d path-to-ctlog/...`

The program requires a database, currently it is running on SQLite.
To create the database run these commands:
```
sqlite3 path-to-ctlog/db/certdb.sqlite
.read create_database.sql
.quit
```

##Usage
###Parameters
- `-logurl url` - used when we only want to scan one log
- `-db path` - path to SQLite3 database

##Architecture
For used keywords refer to [Certificate Transparency RFC](https://tools.ietf.org/html/rfc6962)
The database consists of 4 tables:
- CTLog - pairs of CT log urls and their last downloaded index 
- Monitor - emails of users and the domains they want to monitor
- Downloaded - CN, DN, SN and SAN of certificates downloaded in the last run of the program
- Certificate - downloaded certificates of domains that are monitored

For each log we fetch the previous highest index and we download the STH, that gives us the range and the number of certificates we have to downlaod.

For each log we distribute the range to the downloaders, who we launch in parallel using goroutines.

We send the downloaded certificates to the parsing channel, from which the parsers remove it, parse it and send it over the inserting channel to the database inserter.