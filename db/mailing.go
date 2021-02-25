package sqldb

import (
	"gopkg.in/gomail.v2"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const sendmail = "/usr/sbin/sendmail"
const bodyStart = `
	<head>
		<style>
			body {
				font-family: monospace;
			}
			ul {
				font-weight: bold;
				list-style-type: none;
			}
			li {
				font-weight: lighter; 
			}
		</style>
	</head>
	<body>
		<h2>
			TENTO EMAIL BYL AUTOMATICKY VYGENEROVÁN / THIS IS EMAIL HAS BEEN AUTOMATICALLY GENERATED
		</h2>
		<h2>
			NA TENTO EMAIL NEODPOVÍDEJTE / DO NOT REPLY TO THIS EMAIL
		</h2>
		<a>
			Dobrý den,
		</a><br><br>
		<a>
			Služba CTLog identifikovala vydání těchto nových certifikátů:
		</a>
`

const bodyEnd = `
	<a href="pki.cesnet.cz">O službě</a>
	<img src="https://www.cesnet.cz/wp-content/uploads/2018/01/cesnet-malelogo.jpg
</body>
`

// Use sendmail to send emails.
func submitMail(m *gomail.Message) (err error) {
	cmd := exec.Command(sendmail, "-t")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	pw, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	err = cmd.Start()
	if err != nil {
		return err
	}

	_, err = m.WriteTo(pw)
	if err != nil {
		return err
	}

	err = pw.Close()
	if err != nil {
		return err
	}

	err = cmd.Wait()
	if err != nil {
		return err
	}

	return err
}

// Send out the certificate informations to the email monitoring them.
func SendEmail(info MonitoredCerts) {
	if info.Email == "" {
		return
	}

	t := time.Now().Add(-24 * time.Hour)
	date := strings.Join([]string{strconv.Itoa(t.Day()), strconv.Itoa(int(t.Month())), strconv.Itoa(t.Year())}, ".")

	m := gomail.NewMessage()
	m.SetHeader("From", "no-reply@cesnet.cz")
	m.SetHeader("To", info.Email)
	m.SetHeader("Subject", "[CTLog] Nové certifikáty "+date)

	var sb strings.Builder

	sb.WriteString(bodyStart)

	for _, cur := range info.Certificates {
		sb.WriteString("<ul>")
		sb.WriteString(cur.CN)
		sb.WriteString("<li>Subject DN: " + cur.DN + "</li>" +
			"<li>Serial: " + cur.SerialNumber + "</li>" +
			"<li>Names: " + cur.SAN + "</li>")
		sb.WriteString("</ul>")
	}

	m.SetBody("text/html", sb.String())

	if err := submitMail(m); err != nil {
		log.Printf("[-] Failed sending email to %s -> %s", info.Email, err)
	}
}
