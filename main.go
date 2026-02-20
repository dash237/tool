package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"

	"phishing-tool/core"
	"phishing-tool/database"
	"phishing-tool/log"

	"github.com/caddyserver/certmagic"
	"github.com/fatih/color"
	"go.uber.org/zap"
)

var (
	phishletsDir   = flag.String("p", "", "Phishlets directory path")
	redirectorsDir = flag.String("t", "", "HTML redirector pages directory path")
	debugLog       = flag.Bool("debug", false, "Enable debug output")
	developerMode  = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
	cfgDir         = flag.String("c", "", "Configuration directory path")
	versionFlag    = flag.Bool("v", false, "Show version")
)

func joinPath(basePath, relPath string) string {
	if filepath.IsAbs(relPath) {
		return relPath
	}
	return filepath.Join(basePath, relPath)
}

func showEvilginxProAd() {
	lred := color.New(color.FgHiRed)
	lyellow := color.New(color.FgHiYellow)
	white := color.New(color.FgHiWhite)
	message := fmt.Sprintf("%s %s: %s %s",
		lred.Sprint("Evilginx Pro"),
		white.Sprint("is finally out"),
		lyellow.Sprint("https://evilginx.com"),
		white.Sprint("(advanced phishing framework for red teams)"),
	)
	log.Info("%s", message)
}

func showEvilginxMasteryAd() {
	lyellow := color.New(color.FgHiYellow)
	white := color.New(color.FgHiWhite)
	hcyan := color.New(color.FgHiCyan)
	message := fmt.Sprintf("%s: %s %s",
		hcyan.Sprint("Evilginx Mastery Course"),
		lyellow.Sprint("https://academy.breakdev.org/evilginx-mastery"),
		white.Sprint("(learn how to create phishlets)"),
	)
	log.Info("%s", message)
}

func main() {
	flag.Parse()

	if *versionFlag {
		log.Info("version: %s", core.VERSION)
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Fatal("failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	core.Banner()
	showEvilginxProAd()
	showEvilginxMasteryAd()

	// Suppress certmagic logs
	certmagic.Default.Logger = zap.NewNop()
	certmagic.DefaultACME.Logger = zap.NewNop()

	// Set default phishlets directory
	if *phishletsDir == "" {
		*phishletsDir = joinPath(exeDir, "./phishlets")
		if _, err := os.Stat(*phishletsDir); os.IsNotExist(err) {
			*phishletsDir = "/usr/share/evilginx/phishlets/"
			if _, err := os.Stat(*phishletsDir); os.IsNotExist(err) {
				log.Fatal("you need to provide the path to directory where your phishlets are stored: ./evilginx -p <phishlets_path>")
			}
		}
	}

	// Set default redirectors directory
	if *redirectorsDir == "" {
		*redirectorsDir = joinPath(exeDir, "./redirectors")
		if _, err := os.Stat(*redirectorsDir); os.IsNotExist(err) {
			*redirectorsDir = "/usr/share/evilginx/redirectors/"
			if _, err := os.Stat(*redirectorsDir); os.IsNotExist(err) {
				*redirectorsDir = joinPath(exeDir, "./redirectors")
			}
		}
	}

	// Validate directories
	if _, err := os.Stat(*phishletsDir); os.IsNotExist(err) {
		log.Fatal("provided phishlets directory path does not exist: %s", *phishletsDir)
	}
	if _, err := os.Stat(*redirectorsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(*redirectorsDir, 0700); err != nil {
			log.Fatal("failed to create redirectors directory: %v", err)
		}
	}

	// Enable debug logging
	log.DebugEnable(*debugLog)
	if *debugLog {
		log.Info("debug output enabled")
	}

	phishletsPath := *phishletsDir
	log.Info("loading phishlets from: %s", phishletsPath)

	// Set default config directory
	if *cfgDir == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("failed to get current user: %v", err)
		}
		*cfgDir = filepath.Join(usr.HomeDir, ".evilginx")
	}

	configPath := *cfgDir
	log.Info("loading configuration from: %s", configPath)

	// Create config directory
	if err := os.MkdirAll(*cfgDir, 0700); err != nil {
		log.Fatal("failed to create config directory: %v", err)
	}

	crtPath := joinPath(*cfgDir, "./crt")

	// Initialize core components
	cfg, err := core.NewConfig(*cfgDir, "")
	if err != nil {
		log.Fatal("config: %v", err)
	}
	cfg.SetRedirectorsDir(*redirectorsDir)

	db, err := database.NewDatabase(filepath.Join(*cfgDir, "data.db"))
	if err != nil {
		log.Fatal("database: %v", err)
	}

	bl, err := core.NewBlacklist(filepath.Join(*cfgDir, "blacklist.txt"))
	if err != nil {
		log.Error("blacklist: %s", err)
		// Continue even if blacklist fails
	}

	// Load phishlets
	files, err := os.ReadDir(phishletsPath)
	if err != nil {
		log.Fatal("failed to list phishlets directory '%s': %v", phishletsPath, err)
	}

	phishletRegex := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.yaml`)
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		matches := phishletRegex.FindStringSubmatch(f.Name())
		if len(matches) < 2 {
			continue
		}

		pname := matches[1]
		if pname == "" {
			continue
		}

		pl, err := core.NewPhishlet(pname, filepath.Join(phishletsPath, f.Name()), nil, cfg)
		if err != nil {
			log.Error("failed to load phishlet '%s': %v", f.Name(), err)
			continue
		}
		cfg.AddPhishlet(pname, pl)
	}

	cfg.LoadSubPhishlets()
	cfg.CleanUp()

	// Start nameserver
	ns, err := core.NewNameserver(cfg)
	if err != nil {
		log.Fatal("nameserver: %v", err)
	}
	ns.Start()

	// Initialize cert database
	crtDb, err := core.NewCertDb(crtPath, cfg, ns)
	if err != nil {
		log.Fatal("certdb: %v", err)
	}

	// Start HTTP proxy
	hp, err := core.NewHttpProxy(cfg.GetServerBindIP(), cfg.GetHttpsPort(), cfg, crtDb, db, bl, *developerMode)
	if err != nil {
		log.Fatal("http proxy: %v", err)
	}
	hp.Start()

	// Start terminal
	t, err := core.NewTerminal(hp, cfg, crtDb, db, *developerMode)
	if err != nil {
		log.Fatal("terminal: %v", err)
	}

	t.DoWork()
}
