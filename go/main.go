package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/StudentOsowle/go_pre_pipeline/waf"
)

func main() {
	cfg := loadConfig()

	logger := log.New(os.Stdout, "", log.LstdFlags)
	if cfg.LogPath != "" {
		f, err := os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("opening log file: %v", err)
		}
		defer f.Close()
		logger = log.New(f, "", log.LstdFlags)
	}

	backend, err := url.Parse(cfg.BackendURL)
	if err != nil {
		log.Fatalf("invalid WAF_BACKEND_URL %q: %v", cfg.BackendURL, err)
	}

	blocklist := waf.NewBlocklist()
	if err := blocklist.LoadFile(cfg.BlocklistPath); err != nil {
		log.Fatalf("loading blocklist: %v", err)
	}

	beacon := waf.NewBeaconDetector(
		cfg.BeaconWindowSize,
		cfg.BeaconMinSamples,
		cfg.BeaconMaxCV,
		cfg.BeaconMinIntervalSec,
		cfg.BeaconMaxIntervalSec,
	)

	inspector := &waf.Inspector{
		Blocklist:         blocklist,
		Beacon:            beacon,
		Logger:            logger,
		AutoBlockOnBeacon: false,
	}

	proxy := httputil.NewSingleHostReverseProxy(backend)
	protected := inspector.Middleware(proxy)

	logger.Printf("go-waf listening on %s, proxying to %s", cfg.ListenAddr, cfg.BackendURL)
	if err := http.ListenAndServe(cfg.ListenAddr, protected); err != nil {
		log.Fatal(err)
	}
}
