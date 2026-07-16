package main

import (
	"os"
	"strconv"
)

type Config struct {
	ListenAddr           string
	BackendURL           string
	BlocklistPath        string
	BeaconWindowSize     int
	BeaconMinSamples     int
	BeaconMaxCV          float64
	BeaconMinIntervalSec float64
	BeaconMaxIntervalSec float64
	LogPath              string
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr:           getEnv("WAF_LISTEN_ADDR", ":8080"),
		BackendURL:           getEnv("WAF_BACKEND_URL", "http://127.0.0.1:3000"),
		BlocklistPath:        getEnv("WAF_BLOCKLIST_PATH", "blocklist.txt"),
		BeaconWindowSize:     getEnvInt("WAF_BEACON_WINDOW", 8),
		BeaconMinSamples:     getEnvInt("WAF_BEACON_MIN_SAMPLES", 4),
		BeaconMaxCV:          getEnvFloat("WAF_BEACON_MAX_CV", 0.15),
		BeaconMinIntervalSec: getEnvFloat("WAF_BEACON_MIN_INTERVAL", 3),
		BeaconMaxIntervalSec: getEnvFloat("WAF_BEACON_MAX_INTERVAL", 3600),
		LogPath:              getEnv("WAF_LOG_PATH", ""),
	}
	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			return n
		}
	}
	return fallback
}
