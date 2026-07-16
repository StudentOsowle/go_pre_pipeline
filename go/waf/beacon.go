package waf

import (
	"math"
	"sync"
	"time"
)

type BeaconDetector struct {
	mu          sync.Mutex
	windowSize  int
	minSamples  int
	maxCV       float64
	minInterval float64
	maxInterval float64
	history     map[string][]time.Time
}

func NewBeaconDetector(windowSize, minSamples int, maxCV, minInterval, maxInterval float64) *BeaconDetector {
	return &BeaconDetector{
		windowSize:  windowSize,
		minSamples:  minSamples,
		maxCV:       maxCV,
		minInterval: minInterval,
		maxInterval: maxInterval,
		history:     make(map[string][]time.Time),
	}
}

func (d *BeaconDetector) Observe(ip string, t time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	h := append(d.history[ip], t)
	if len(h) > d.windowSize {
		h = h[len(h)-d.windowSize:]
	}
	d.history[ip] = h

	return d.isBeaconingLocked(h)
}

func (d *BeaconDetector) isBeaconingLocked(h []time.Time) bool {
	if len(h) < d.minSamples+1 {
		return false
	}

	intervals := make([]float64, 0, len(h)-1)
	for i := 1; i < len(h); i++ {
		intervals = append(intervals, h[i].Sub(h[i-1]).Seconds())
	}

	mean := 0.0
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(len(intervals))

	if mean < d.minInterval || mean > d.maxInterval {
		return false
	}

	var variance float64
	for _, v := range intervals {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))
	stddev := math.Sqrt(variance)

	if mean == 0 {
		return false
	}
	cv := stddev / mean

	return cv <= d.maxCV
}

func (d *BeaconDetector) Reset(ip string) {
	d.mu.Lock()
	delete(d.history, ip)
	d.mu.Unlock()
}
