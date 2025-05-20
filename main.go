package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nxadm/tail"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config global config
var globalConfig struct {
	LogFile        string
	PositionFile   string
	PrometheusPort int
	TailMode       bool
	ResetOnStart   bool
}

// SNIStats 存储每个 SNI 的统计信息
type SNIStats struct {
	TotalBytes  int64 `json:"total_bytes"`
	Connections int   `json:"connections"`
	ZeroBytes   int   `json:"zero_bytes"`
	mu          sync.RWMutex
}

// LogStats 存储全局统计信息
type LogStats struct {
	SNIStats       map[string]*SNIStats
	mu             sync.RWMutex
	lastReportTime time.Time
}

var (
	stats LogStats

	sniBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "haproxy_sni_total_bytes",
			Help: "Total bytes transferred per SNI",
		},
		[]string{"sni"},
	)
	sniConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "haproxy_sni_connections",
			Help: "Total connections per SNI",
		},
		[]string{"sni"},
	)
	sniZeroBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "haproxy_sni_zero_bytes",
			Help: "Zero byte connections per SNI",
		},
		[]string{"sni"},
	)

	currentTailInstance     *tail.Tail
	currentTailInstanceLock sync.Mutex
	tailWg                  sync.WaitGroup // To wait for tailing goroutine to finish
)

func init() {
	prometheus.MustRegister(sniBytes)
	prometheus.MustRegister(sniConnections)
	prometheus.MustRegister(sniZeroBytes)
	stats = LogStats{
		SNIStats:       make(map[string]*SNIStats),
		lastReportTime: time.Now(),
	}
}

func updatePrometheusMetrics() {
	// log.Printf("[Prometheus] updatePrometheusMetrics called") // Can be verbose
	stats.mu.RLock()
	defer stats.mu.RUnlock()
	for sni, sniStat := range stats.SNIStats {
		sniStat.mu.RLock()
		sniBytes.WithLabelValues(sni).Set(float64(sniStat.TotalBytes))
		sniConnections.WithLabelValues(sni).Set(float64(sniStat.Connections))
		sniZeroBytes.WithLabelValues(sni).Set(float64(sniStat.ZeroBytes))
		sniStat.mu.RUnlock()
	}
}

func processLine(line string) {
	if !globalConfig.TailMode {
		// log.Printf("STDIN_MODE: Processing line: %s", line) // Can be verbose
	} else {
		// log.Printf("TAIL_MODE (nxadm/tail): Processing line: %s", line) // Can be verbose
	}
	idx := strings.Index(line, "SNI=")
	if idx == -1 {
		// log.Printf("No SNI found for line: %s", line) // Can be verbose
		return
	}
	sniPart := line[idx+4:]
	sniFields := strings.Fields(sniPart)
	if len(sniFields) == 0 {
		// log.Printf("Empty SNI value after 'SNI=' for line: %s", line) // Can be verbose
		return
	}
	sni := sniFields[0]
	sni = strings.TrimSpace(sni)
	before := strings.TrimSpace(line[:idx])
	fields := strings.Fields(before)
	if len(fields) < 1 {
		// log.Printf("No fields before SNI for line: %s", line) // Can be verbose
		return
	}
	var bytesVal int64
	foundBytes := false
	for i := len(fields) - 1; i >= 0; i-- {
		if n, err := strconv.ParseInt(fields[i], 10, 64); err == nil {
			bytesVal = n
			foundBytes = true
			break
		}
	}
	if !foundBytes {
		// log.Printf("No numeric field found before SNI for line: %s", line) // Can be verbose
		return
	}
	// log.Printf("Extracted SNI: %s, bytes: %d", sni, bytesVal) // Can be verbose

	stats.mu.Lock()
	sniStat, exists := stats.SNIStats[sni]
	if !exists {
		sniStat = &SNIStats{}
		stats.SNIStats[sni] = sniStat
	}
	stats.mu.Unlock()

	sniStat.mu.Lock()
	sniStat.TotalBytes += bytesVal
	sniStat.Connections++
	if bytesVal == 0 {
		sniStat.ZeroBytes++
	}
	sniStat.mu.Unlock()

	// log.Printf("Stats for SNI %s updated: TotalBytes=%d, Connections=%d, ZeroBytes=%d", // Can be verbose
	// 	sni, sniStat.TotalBytes, sniStat.Connections, sniStat.ZeroBytes)

	updatePrometheusMetrics()
	// log.Printf("Prometheus metrics updated via updatePrometheusMetrics() for SNI: %s", sni) // Can be verbose
}

func readStartingOffset(posFile string) (int64, error) {
	data, err := os.ReadFile(posFile)
	if err != nil {
		return 0, err
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing position file %s: %v", posFile, err)
	}
	return offset, nil
}

func saveCurrentPosition(posFile string, t *tail.Tail) {
	if t == nil {
		return
	}
	currentOffset, err := t.Tell()
	if err != nil {
		log.Printf("Error getting current offset from tail: %v", err)
		return
	}
	err = os.WriteFile(posFile, []byte(fmt.Sprintf("%d", currentOffset)), 0644)
	if err != nil {
		log.Printf("Error writing position to %s: %v", posFile, err)
	}
}

func resetStats() {
	stats.mu.Lock()
	stats.SNIStats = make(map[string]*SNIStats)
	stats.mu.Unlock()

	// Reset Prometheus gauges
	sniBytes.Reset()
	sniConnections.Reset()
	sniZeroBytes.Reset()
	log.Println("Internal stats and Prometheus metrics have been reset.")
}

func processTailLines(t *tail.Tail, posFile string) {
	defer tailWg.Done()
	log.Printf("Goroutine processTailLines started for %s", t.Filename)
	for line := range t.Lines {
		if line.Err != nil {
			log.Printf("Error from tail line for %s: %v", t.Filename, line.Err)
			continue
		}
		processLine(line.Text)
		saveCurrentPosition(posFile, t)
	}
	log.Printf("Tail lines channel closed for %s. Exiting processTailLines goroutine.", t.Filename)
}

// startTailingInternal stops any existing tailer, then starts a new one.
func startTailingInternal(logFilePath string, posFilePath string, resetPosition bool) error {
	currentTailInstanceLock.Lock()
	// Stop and cleanup existing instance if it's running
	if currentTailInstance != nil {
		log.Printf("Stopping existing tail instance for %s...", currentTailInstance.Filename)
		// Attempt to stop gracefully. Stop() should close the t.Lines channel.
		if err := currentTailInstance.Stop(); err != nil {
			log.Printf("Error stopping current tail instance: %v. Attempting to kill...", err)
			// If Stop() fails or hangs, Kill() might be necessary.
			// Kill() sends an error to the Lines channel, which should also lead to goroutine exit.
			currentTailInstance.Kill(fmt.Errorf("restarting tailer due to stop error: %v", err))
		}
		currentTailInstanceLock.Unlock() // Unlock before waiting to prevent deadlock if Done() needs lock

		log.Println("Waiting for previous tailing goroutine (processTailLines) to complete...")
		tailWg.Wait() // Wait for the previous processTailLines to call Done()
		log.Println("Previous tailing goroutine completed.")

		currentTailInstanceLock.Lock() // Re-acquire lock to safely nullify currentTailInstance
		currentTailInstance = nil
	}

	var initialOffset int64
	var seekOrigin int = io.SeekStart

	if resetPosition {
		log.Println("Resetting position, starting from beginning of file.")
		initialOffset = 0
		if err := os.Remove(posFilePath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: Error removing position file %s: %v", posFilePath, err)
		}
		if err := os.WriteFile(posFilePath, []byte("0"), 0644); err != nil {
			log.Printf("Warning: Error creating zero position file %s: %v", posFilePath, err)
		}
	} else {
		offset, err := readStartingOffset(posFilePath)
		if err == nil {
			initialOffset = offset
			log.Printf("Read starting offset %d from %s", initialOffset, posFilePath)
		} else {
			if !os.IsNotExist(err) {
				log.Printf("Warning: Error reading position file %s (%v). Will start from end.", posFilePath, err)
			}
			initialOffset = 0
			seekOrigin = io.SeekEnd
			log.Println("No valid position file or error reading it. Tailing from end of file.")
		}
	}

	tailConfig := tail.Config{
		Location:  &tail.SeekInfo{Offset: initialOffset, Whence: seekOrigin},
		Follow:    true,
		ReOpen:    true,
		Poll:      true,
		MustExist: false,
		// Logger:    tail.DiscardingLogger,
	}

	t, err := tail.TailFile(logFilePath, tailConfig)
	if err != nil {
		currentTailInstanceLock.Unlock()
		return fmt.Errorf("failed to start tailing file %s: %v", logFilePath, err)
	}

	currentTailInstance = t
	currentTailInstanceLock.Unlock() // Unlock after currentTailInstance is set

	log.Printf("Successfully started tailing %s from offset %d (Whence: %d)", logFilePath, tailConfig.Location.Offset, tailConfig.Location.Whence)

	tailWg.Add(1)
	go processTailLines(t, posFilePath)

	return nil
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received /reset request.")
	resetStats()

	if globalConfig.TailMode {
		log.Println("TailMode enabled, attempting to reset and restart tailing...")
		err := startTailingInternal(globalConfig.LogFile, globalConfig.PositionFile, true)
		if err != nil {
			log.Printf("Error restarting tailing: %v", err)
			http.Error(w, fmt.Sprintf("Failed to reset and restart tailing: %v", err), http.StatusInternalServerError)
			return
		}
		log.Println("Tailing restarted successfully after reset.")
		fmt.Fprintln(w, "Metrics and tailing position reset successfully.")
	} else {
		log.Println("Stdin mode, only metrics were reset.")
		fmt.Fprintln(w, "Metrics reset successfully (stdin mode, no tail position to reset).")
	}
}

func main() {
	flag.StringVar(&globalConfig.LogFile, "log", "/var/log/haproxy.log", "HAProxy log file to monitor")
	flag.StringVar(&globalConfig.PositionFile, "pos", ".haproxy-sni-exporter.pos", "Position file for tail mode (relative to PWD or absolute)")
	flag.IntVar(&globalConfig.PrometheusPort, "port", 9100, "Prometheus metrics port")
	flag.BoolVar(&globalConfig.TailMode, "tailmode", false, "Enable direct file tailing mode using nxadm/tail")
	flag.BoolVar(&globalConfig.ResetOnStart, "reset", false, "Reset position and start from beginning of file (in tailmode)")
	flag.Parse()

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/reset", resetHandler)
	go func() {
		log.Printf("Starting Prometheus server with /reset endpoint on :%d", globalConfig.PrometheusPort)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", globalConfig.PrometheusPort), nil); err != nil {
			// If the server fails to start (e.g. port already in use), log fatal.
			// Note: This doesn't stop the main() goroutine if it's already waiting on 'done'.
			// Consider a channel to signal main() for a cleaner shutdown.
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	if globalConfig.TailMode {
		log.Println("Tail mode (nxadm/tail) enabled.")
		if err := startTailingInternal(globalConfig.LogFile, globalConfig.PositionFile, globalConfig.ResetOnStart); err != nil {
			log.Fatalf("Failed to initialize tailing: %v", err)
		}

		<-done
		log.Println("Termination signal received. Shutting down tailer...")

		currentTailInstanceLock.Lock()
		if currentTailInstance != nil {
			log.Println("Stopping current tail instance...")
			if err := currentTailInstance.Stop(); err != nil { // Stop should be enough for graceful shutdown
				log.Printf("Error stopping tail instance during shutdown: %v", err)
			}
		}
		currentTailInstanceLock.Unlock() // Unlock before Wait to avoid deadlock if Done() tries to lock

		log.Println("Waiting for tailing goroutine (processTailLines) to complete...")
		tailWg.Wait()
		log.Println("Tailing stopped. Exiting.")

	} else {
		log.Println("Stdin mode enabled. Reading from stdin...")
		stdinDone := make(chan struct{}) // Channel to signal stdin processing completion
		go func() {
			defer close(stdinDone) // Signal completion
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := scanner.Text()
				processLine(line)
			}
			if err := scanner.Err(); err != nil {
				log.Printf("Error reading stdin: %v", err)
			}
			log.Println("Stdin reader finished.")
		}()

		select {
		case <-done:
			log.Println("Termination signal received. Shutting down...")
			// os.Stdin.Close() // This can help unblock the scanner if it's stuck on Read
		case <-stdinDone:
			log.Println("Stdin processing finished. Application will now exit.")
		}
	}
	log.Println("Application shut down gracefully.")
}
