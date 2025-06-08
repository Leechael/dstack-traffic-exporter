package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nxadm/tail"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version information (will be set during build time)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// Config global config
var globalConfig struct {
	LogFile             string
	PositionFile        string
	PrometheusPort      int
	ResetOnStart        bool
	QEMUMonitorInterval time.Duration
	DomainSuffix        string
}

// SNIStats 存储每个 SNI 的统计信息
type SNIStats struct {
	TotalBytes  int64 `json:"total_bytes"`
	Connections int   `json:"connections"`
	ZeroBytes   int   `json:"zero_bytes"`
	mu          sync.RWMutex
}

// NetworkSnapshot represents network stats at a specific time
type NetworkSnapshot struct {
	Timestamp time.Time
	RxBytes   uint64
	TxBytes   uint64
}

// QEMUProcessStats stores network statistics for a QEMU process
type QEMUProcessStats struct {
	PID       int
	UUID      string
	Snapshots []NetworkSnapshot
	mu        sync.RWMutex
}

// LogStats 存储全局统计信息
type LogStats struct {
	SNIStats       map[string]*SNIStats
	mu             sync.RWMutex
	lastReportTime time.Time
}

// QEMUStats stores all QEMU process statistics
type QEMUStats struct {
	Processes map[int]*QEMUProcessStats
	mu        sync.RWMutex
}

// Query response structures
type NetworkBytes struct {
	RX uint64 `json:"rx"`
	TX uint64 `json:"tx"`
}

type HAProxyAppData struct {
	TotalBytes  int64    `json:"total_bytes"`
	Connections int      `json:"connections"`
	ZeroBytes   int      `json:"zero_bytes"`
	SNIs        []string `json:"snis"`
}

type QEMUNetworkData struct {
	TotalBytes NetworkBytes `json:"total_bytes"`
	Bytes30s   NetworkBytes `json:"30s_bytes"`
	Bytes1min  NetworkBytes `json:"1min_bytes"`
	Bytes5min  NetworkBytes `json:"5min_bytes"`
	Bytes15min NetworkBytes `json:"15min_bytes"`
	Bytes1h    NetworkBytes `json:"1h_bytes"`
}

type QueryResponse struct {
	HAProxy map[string]HAProxyAppData  `json:"haproxy"`
	QEMU    map[string]QEMUNetworkData `json:"qemu"`
}

type QueryRequest struct {
	AppIDs []string `json:"appids"`
	UUIDs  []string `json:"uuids"`
}

var (
	stats     LogStats
	qemuStats QEMUStats

	// Original HAProxy SNI metrics
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

	// QEMU network metrics
	qemuTotalBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "qemu_network_total_bytes",
			Help: "Total network bytes for QEMU process",
		},
		[]string{"uuid", "direction"},
	)
	qemu30sBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "qemu_network_30s_bytes",
			Help: "Network bytes in last 30 seconds for QEMU process",
		},
		[]string{"uuid", "direction"},
	)
	qemu1minBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "qemu_network_1min_bytes",
			Help: "Network bytes in last 1 minute for QEMU process",
		},
		[]string{"uuid", "direction"},
	)
	qemu5minBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "qemu_network_5min_bytes",
			Help: "Network bytes in last 5 minutes for QEMU process",
		},
		[]string{"uuid", "direction"},
	)
	qemu15minBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "qemu_network_15min_bytes",
			Help: "Network bytes in last 15 minutes for QEMU process",
		},
		[]string{"uuid", "direction"},
	)
	qemu1hBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "qemu_network_1h_bytes",
			Help: "Network bytes in last 1 hour for QEMU process",
		},
		[]string{"uuid", "direction"},
	)

	currentTailInstance     *tail.Tail
	currentTailInstanceLock sync.Mutex
	tailWg                  sync.WaitGroup // To wait for tailing goroutine to finish

	// QEMU monitoring
	qemuMonitorTicker *time.Ticker
	qemuMonitorDone   chan bool
)

func init() {
	prometheus.MustRegister(sniBytes)
	prometheus.MustRegister(sniConnections)
	prometheus.MustRegister(sniZeroBytes)
	prometheus.MustRegister(qemuTotalBytes)
	prometheus.MustRegister(qemu30sBytes)
	prometheus.MustRegister(qemu1minBytes)
	prometheus.MustRegister(qemu5minBytes)
	prometheus.MustRegister(qemu15minBytes)
	prometheus.MustRegister(qemu1hBytes)

	stats = LogStats{
		SNIStats:       make(map[string]*SNIStats),
		lastReportTime: time.Now(),
	}
	qemuStats = QEMUStats{
		Processes: make(map[int]*QEMUProcessStats),
	}
}

func updatePrometheusMetrics() {
	// Update HAProxy SNI metrics only if we have data
	stats.mu.RLock()
	if len(stats.SNIStats) > 0 {
		for sni, sniStat := range stats.SNIStats {
			sniStat.mu.RLock()
			sniBytes.WithLabelValues(sni).Set(float64(sniStat.TotalBytes))
			sniConnections.WithLabelValues(sni).Set(float64(sniStat.Connections))
			sniZeroBytes.WithLabelValues(sni).Set(float64(sniStat.ZeroBytes))
			sniStat.mu.RUnlock()
		}
	}
	stats.mu.RUnlock()
}

func processLine(line string) {
	// log.Printf("Processing line: %s", line) // Can be verbose
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

	// Only update Prometheus metrics periodically, not on every line
	// updatePrometheusMetrics() will be called by a periodic updater
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

// extractAppIDFromSNI extracts app ID from SNI
// For configured domain suffix: extracts the first part and removes -xxx suffix if present
// For other domains: returns the entire domain
func extractAppIDFromSNI(sni string) string {
	// Check if it's a configured domain suffix and suffix is not empty
	if globalConfig.DomainSuffix != "" && strings.HasSuffix(sni, "."+globalConfig.DomainSuffix) {
		// Find the first dot to get the subdomain part
		if idx := strings.Index(sni, "."); idx != -1 {
			subdomain := sni[:idx]

			// Remove -xxx suffix if present (e.g., -80, -443, etc.)
			if dashIdx := strings.LastIndex(subdomain, "-"); dashIdx != -1 {
				// Check if everything after the dash is numeric (port number)
				suffix := subdomain[dashIdx+1:]
				if _, err := strconv.Atoi(suffix); err == nil {
					return subdomain[:dashIdx]
				}
			}
			return subdomain
		}
	}

	// For other domains, return the entire SNI
	return sni
}

// queryHAProxyDataByAppIDs queries HAProxy statistics by app IDs
// If appIDs is empty, returns all available app data
func queryHAProxyDataByAppIDs(appIDs []string) map[string]HAProxyAppData {
	result := make(map[string]HAProxyAppData)

	// Create a map for fast lookup if specific app IDs are requested
	var appIDSet map[string]bool
	returnAll := appIDs == nil || len(appIDs) == 0
	if !returnAll {
		appIDSet = make(map[string]bool)
		for _, appID := range appIDs {
			appIDSet[appID] = true
		}
	}

	// First, collect all SNI data with minimal lock time
	stats.mu.RLock()
	sniDataSnapshot := make(map[string]struct {
		TotalBytes  int64
		Connections int
		ZeroBytes   int
	})

	for sni, sniStat := range stats.SNIStats {
		sniStat.mu.RLock()
		sniDataSnapshot[sni] = struct {
			TotalBytes  int64
			Connections int
			ZeroBytes   int
		}{
			TotalBytes:  sniStat.TotalBytes,
			Connections: sniStat.Connections,
			ZeroBytes:   sniStat.ZeroBytes,
		}
		sniStat.mu.RUnlock()
	}
	stats.mu.RUnlock()

	// Now process the data without holding any locks
	appData := make(map[string]*HAProxyAppData)

	for sni, data := range sniDataSnapshot {
		appID := extractAppIDFromSNI(sni)

		// Filter by requested app IDs if specified
		if !returnAll && !appIDSet[appID] {
			continue
		}

		if appData[appID] == nil {
			appData[appID] = &HAProxyAppData{
				SNIs: make([]string, 0),
			}
		}

		appData[appID].TotalBytes += data.TotalBytes
		appData[appID].Connections += data.Connections
		appData[appID].ZeroBytes += data.ZeroBytes
		appData[appID].SNIs = append(appData[appID].SNIs, sni)
	}

	// Convert to result format
	for appID, data := range appData {
		result[appID] = *data
	}

	// Ensure all requested app IDs are in the result (even if empty) when specific IDs requested
	if !returnAll {
		for _, appID := range appIDs {
			if _, exists := result[appID]; !exists {
				result[appID] = HAProxyAppData{
					SNIs: make([]string, 0),
				}
			}
		}
	}

	return result
}

// queryQEMUDataByUUIDs queries QEMU statistics by UUIDs
// If uuids is empty, returns all available QEMU data
func queryQEMUDataByUUIDs(uuids []string) map[string]QEMUNetworkData {
	result := make(map[string]QEMUNetworkData)

	// Create a map for fast lookup if specific UUIDs are requested
	var uuidSet map[string]bool
	returnAll := uuids == nil || len(uuids) == 0
	if !returnAll {
		uuidSet = make(map[string]bool)
		for _, uuid := range uuids {
			uuidSet[uuid] = true
		}
	}

	// First, collect process data with minimal lock time
	qemuStats.mu.RLock()
	processDataSnapshot := make(map[string][]NetworkSnapshot)

	for _, processStats := range qemuStats.Processes {
		uuid := processStats.UUID

		// Filter by requested UUIDs if specified
		if !returnAll && !uuidSet[uuid] {
			continue
		}

		processStats.mu.RLock()
		if len(processStats.Snapshots) > 0 {
			// Copy snapshots to avoid holding locks during calculations
			snapshots := make([]NetworkSnapshot, len(processStats.Snapshots))
			copy(snapshots, processStats.Snapshots)
			processDataSnapshot[uuid] = snapshots
		}
		processStats.mu.RUnlock()
	}
	qemuStats.mu.RUnlock()

	// Process data without holding any locks
	var processUUIDs []string
	if returnAll {
		processUUIDs = make([]string, 0, len(processDataSnapshot))
		for uuid := range processDataSnapshot {
			processUUIDs = append(processUUIDs, uuid)
		}
	} else {
		processUUIDs = uuids
	}

	for _, uuid := range processUUIDs {
		var networkData QEMUNetworkData

		if snapshots, exists := processDataSnapshot[uuid]; exists && len(snapshots) > 0 {
			// Get the latest snapshot for total bytes
			latest := snapshots[len(snapshots)-1]
			networkData.TotalBytes = NetworkBytes{
				RX: latest.RxBytes,
				TX: latest.TxBytes,
			}

			// Calculate windowed metrics
			rx30s, tx30s := calculateBytesInWindow(snapshots, 30*time.Second)
			networkData.Bytes30s = NetworkBytes{RX: rx30s, TX: tx30s}

			rx1min, tx1min := calculateBytesInWindow(snapshots, 1*time.Minute)
			networkData.Bytes1min = NetworkBytes{RX: rx1min, TX: tx1min}

			rx5min, tx5min := calculateBytesInWindow(snapshots, 5*time.Minute)
			networkData.Bytes5min = NetworkBytes{RX: rx5min, TX: tx5min}

			rx15min, tx15min := calculateBytesInWindow(snapshots, 15*time.Minute)
			networkData.Bytes15min = NetworkBytes{RX: rx15min, TX: tx15min}

			rx1h, tx1h := calculateBytesInWindow(snapshots, 1*time.Hour)
			networkData.Bytes1h = NetworkBytes{RX: rx1h, TX: tx1h}
		}

		result[uuid] = networkData
	}

	return result
}

// parseQueryParameters extracts app IDs and UUIDs from query parameters
func parseQueryParameters(query map[string][]string) ([]string, []string) {
	var appIDs, uuids []string

	// Parse app IDs
	if appIDsParam := query["appids"]; len(appIDsParam) > 0 && appIDsParam[0] != "" {
		appIDs = strings.Split(appIDsParam[0], ",")
		// Trim whitespace
		for i := range appIDs {
			appIDs[i] = strings.TrimSpace(appIDs[i])
		}
	}

	// Parse UUIDs
	if uuidsParam := query["uuids"]; len(uuidsParam) > 0 && uuidsParam[0] != "" {
		uuids = strings.Split(uuidsParam[0], ",")
		// Trim whitespace
		for i := range uuids {
			uuids[i] = strings.TrimSpace(uuids[i])
		}
	}

	return appIDs, uuids
}

// queryHandler handles /query requests (supports both GET and POST)
func queryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Supported methods: GET, POST", http.StatusMethodNotAllowed)
		return
	}

	var appIDs, uuids []string
	var err error

	switch r.Method {
	case http.MethodGet:
		// Parse query parameters
		appIDs, uuids = parseQueryParameters(r.URL.Query())

	case http.MethodPost:
		// Parse JSON body
		var req QueryRequest
		if r.Header.Get("Content-Type") == "application/json" {
			decoder := json.NewDecoder(r.Body)
			if err := decoder.Decode(&req); err != nil {
				http.Error(w, "Invalid JSON body", http.StatusBadRequest)
				return
			}
			appIDs = req.AppIDs
			uuids = req.UUIDs
		} else {
			// Parse form data
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Invalid form data", http.StatusBadRequest)
				return
			}
			appIDs, uuids = parseQueryParameters(r.Form)
		}
	}

	// Trim any empty strings from slices
	appIDs = filterEmptyStrings(appIDs)
	uuids = filterEmptyStrings(uuids)

	// Query data
	// Special case: if no parameters provided, return all data
	hasAppIDParams := len(appIDs) > 0
	hasUUIDParams := len(uuids) > 0

	var haproxyData map[string]HAProxyAppData
	var qemuData map[string]QEMUNetworkData

	// If neither parameter is provided, return all data
	if !hasAppIDParams && !hasUUIDParams {
		haproxyData = queryHAProxyDataByAppIDs(nil) // nil means return all
		qemuData = queryQEMUDataByUUIDs(nil)        // nil means return all
	} else {
		// Only query the data types that were specifically requested
		if hasAppIDParams {
			haproxyData = queryHAProxyDataByAppIDs(appIDs)
		} else {
			haproxyData = make(map[string]HAProxyAppData)
		}

		if hasUUIDParams {
			qemuData = queryQEMUDataByUUIDs(uuids)
		} else {
			qemuData = make(map[string]QEMUNetworkData)
		}
	}

	response := QueryResponse{
		HAProxy: haproxyData,
		QEMU:    qemuData,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding query response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("Query request processed (%s): appids=%v, uuids=%v", r.Method, appIDs, uuids)
}

// filterEmptyStrings removes empty strings from slice
func filterEmptyStrings(slice []string) []string {
	if slice == nil {
		return nil
	}

	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if strings.TrimSpace(s) != "" {
			result = append(result, strings.TrimSpace(s))
		}
	}
	return result
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received /reset request.")
	resetStats()

	// Reset QEMU stats (always enabled)
	qemuStats.mu.Lock()
	qemuStats.Processes = make(map[int]*QEMUProcessStats)
	qemuStats.mu.Unlock()

	// Reset QEMU Prometheus gauges
	qemuTotalBytes.Reset()
	qemu30sBytes.Reset()
	qemu1minBytes.Reset()
	qemu5minBytes.Reset()
	qemu15minBytes.Reset()
	qemu1hBytes.Reset()

	log.Println("QEMU stats and metrics have been reset.")

	// Reset HAProxy log tailing (always enabled)
	log.Println("Attempting to reset and restart HAProxy log tailing...")
	err := startTailingInternal(globalConfig.LogFile, globalConfig.PositionFile, true)
	if err != nil {
		log.Printf("Error restarting tailing: %v", err)
		fmt.Fprintln(w, "HAProxy and QEMU metrics reset successfully. Warning: Failed to reset HAProxy log tailing.")
		return
	}
	log.Println("HAProxy log tailing restarted successfully after reset.")

	fmt.Fprintln(w, "HAProxy metrics, QEMU metrics, and log tailing position reset successfully.")
}

// getQEMUProcesses discovers all QEMU processes and extracts their UUIDs
func getQEMUProcesses() (map[int]string, error) {
	processes := make(map[int]string)

	files, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}

		// Read command line
		cmdlineFile := filepath.Join("/proc", file.Name(), "cmdline")
		cmdlineBytes, err := os.ReadFile(cmdlineFile)
		if err != nil {
			continue
		}

		cmdline := string(cmdlineBytes)
		if !strings.Contains(cmdline, "qemu-system") {
			continue
		}

		// Extract UUID from command line
		uuid := extractUUIDFromCmdline(cmdline)
		if uuid != "" {
			processes[pid] = uuid
		}
	}

	return processes, nil
}

// extractUUIDFromCmdline extracts UUID from QEMU command line
func extractUUIDFromCmdline(cmdline string) string {
	// Try to extract from /opt/dstack/run/vm/UUID/ pattern
	re := regexp.MustCompile(`run/vm/([^/\x00]+)`)
	matches := re.FindStringSubmatch(cmdline)
	if len(matches) > 1 {
		return matches[1]
	}

	// Try to extract from guest-cid parameter
	re = regexp.MustCompile(`guest-cid=(\d+)`)
	matches = re.FindStringSubmatch(cmdline)
	if len(matches) > 1 {
		return "CID-" + matches[1]
	}

	return ""
}

// getNetworkStats reads network statistics from /proc/{pid}/net/dev
func getNetworkStats(pid int) (rxBytes, txBytes uint64, err error) {
	netDevFile := filepath.Join("/proc", strconv.Itoa(pid), "net", "dev")
	content, err := os.ReadFile(netDevFile)
	if err != nil {
		return 0, 0, err
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i < 2 { // Skip header lines
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "lo:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse RX bytes (field 1) and TX bytes (field 9)
		rx, err1 := strconv.ParseUint(fields[1], 10, 64)
		tx, err2 := strconv.ParseUint(fields[9], 10, 64)

		if err1 == nil && err2 == nil {
			rxBytes += rx
			txBytes += tx
		}
	}

	return rxBytes, txBytes, nil
}

// cleanOldSnapshots removes snapshots older than 1 hour
func cleanOldSnapshots(snapshots []NetworkSnapshot) []NetworkSnapshot {
	cutoff := time.Now().Add(-1 * time.Hour)
	cleaned := make([]NetworkSnapshot, 0, len(snapshots))

	for _, snapshot := range snapshots {
		if snapshot.Timestamp.After(cutoff) {
			cleaned = append(cleaned, snapshot)
		}
	}

	return cleaned
}

// calculateBytesInWindow calculates bytes transferred in a time window
func calculateBytesInWindow(snapshots []NetworkSnapshot, window time.Duration) (rxBytes, txBytes uint64) {
	if len(snapshots) < 2 {
		return 0, 0
	}

	cutoff := time.Now().Add(-window)

	// Find the first snapshot within the window
	var startSnapshot *NetworkSnapshot
	for i := len(snapshots) - 1; i >= 0; i-- {
		if snapshots[i].Timestamp.Before(cutoff) {
			if i+1 < len(snapshots) {
				startSnapshot = &snapshots[i+1]
			}
			break
		}
	}

	if startSnapshot == nil && len(snapshots) > 0 {
		startSnapshot = &snapshots[0]
	}

	if startSnapshot == nil {
		return 0, 0
	}

	// Use the latest snapshot as end
	endSnapshot := snapshots[len(snapshots)-1]

	if endSnapshot.RxBytes >= startSnapshot.RxBytes {
		rxBytes = endSnapshot.RxBytes - startSnapshot.RxBytes
	}
	if endSnapshot.TxBytes >= startSnapshot.TxBytes {
		txBytes = endSnapshot.TxBytes - startSnapshot.TxBytes
	}

	return rxBytes, txBytes
}

// updateQEMUMetrics updates Prometheus metrics for QEMU processes
func updateQEMUMetrics() {
	// First, copy the process list to avoid holding the main lock too long
	qemuStats.mu.RLock()
	processMap := make(map[int]*QEMUProcessStats)
	for pid, processStats := range qemuStats.Processes {
		processMap[pid] = processStats
	}
	qemuStats.mu.RUnlock()

	// Now process each one without holding the main lock
	for _, processStats := range processMap {
		processStats.mu.RLock()

		if len(processStats.Snapshots) == 0 {
			processStats.mu.RUnlock()
			continue
		}

		// Get the latest snapshot for total bytes
		latest := processStats.Snapshots[len(processStats.Snapshots)-1]
		uuid := processStats.UUID

		// Copy snapshots for window calculations to avoid holding lock during calculations
		snapshots := make([]NetworkSnapshot, len(processStats.Snapshots))
		copy(snapshots, processStats.Snapshots)

		processStats.mu.RUnlock()

		// Now we can safely update metrics without holding any locks
		qemuTotalBytes.WithLabelValues(uuid, "rx").Set(float64(latest.RxBytes))
		qemuTotalBytes.WithLabelValues(uuid, "tx").Set(float64(latest.TxBytes))

		// Calculate windowed metrics
		rx30s, tx30s := calculateBytesInWindow(snapshots, 30*time.Second)
		qemu30sBytes.WithLabelValues(uuid, "rx").Set(float64(rx30s))
		qemu30sBytes.WithLabelValues(uuid, "tx").Set(float64(tx30s))

		rx1min, tx1min := calculateBytesInWindow(snapshots, 1*time.Minute)
		qemu1minBytes.WithLabelValues(uuid, "rx").Set(float64(rx1min))
		qemu1minBytes.WithLabelValues(uuid, "tx").Set(float64(tx1min))

		rx5min, tx5min := calculateBytesInWindow(snapshots, 5*time.Minute)
		qemu5minBytes.WithLabelValues(uuid, "rx").Set(float64(rx5min))
		qemu5minBytes.WithLabelValues(uuid, "tx").Set(float64(tx5min))

		rx15min, tx15min := calculateBytesInWindow(snapshots, 15*time.Minute)
		qemu15minBytes.WithLabelValues(uuid, "rx").Set(float64(rx15min))
		qemu15minBytes.WithLabelValues(uuid, "tx").Set(float64(tx15min))

		rx1h, tx1h := calculateBytesInWindow(snapshots, 1*time.Hour)
		qemu1hBytes.WithLabelValues(uuid, "rx").Set(float64(rx1h))
		qemu1hBytes.WithLabelValues(uuid, "tx").Set(float64(tx1h))
	}
}

// monitorQEMUProcesses periodically monitors QEMU processes
func monitorQEMUProcesses() {
	log.Println("Starting QEMU process monitoring...")

	for {
		select {
		case <-qemuMonitorDone:
			log.Println("Stopping QEMU process monitoring...")
			return
		case <-qemuMonitorTicker.C:
			// Discover current QEMU processes
			processes, err := getQEMUProcesses()
			if err != nil {
				log.Printf("Error discovering QEMU processes: %v", err)
				continue
			}

			now := time.Now()

			qemuStats.mu.Lock()

			// Remove processes that no longer exist
			for pid := range qemuStats.Processes {
				if _, exists := processes[pid]; !exists {
					log.Printf("QEMU process %d no longer exists, removing from monitoring", pid)
					delete(qemuStats.Processes, pid)
				}
			}

			// Update or add processes
			for pid, uuid := range processes {
				// Get network stats
				rxBytes, txBytes, err := getNetworkStats(pid)
				if err != nil {
					log.Printf("Error reading network stats for PID %d: %v", pid, err)
					continue
				}

				snapshot := NetworkSnapshot{
					Timestamp: now,
					RxBytes:   rxBytes,
					TxBytes:   txBytes,
				}

				processStats, exists := qemuStats.Processes[pid]
				if !exists {
					log.Printf("Started monitoring QEMU process PID=%d UUID=%s", pid, uuid)
					processStats = &QEMUProcessStats{
						PID:       pid,
						UUID:      uuid,
						Snapshots: make([]NetworkSnapshot, 0),
					}
					qemuStats.Processes[pid] = processStats
				}

				processStats.mu.Lock()
				processStats.Snapshots = append(processStats.Snapshots, snapshot)
				// Clean old snapshots to prevent memory growth
				processStats.Snapshots = cleanOldSnapshots(processStats.Snapshots)
				processStats.mu.Unlock()
			}

			qemuStats.mu.Unlock()

			log.Printf("Monitored %d QEMU processes", len(processes))
		}
	}
}

// Start a periodic metrics updater
func startMetricsUpdater() {
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			updatePrometheusMetrics()
			updateQEMUMetrics()
		}
	}()
}

func main() {
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Show version information and exit")
	flag.StringVar(&globalConfig.LogFile, "log", "/var/log/haproxy.log", "HAProxy log file to monitor")
	flag.StringVar(&globalConfig.PositionFile, "pos", ".traffic-exporter.pos", "Position file for tail mode")
	flag.IntVar(&globalConfig.PrometheusPort, "port", 9100, "Prometheus metrics port")
	flag.BoolVar(&globalConfig.ResetOnStart, "reset", false, "Reset position and start from beginning of file")
	flag.DurationVar(&globalConfig.QEMUMonitorInterval, "qemu-monitor-interval", 5*time.Second, "Interval for QEMU process monitoring")
	flag.StringVar(&globalConfig.DomainSuffix, "domain-suffix", "phala.network", "Domain suffix for app ID extraction (e.g., phala.network)")
	flag.Parse()

	// Handle version flag
	if showVersion {
		fmt.Printf("dstack-traffic-exporter\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		fmt.Printf("Build Time: %s\n", BuildTime)
		os.Exit(0)
	}

	// Start periodic metrics updater
	startMetricsUpdater()

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/reset", resetHandler)
	http.HandleFunc("/query", queryHandler)
	go func() {
		log.Printf("Starting Prometheus server with /reset and /query endpoints on :%d", globalConfig.PrometheusPort)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", globalConfig.PrometheusPort), nil); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	// Start QEMU monitoring (always enabled)
	log.Printf("QEMU monitoring enabled with interval: %v", globalConfig.QEMUMonitorInterval)
	qemuMonitorTicker = time.NewTicker(globalConfig.QEMUMonitorInterval)
	qemuMonitorDone = make(chan bool)
	go monitorQEMUProcesses()

	// Start HAProxy log tailing (always enabled)
	log.Println("HAProxy log tailing enabled.")
	if err := startTailingInternal(globalConfig.LogFile, globalConfig.PositionFile, globalConfig.ResetOnStart); err != nil {
		log.Printf("Warning: Failed to initialize HAProxy log tailing: %v", err)
		log.Println("Continuing with QEMU monitoring only...")
	}

	<-done
	log.Println("Termination signal received. Shutting down...")

	// Stop HAProxy log tailing
	currentTailInstanceLock.Lock()
	if currentTailInstance != nil {
		log.Println("Stopping HAProxy log tailer...")
		if err := currentTailInstance.Stop(); err != nil {
			log.Printf("Error stopping tail instance during shutdown: %v", err)
		}
	}
	currentTailInstanceLock.Unlock()

	log.Println("Waiting for tailing goroutine to complete...")
	tailWg.Wait()
	log.Println("HAProxy log tailing stopped.")

	// Stop QEMU monitoring
	log.Println("Stopping QEMU monitoring...")
	if qemuMonitorTicker != nil {
		qemuMonitorTicker.Stop()
	}
	if qemuMonitorDone != nil {
		close(qemuMonitorDone)
	}

	log.Println("Application shut down gracefully.")
}
