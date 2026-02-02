package main

import (
	"bufio"
	"bytes"
	// "context"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	// "golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

// Constants and Configuration
const (
	Version           = "2.0.0"
	DefaultConfigPath = "/etc/apt-analyzer/config.yaml"
	MaxPacketSize     = 1600
	PrometheusPort    = 9090
	WebUIPort         = 8080
	MaxConnections    = 100000
	AlertWindowSize   = 1000
	GeoIPDatabasePath = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
)

// Config holds application configuration
type Config struct {
	Interfaces          []string    `yaml:"interfaces"`
	PrometheusEnabled   bool        `yaml:"prometheus_enabled"`
	WebUIEnabled        bool        `yaml:"webui_enabled"`
	AlertThresholds     AlertConfig `yaml:"alert_thresholds"`
	IOCSources          []string    `yaml:"ioc_sources"`
	GeoIPEnabled        bool        `yaml:"geoip_enabled"`
	StoragePath         string      `yaml:"storage_path"`
	RetentionDays       int         `yaml:"retention_days"`
	Whitelist           []string    `yaml:"whitelist"`
	Blacklist           []string    `yaml:"blacklist"`
	CaptureFilter       string      `yaml:"capture_filter"`
	MaxPacketRate       int         `yaml:"max_packet_rate"`
	LogLevel            string      `yaml:"log_level"`
	NotificationWebhook string      `yaml:"notification_webhook"`
}

// AlertConfig holds alert threshold configurations
type AlertConfig struct {
	PortScanThreshold    int           `yaml:"port_scan_threshold"`
	SynFloodThreshold    int           `yaml:"syn_flood_threshold"`
	BeaconIntervalMin    time.Duration `yaml:"beacon_interval_min"`
	BeaconIntervalMax    time.Duration `yaml:"beacon_interval_max"`
	DataExfilThreshold   int64         `yaml:"data_exfil_threshold"`
	ConnectionRateLimit  int           `yaml:"connection_rate_limit"`
	MaliciousIPThreshold int           `yaml:"malicious_ip_threshold"`
}

// TCPConnection represents a monitored TCP connection
type TCPConnection struct {
	ID            string
	SourceIP      net.IP
	SourcePort    uint16
	DestIP        net.IP
	DestPort      uint16
	State         string
	StartTime     time.Time
	LastSeen      time.Time
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint32
	PacketsReceived uint32
	Flags         []string
	GeoInfo       GeoIPInfo
	ThreatScore   float64
	Tags          []string
	ProcessID     int
	ProcessName   string
	UserAgent     string
	TLSInfo       TLSDetails
	HTTPInfo      HTTPDetails
}

// GeoIPInfo holds geographical information
type GeoIPInfo struct {
	Country     string
	City        string
	ASN         uint
	ISP         string
	Coordinates struct {
		Latitude  float64
		Longitude float64
	}
}

// TLSDetails holds TLS connection information
type TLSDetails struct {
	Version     string
	CipherSuite string
	SNI         string
	ALPN        []string
	Certificate struct {
		Issuer  string
		Subject string
		Expiry  time.Time
	}
}

// HTTPDetails holds HTTP request/response information
type HTTPDetails struct {
	Method      string
	Host        string
	URI         string
	UserAgent   string
	Referer     string
	StatusCode  int
	ContentType string
}

// Alert represents a security alert
type Alert struct {
	ID          string
	Timestamp   time.Time
	Severity    string
	Category    string
	Description string
	SourceIP    net.IP
	DestIP      net.IP
	DestPort    uint16
	Evidence    map[string]interface{}
	Confidence  float64
	Mitigation  []string
	References  []string
}

// IOCDatabase holds threat intelligence data
type IOCDatabase struct {
	IPs        map[string]IOCEntry
	Domains    map[string]IOCEntry
	URLs       map[string]IOCEntry
	Hashes     map[string]IOCEntry
	mu         sync.RWMutex
	LastUpdate time.Time
}

// IOCEntry represents a single IOC
type IOCEntry struct {
	Type        string
	Value       string
	ThreatType  string
	Confidence  float64
	FirstSeen   time.Time
	LastSeen    time.Time
	Description string
	Source      string
	Tags        []string
}

// ConnectionTracker manages TCP connections
type ConnectionTracker struct {
	connections map[string]*TCPConnection
	timeouts    map[string]time.Time
	beacons     map[string][]time.Time
	portScans   map[string]map[uint16]time.Time
	synCounts   map[string]int
	errorCounts map[string]int
	mu          sync.RWMutex
}

// AlertManager manages security alerts
type AlertManager struct {
	alerts      []*Alert
	subscribers map[string]chan *Alert
	mu          sync.RWMutex
}

// PacketSource handles packet capture
type PacketSource struct {
	handle     *pcap.Handle
	iface      string
	packetChan chan gopacket.Packet
	stop       chan struct{}
}

// Statistics holds runtime statistics
type Statistics struct {
	PacketsProcessed    uint64
	AlertsGenerated     uint64
	ConnectionsTracked  uint64
	MemoryUsage         uint64
	StartTime           time.Time
	mu                  sync.RWMutex
}

// APTAnalyzer main analyzer struct
type APTAnalyzer struct {
	config        *Config
	logger        *zap.Logger
	iocDB         *IOCDatabase
	connections   *ConnectionTracker
	alerts        *AlertManager
	geoIPDB       *geoip2.Reader
	packetSources []*PacketSource
	httpServer    *http.Server
	shutdown      chan struct{}
	wg            sync.WaitGroup
	stats         Statistics
}

// Metrics for Prometheus
var (
	packetsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "apt_analyzer_packets_processed_total",
		Help: "Total number of packets processed",
	}, []string{"interface", "protocol"})

	connectionsTracked = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "apt_analyzer_connections_tracked",
		Help: "Number of TCP connections currently being tracked",
	})

	alertsGenerated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "apt_analyzer_alerts_generated_total",
		Help: "Total number of alerts generated",
	}, []string{"severity", "category"})

	bytesTransferred = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "apt_analyzer_bytes_transferred_total",
		Help: "Total bytes transferred",
	}, []string{"direction", "ip"})

	threatScoreMetric = promauto.NewGaugeVec(prometheus.GaugeOpts{
	    Name: "apt_analyzer_threat_score",
	    Help: "Current threat score",
	}, []string{"ip"})


	geoIPHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "apt_analyzer_geoip_hits_total",
		Help: "GeoIP lookup hits",
	}, []string{"country"})
)

func main() {
	configPath := flag.String("config", DefaultConfigPath, "Path to configuration file")
	interfaceName := flag.String("interface", "any", "Network interface to capture")
	debug := flag.Bool("debug", false, "Enable debug mode")
	dumpConfig := flag.Bool("dump-config", false, "Dump default configuration and exit")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	if *dumpConfig {
		dumpDefaultConfig()
		return
	}

	// Setup logger
	var logger *zap.Logger
	var err error
	if *debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}
	defer logger.Sync()

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Override interface if specified via flag
	if *interfaceName != "any" {
		config.Interfaces = []string{*interfaceName}
	}

	// Create analyzer
	analyzer, err := NewAPTAnalyzer(config, logger)
	if err != nil {
		logger.Fatal("Failed to create analyzer", zap.Error(err))
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start analyzer
	if err := analyzer.Start(); err != nil {
		logger.Fatal("Failed to start analyzer", zap.Error(err))
	}

	logger.Info("APT Analyzer started",
		zap.String("version", Version),
		zap.Strings("interfaces", config.Interfaces),
		zap.Bool("prometheus", config.PrometheusEnabled),
		zap.Bool("webui", config.WebUIEnabled),
	)

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutdown signal received")

	// Graceful shutdown
	analyzer.Stop()
	logger.Info("APT Analyzer stopped")
}

// NewAPTAnalyzer creates a new APT analyzer instance
func NewAPTAnalyzer(config *Config, logger *zap.Logger) (*APTAnalyzer, error) {
	// Initialize IOC database
	iocDB := &IOCDatabase{
		IPs:     make(map[string]IOCEntry),
		Domains: make(map[string]IOCEntry),
		URLs:    make(map[string]IOCEntry),
		Hashes:  make(map[string]IOCEntry),
	}

	// Load GeoIP database if enabled
	var geoIPDB *geoip2.Reader
	if config.GeoIPEnabled {
		db, err := geoip2.Open(GeoIPDatabasePath)
		if err != nil {
			logger.Warn("Failed to open GeoIP database", zap.Error(err))
		} else {
			geoIPDB = db
		}
	}

	// Create storage directory
	if err := os.MkdirAll(config.StoragePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &APTAnalyzer{
		config:      config,
		logger:      logger,
		iocDB:       iocDB,
		connections: NewConnectionTracker(),
		alerts:      NewAlertManager(),
		geoIPDB:     geoIPDB,
		shutdown:    make(chan struct{}),
		stats: Statistics{
			StartTime: time.Now(),
		},
	}, nil
}

// Start begins packet capture and analysis
func (a *APTAnalyzer) Start() error {
	// Start IOC updater
	a.wg.Add(1)
	go a.updateIOCs()

	// Start packet capture on all interfaces
	for _, iface := range a.config.Interfaces {
		if err := a.startPacketCapture(iface); err != nil {
			a.logger.Error("Failed to start packet capture",
				zap.String("interface", iface),
				zap.Error(err),
			)
		}
	}

	// Start alert processor
	a.wg.Add(1)
	go a.processAlerts()

	// Start statistics reporter
	a.wg.Add(1)
	go a.reportStatistics()

	// Start HTTP server if enabled
	if a.config.WebUIEnabled {
		a.wg.Add(1)
		go a.startHTTPServer()
	}

	// Start Prometheus metrics if enabled
	if a.config.PrometheusEnabled {
		a.wg.Add(1)
		go a.startPrometheus()
	}

	return nil
}

// Stop gracefully shuts down the analyzer
func (a *APTAnalyzer) Stop() {
	close(a.shutdown)
	a.wg.Wait()

	// Close all packet sources
	for _, ps := range a.packetSources {
		ps.Close()
	}

	// Close GeoIP database
	if a.geoIPDB != nil {
		a.geoIPDB.Close()
	}

	// Save state
	a.saveState()
}

// Close closes the packet source
func (ps *PacketSource) Close() {
	close(ps.stop)
	ps.handle.Close()
}

// startPacketCapture starts capturing packets on an interface
func (a *APTAnalyzer) startPacketCapture(interfaceName string) error {
	var handle *pcap.Handle
	var err error

	if interfaceName == "any" {
		handle, err = pcap.OpenLive("any", MaxPacketSize, true, pcap.BlockForever)
	} else {
		handle, err = pcap.OpenLive(interfaceName, MaxPacketSize, true, pcap.BlockForever)
	}

	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", interfaceName, err)
	}

	// Apply capture filter if specified
	if a.config.CaptureFilter != "" {
		if err := handle.SetBPFFilter(a.config.CaptureFilter); err != nil {
			handle.Close()
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	ps := &PacketSource{
		handle:     handle,
		iface:      interfaceName,
		packetChan: make(chan gopacket.Packet, 1000),
		stop:       make(chan struct{}),
	}

	a.packetSources = append(a.packetSources, ps)

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer close(ps.packetChan)
		defer handle.Close()

		for {
			select {
			case <-ps.stop:
				return
			case packet := <-packetSource.Packets():
				select {
				case ps.packetChan <- packet:
				case <-ps.stop:
					return
				default:
					// Drop packet if channel is full
					a.logger.Warn("Packet channel full, dropping packet")
				}
			}
		}
	}()

	a.wg.Add(1)
	go a.processPackets(ps)

	return nil
}

// processPackets processes captured packets
func (a *APTAnalyzer) processPackets(ps *PacketSource) {
	defer a.wg.Done()

	packetCount := 0
	startTime := time.Now()

	for {
		select {
		case <-a.shutdown:
			return
		case <-ps.stop:
			return
		case packet, ok := <-ps.packetChan:
			if !ok {
				return
			}

			packetCount++
			a.stats.mu.Lock()
			a.stats.PacketsProcessed++
			a.stats.mu.Unlock()

			// Process packet
			a.analyzePacket(packet, ps.iface)

			// Rate limiting
			if a.config.MaxPacketRate > 0 && packetCount%1000 == 0 {
				elapsed := time.Since(startTime)
				expected := time.Duration(packetCount) * time.Second / time.Duration(a.config.MaxPacketRate)
				if elapsed < expected {
					time.Sleep(expected - elapsed)
				}
			}
		}
	}
}

// analyzePacket analyzes a single packet for APT indicators
func (a *APTAnalyzer) analyzePacket(packet gopacket.Packet, interfaceName string) {
	// Update metrics
	packetsProcessed.WithLabelValues(interfaceName, "TCP").Inc()

	// Check for TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	// Get IP layer
	var srcIP, dstIP net.IP
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4, _ := ip4Layer.(*layers.IPv4)
		srcIP = ip4.SrcIP
		dstIP = ip4.DstIP
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		srcIP = ip6.SrcIP
		dstIP = ip6.DstIP
	} else {
		return
	}

	// Check IOC database
	if entry, found := a.iocDB.LookupIP(srcIP.String()); found {
		a.generateAlert("IOC_MATCH", "HIGH", srcIP, dstIP, uint16(tcp.DstPort),

			fmt.Sprintf("Source IP matched known IOC: %s", entry.Description),
			map[string]interface{}{
				"ioc_type":   entry.Type,
				"threat_type": entry.ThreatType,
				"confidence":  entry.Confidence,
				"source":     entry.Source,
			})
	}

	// Track connection
	connID := generateConnectionID(srcIP, dstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort))
	conn := a.connections.GetOrCreate(connID, srcIP, dstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort))


	// Update connection state
	conn.Update(tcp, packet.Metadata().Timestamp)

	// Analyze TCP flags for anomalies
	a.analyzeTCPFlags(conn, tcp, srcIP, dstIP)

	// Check for port scanning
	a.detectPortScanning(srcIP, dstIP, uint16(tcp.DstPort), packet.Metadata().Timestamp)


	// Check for SYN flood
	a.detectSYNFlood(srcIP, packet.Metadata().Timestamp)

	// Analyze payload for threats
	if tcp.Payload != nil && len(tcp.Payload) > 0 {
		a.analyzePayload(conn, tcp.Payload, srcIP, dstIP)
	}

	// Check for beaconing behavior
	a.detectBeaconing(conn)

	// Update GeoIP information
	if a.geoIPDB != nil {
		a.updateGeoIPInfo(conn)
	}

	// Update metrics
	connectionsTracked.Set(float64(a.connections.Count()))
	bytesTransferred.WithLabelValues("out", srcIP.String()).Add(float64(len(tcp.Payload)))
}

// analyzeTCPFlags analyzes TCP flags for malicious patterns
func (a *APTAnalyzer) analyzeTCPFlags(conn *TCPConnection, tcp *layers.TCP, srcIP, dstIP net.IP) {
	flags := []string{}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}

	conn.Flags = flags

	// Detect suspicious flag combinations
	if tcp.SYN && tcp.FIN { // SYN-FIN attack
		a.generateAlert("SYN_FIN_ATTACK", "HIGH", srcIP, dstIP, uint16(tcp.DstPort),

			"SYN-FIN packet detected (possible attack)",
			map[string]interface{}{
				"flags": flags,
			})
	}

	if tcp.SYN && !tcp.ACK && conn.PacketsSent == 0 { // First SYN
		// Check for SYN to suspicious port
		if isSuspiciousPort(uint16(tcp.DstPort)) {
			a.generateAlert("SUSPICIOUS_PORT", "MEDIUM", srcIP, dstIP, uint16(tcp.DstPort),

				fmt.Sprintf("SYN to suspicious port %d", tcp.DstPort),
				map[string]interface{}{
					"port": tcp.DstPort,
				})
		}
	}
}

// detectPortScanning detects port scanning activity
func (a *APTAnalyzer) detectPortScanning(srcIP, dstIP net.IP, port uint16, timestamp time.Time) {
	key := srcIP.String()
	portScans := a.connections.GetPortScans(key)

	if portScans == nil {
		portScans = make(map[uint16]time.Time)
		a.connections.SetPortScans(key, portScans)
	}

	portScans[port] = timestamp

	// Check threshold
	if len(portScans) >= a.config.AlertThresholds.PortScanThreshold {
		// Remove old entries
		for p, t := range portScans {
			if time.Since(t) > time.Minute {
				delete(portScans, p)
			}
		}

		if len(portScans) >= a.config.AlertThresholds.PortScanThreshold {
			a.generateAlert("PORT_SCAN", "HIGH", srcIP, dstIP, port,
				fmt.Sprintf("Port scanning detected: %d unique ports", len(portScans)),
				map[string]interface{}{
					"ports_scanned": len(portScans),
					"ports":         getPortList(portScans),
				})

			// Clear after alert
			a.connections.ClearPortScans(key)
		}
	}
}

// detectSYNFlood detects SYN flood attacks
func (a *APTAnalyzer) detectSYNFlood(srcIP net.IP, timestamp time.Time) {
	// Track SYN packets per source IP
	synCount := a.connections.GetSYNCount(srcIP.String())
	synCount++

	if synCount >= a.config.AlertThresholds.SynFloodThreshold {
		a.generateAlert("SYN_FLOOD", "CRITICAL", srcIP, nil, 0,
			fmt.Sprintf("SYN flood detected: %d SYN packets", synCount),
			map[string]interface{}{
				"syn_count": synCount,
			})
	}

	// Reset counter after window
	go func() {
		time.Sleep(time.Second)
		a.connections.ResetSYNCount(srcIP.String())
	}()
}

// analyzePayload analyzes packet payload for threats
func (a *APTAnalyzer) analyzePayload(conn *TCPConnection, payload []byte, srcIP, dstIP net.IP) {
	// Check for known malware signatures
	if matches := a.detectMalwareSignatures(payload); len(matches) > 0 {
		a.generateAlert("MALWARE_SIGNATURE", "CRITICAL", srcIP, dstIP, conn.DestPort,
			"Malware signature detected in payload",
			map[string]interface{}{
				"signatures":      matches,
				"payload_preview": string(payload[:min(len(payload), 100)]),
			})
	}

	// Check for data exfiltration patterns
	if a.isDataExfiltration(conn, payload) {
		a.generateAlert("DATA_EXFILTRATION", "HIGH", srcIP, dstIP, conn.DestPort,
			"Possible data exfiltration detected",
			map[string]interface{}{
				"bytes_sent": conn.BytesSent,
				"pattern":    "large_encrypted_or_compressed",
			})
	}

	// Parse HTTP if applicable
	if conn.DestPort == 80 || conn.DestPort == 443 || conn.DestPort == 8080 {
		a.parseHTTP(conn, payload)
	}

	// Parse TLS if applicable
	if conn.DestPort == 443 || conn.DestPort == 8443 {
		a.parseTLS(conn, payload)
	}
}

// detectMalwareSignatures checks payload against known malware signatures
func (a *APTAnalyzer) detectMalwareSignatures(payload []byte) []string {
	signatures := []string{
		// Example signatures (in real implementation, use proper signature database)
		"eval(base64_decode(",
		"powershell -e ",
		"cmd.exe /c ",
		"<script>alert(1)</script>",
		"../../../../etc/passwd",
	}

	var matches []string
	payloadStr := string(payload)

	for _, sig := range signatures {
		if strings.Contains(payloadStr, sig) {
			matches = append(matches, sig)
		}
	}

	return matches
}

// isDataExfiltration checks for data exfiltration patterns
func (a *APTAnalyzer) isDataExfiltration(conn *TCPConnection, payload []byte) bool {
	// Check if large amount of data is being sent to external IP
	if conn.BytesSent > uint64(a.config.AlertThresholds.DataExfilThreshold) {
		// Check if destination is external (not in private ranges)
		if isExternalIP(conn.DestIP) {
			// Check for encryption/compression patterns
			if isEncryptedOrCompressed(payload) {
				return true
			}
		}
	}
	return false
}

// detectBeaconing detects beaconing behavior (regular calls to C2)
func (a *APTAnalyzer) detectBeaconing(conn *TCPConnection) {
	beacons := a.connections.GetBeacons(conn.ID)
	beacons = append(beacons, time.Now())

	// Keep only recent beacons
	windowStart := time.Now().Add(-5 * time.Minute)
	var recentBeacons []time.Time
	for _, t := range beacons {
		if t.After(windowStart) {
			recentBeacons = append(recentBeacons, t)
		}
	}

	if len(recentBeacons) > 1 {
		// Calculate intervals
		var intervals []time.Duration
		for i := 1; i < len(recentBeacons); i++ {
			intervals = append(intervals, recentBeacons[i].Sub(recentBeacons[i-1]))
		}

		// Check for regular intervals (beaconing)
		if isRegularInterval(intervals, a.config.AlertThresholds.BeaconIntervalMin,
			a.config.AlertThresholds.BeaconIntervalMax) {
			a.generateAlert("BEACONING", "HIGH", conn.SourceIP, conn.DestIP, conn.DestPort,
				"Beaconing behavior detected",
				map[string]interface{}{
					"interval_seconds": intervals[len(intervals)-1].Seconds(),
					"beacon_count":     len(recentBeacons),
				})
		}
	}

	a.connections.SetBeacons(conn.ID, recentBeacons)
}

// parseHTTP parses HTTP traffic
func (a *APTAnalyzer) parseHTTP(conn *TCPConnection, payload []byte) {
	payloadStr := string(payload)

	// Simple HTTP request detection
	if strings.HasPrefix(payloadStr, "GET ") ||
		strings.HasPrefix(payloadStr, "POST ") ||
		strings.HasPrefix(payloadStr, "PUT ") ||
		strings.HasPrefix(payloadStr, "DELETE ") ||
		strings.HasPrefix(payloadStr, "HEAD ") ||
		strings.HasPrefix(payloadStr, "OPTIONS ") {

		lines := strings.Split(payloadStr, "\r\n")
		if len(lines) > 0 {
			parts := strings.Split(lines[0], " ")
			if len(parts) >= 3 {
				conn.HTTPInfo.Method = parts[0]
				conn.HTTPInfo.URI = parts[1]

				// Extract headers
				for _, line := range lines[1:] {
					if line == "" {
						break // End of headers
					}
					if strings.HasPrefix(strings.ToLower(line), "host: ") {
						conn.HTTPInfo.Host = strings.TrimSpace(line[5:])
					}
					if strings.HasPrefix(strings.ToLower(line), "user-agent: ") {
						conn.HTTPInfo.UserAgent = strings.TrimSpace(line[12:])
						conn.UserAgent = conn.HTTPInfo.UserAgent
					}
					if strings.HasPrefix(strings.ToLower(line), "referer: ") {
						conn.HTTPInfo.Referer = strings.TrimSpace(line[9:])
					}
				}

				// Check for suspicious URIs
				if isSuspiciousURI(conn.HTTPInfo.URI) {
					a.generateAlert("SUSPICIOUS_URI", "MEDIUM", conn.SourceIP, conn.DestIP, conn.DestPort,
						fmt.Sprintf("Suspicious URI: %s", conn.HTTPInfo.URI),
						map[string]interface{}{
							"uri":    conn.HTTPInfo.URI,
							"method": conn.HTTPInfo.Method,
						})
				}

				// Check for exploit patterns
				if containsExploitPatterns(conn.HTTPInfo.URI) {
					a.generateAlert("WEB_EXPLOIT", "HIGH", conn.SourceIP, conn.DestIP, conn.DestPort,
						"Web exploit attempt detected",
						map[string]interface{}{
							"uri":     conn.HTTPInfo.URI,
							"pattern": "exploit_pattern",
						})
				}
			}
		}
	}

	// Check for HTTP response
	if strings.HasPrefix(payloadStr, "HTTP/") {
		lines := strings.Split(payloadStr, "\r\n")
		if len(lines) > 0 {
			parts := strings.Split(lines[0], " ")
			if len(parts) >= 2 {
				if statusCode, err := strconv.Atoi(parts[1]); err == nil {
					conn.HTTPInfo.StatusCode = statusCode

					// Check for suspicious status codes
					if statusCode >= 400 && statusCode < 500 {
						// Client errors might indicate scanning
						a.connections.IncrementErrorCount(conn.SourceIP.String())
					}
				}
			}

			// Extract headers
			for _, line := range lines[1:] {
				if line == "" {
					break
				}
				if strings.HasPrefix(strings.ToLower(line), "content-type: ") {
					conn.HTTPInfo.ContentType = strings.TrimSpace(line[14:])
				}
			}
		}
	}
}

// parseTLS parses TLS handshake data
func (a *APTAnalyzer) parseTLS(conn *TCPConnection, payload []byte) {
	// Check for TLS handshake
	if len(payload) > 0 && payload[0] == 0x16 { // TLS Handshake
		// Simple TLS parsing - in production, use proper TLS parser
		if len(payload) > 5 {
			// Check for ClientHello
			if payload[5] == 0x01 { // ClientHello
				// Extract SNI if present
				sni := extractSNI(payload)
				if sni != "" {
					conn.TLSInfo.SNI = sni

					// Check IOC database for malicious domains
					if entry, found := a.iocDB.LookupDomain(sni); found {
						a.generateAlert("MALICIOUS_DOMAIN", "HIGH", conn.SourceIP, conn.DestIP, conn.DestPort,
							fmt.Sprintf("TLS connection to malicious domain: %s", sni),
							map[string]interface{}{
								"domain":   sni,
								"ioc_info": entry,
							})
					}

					// Check for DGA (Domain Generation Algorithm) patterns
					if isDGADomain(sni) {
						a.generateAlert("DGA_DOMAIN", "HIGH", conn.SourceIP, conn.DestIP, conn.DestPort,
							"DGA domain detected in TLS SNI",
							map[string]interface{}{
								"domain":  sni,
								"entropy": calculateEntropy(sni),
							})
					}
				}
			}
		}
	}
}

// updateGeoIPInfo updates geographical information for connection
func (a *APTAnalyzer) updateGeoIPInfo(conn *TCPConnection) {
	if a.geoIPDB == nil {
		return
	}

	// Lookup source IP
	if record, err := a.geoIPDB.Country(conn.SourceIP); err == nil {
		conn.GeoInfo.Country = record.Country.Names["en"]
		geoIPHits.WithLabelValues(conn.GeoInfo.Country).Inc()
	}

	// Update threat score based on country
	if conn.GeoInfo.Country != "" {
		// Adjust threat score based on country reputation
		threatScore := a.calculateThreatScore(conn)
		conn.ThreatScore = threatScore
		threatScoreMetric.WithLabelValues(conn.SourceIP.String()).Set(threatScore)

	}
}

// calculateThreatScore calculates threat score for a connection
func (a *APTAnalyzer) calculateThreatScore(conn *TCPConnection) float64 {
	score := 0.0

	// Base score from IOC
	if _, found := a.iocDB.LookupIP(conn.SourceIP.String()); found {
		score += 0.7
	}

	// Suspicious port
	if isSuspiciousPort(conn.DestPort) {
		score += 0.3
	}

	// Beaconing detection
	beacons := a.connections.GetBeacons(conn.ID)
	if len(beacons) > 5 {
		score += 0.4
	}

	// Data exfiltration
	if conn.BytesSent > uint64(a.config.AlertThresholds.DataExfilThreshold) {
		score += 0.5
	}

	// Country risk (example - adjust based on your threat intelligence)
	highRiskCountries := map[string]bool{
		"Russia":      true,
		"China":       true,
		"North Korea": true,
		"Iran":        true,
	}
	if highRiskCountries[conn.GeoInfo.Country] {
		score += 0.3
	}

	return minFloat(score, 1.0)
}

// generateAlert creates a new security alert
func (a *APTAnalyzer) generateAlert(category, severity string, srcIP, dstIP net.IP, port uint16,
	description string, evidence map[string]interface{}) {

	alert := &Alert{
		ID:          generateAlertID(),
		Timestamp:   time.Now(),
		Severity:    severity,
		Category:    category,
		Description: description,
		SourceIP:    srcIP,
		DestIP:      dstIP,
		DestPort:    port,
		Evidence:    evidence,
		Confidence:  0.8, // Default confidence
		Mitigation:  a.getMitigationSteps(category),
		References:  a.getReferences(category),
	}

	// Update statistics
	a.stats.mu.Lock()
	a.stats.AlertsGenerated++
	a.stats.mu.Unlock()

	// Update metrics
	alertsGenerated.WithLabelValues(severity, category).Inc()

	// Send to alert manager
	a.alerts.AddAlert(alert)

	// Log alert
	a.logger.Warn("Security alert generated",
		zap.String("category", category),
		zap.String("severity", severity),
		zap.String("source_ip", srcIP.String()),
		zap.String("description", description),
		zap.Any("evidence", evidence),
	)

	// Send notification if configured
	if a.config.NotificationWebhook != "" {
		go a.sendNotification(alert)
	}
}

// processAlerts processes and correlates alerts
func (a *APTAnalyzer) processAlerts() {
	defer a.wg.Done()

	alertWindow := make([]*Alert, 0, AlertWindowSize)
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	for {
		select {
		case <-a.shutdown:
			return
		case <-ticker.C:
			// Get new alerts
			newAlerts := a.alerts.GetAlertsSince(time.Now().Add(-5 * time.Second))
			alertWindow = append(alertWindow, newAlerts...)

			// Keep window size limited
			if len(alertWindow) > AlertWindowSize {
				alertWindow = alertWindow[len(alertWindow)-AlertWindowSize:]
			}

			// Correlate alerts
			a.correlateAlerts(alertWindow)

			// Save alerts to disk
			if len(newAlerts) > 0 {
				a.saveAlerts(newAlerts)
			}
		}
	}
}

// correlateAlerts correlates multiple alerts to identify campaigns
func (a *APTAnalyzer) correlateAlerts(alerts []*Alert) {
	if len(alerts) < 2 {
		return
	}

	// Group alerts by source IP
	alertsByIP := make(map[string][]*Alert)
	for _, alert := range alerts {
		key := alert.SourceIP.String()
		alertsByIP[key] = append(alertsByIP[key], alert)
	}

	// Check for multi-stage attacks
	for ip, ipAlerts := range alertsByIP {
		if len(ipAlerts) >= 3 {
			categories := make(map[string]int)
			for _, alert := range ipAlerts {
				categories[alert.Category]++
			}

			// If multiple types of alerts from same IP, might be campaign
			if len(categories) >= 2 {
				a.generateAlert("MULTI_STAGE_ATTACK", "HIGH",
					net.ParseIP(ip), nil, 0,
					fmt.Sprintf("Multi-stage attack campaign detected from %s", ip),
					map[string]interface{}{
						"alert_count": len(ipAlerts),
						"categories":  categories,
						"timeline":    getAlertTimeline(ipAlerts),
					})
			}
		}
	}
}

// updateIOCs updates IOC database from external sources
func (a *APTAnalyzer) updateIOCs() {
	defer a.wg.Done()

	ticker := time.NewTicker(time.Hour * 6)
	defer ticker.Stop()

	// Initial update
	a.updateIOCDatabase()

	for {
		select {
		case <-a.shutdown:
			return
		case <-ticker.C:
			a.updateIOCDatabase()
		}
	}
}

// updateIOCDatabase fetches IOCs from configured sources
func (a *APTAnalyzer) updateIOCDatabase() {
	for _, source := range a.config.IOCSources {
		go func(url string) {
			if err := a.fetchIOCs(url); err != nil {
				a.logger.Error("Failed to fetch IOCs",
					zap.String("source", url),
					zap.Error(err))
			}
		}(source)
	}
}

// fetchIOCs fetches IOCs from a specific source
func (a *APTAnalyzer) fetchIOCs(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse based on source type
	if strings.HasSuffix(url, ".csv") {
		return a.iocDB.parseCSVIOCs(body, url)
	} else if strings.HasSuffix(url, ".json") {
		return a.iocDB.parseJSONIOCs(body, url)
	} else if strings.HasSuffix(url, ".txt") {
		return a.iocDB.parseTextIOCs(body, url)
	}

	return nil
}

// reportStatistics reports runtime statistics
func (a *APTAnalyzer) reportStatistics() {
	defer a.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-a.shutdown:
			return
		case <-ticker.C:
			a.stats.mu.RLock()
			stats := a.stats
			a.stats.mu.RUnlock()

			a.logger.Info("Runtime statistics",
				zap.Uint64("packets_processed", stats.PacketsProcessed),
				zap.Uint64("alerts_generated", stats.AlertsGenerated),
				zap.Uint64("connections_tracked", stats.ConnectionsTracked),
				zap.Duration("uptime", time.Since(stats.StartTime)),
			)
		}
	}
}

// startHTTPServer starts the web UI server
func (a *APTAnalyzer) startHTTPServer() {
	defer a.wg.Done()

	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/alerts", a.handleAlertsAPI)
	mux.HandleFunc("/api/connections", a.handleConnectionsAPI)
	mux.HandleFunc("/api/statistics", a.handleStatisticsAPI)
	mux.HandleFunc("/api/iocs", a.handleIOCsAPI)
	mux.HandleFunc("/api/geo", a.handleGeoAPI)
	mux.HandleFunc("/ws", a.handleWebSocket)

	// Static files (web UI)
	fs := http.FileServer(http.Dir("./webui"))
	mux.Handle("/", fs)

	a.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", WebUIPort),
		Handler: mux,
	}

	if err := a.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		a.logger.Error("HTTP server failed", zap.Error(err))
	}
}

// startPrometheus starts Prometheus metrics endpoint
func (a *APTAnalyzer) startPrometheus() {
	defer a.wg.Done()

	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(fmt.Sprintf(":%d", PrometheusPort), nil); err != nil {
		a.logger.Error("Prometheus server failed", zap.Error(err))
	}
}

// NewConnectionTracker creates a new ConnectionTracker
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]*TCPConnection),
		timeouts:    make(map[string]time.Time),
		beacons:     make(map[string][]time.Time),
		portScans:   make(map[string]map[uint16]time.Time),
		synCounts:   make(map[string]int),
		errorCounts: make(map[string]int),
	}
}

// GetOrCreate gets or creates a connection
func (ct *ConnectionTracker) GetOrCreate(id string, srcIP, dstIP net.IP, srcPort, dstPort uint16) *TCPConnection {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if conn, exists := ct.connections[id]; exists {
		return conn
	}

	conn := &TCPConnection{
		ID:         id,
		SourceIP:   srcIP,
		SourcePort: srcPort,
		DestIP:     dstIP,
		DestPort:   dstPort,
		StartTime:  time.Now(),
		LastSeen:   time.Now(),
		State:      "NEW",
	}

	ct.connections[id] = conn
	return conn
}

// Get gets a connection by ID
func (ct *ConnectionTracker) Get(id string) (*TCPConnection, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	conn, exists := ct.connections[id]
	return conn, exists
}

// Count returns the number of tracked connections
func (ct *ConnectionTracker) Count() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.connections)
}

// GetAll returns all connections
func (ct *ConnectionTracker) GetAll() []*TCPConnection {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	connections := make([]*TCPConnection, 0, len(ct.connections))
	for _, conn := range ct.connections {
		connections = append(connections, conn)
	}
	return connections
}

// GetPortScans gets port scans for a key
func (ct *ConnectionTracker) GetPortScans(key string) map[uint16]time.Time {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.portScans[key]
}

// SetPortScans sets port scans for a key
func (ct *ConnectionTracker) SetPortScans(key string, scans map[uint16]time.Time) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.portScans[key] = scans
}

// ClearPortScans clears port scans for a key
func (ct *ConnectionTracker) ClearPortScans(key string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.portScans, key)
}

// GetSYNCount gets SYN count for a key
func (ct *ConnectionTracker) GetSYNCount(key string) int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.synCounts[key]
}

// ResetSYNCount resets SYN count for a key
func (ct *ConnectionTracker) ResetSYNCount(key string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.synCounts, key)
}

// GetBeacons gets beacons for a key
func (ct *ConnectionTracker) GetBeacons(key string) []time.Time {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.beacons[key]
}

// SetBeacons sets beacons for a key
func (ct *ConnectionTracker) SetBeacons(key string, beacons []time.Time) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.beacons[key] = beacons
}

// IncrementErrorCount increments error count for a key
func (ct *ConnectionTracker) IncrementErrorCount(key string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.errorCounts[key]++
}

// Update updates connection state
func (c *TCPConnection) Update(tcp *layers.TCP, timestamp time.Time) {
	c.LastSeen = timestamp

	if tcp.SYN && !tcp.ACK {
		c.State = "SYN_SENT"
	} else if tcp.SYN && tcp.ACK {
		c.State = "SYN_RECEIVED"
	} else if tcp.FIN {
		c.State = "CLOSING"
	} else if tcp.RST {
		c.State = "RESET"
	}

	// Update packet and byte counts
	if len(tcp.Payload) > 0 {
		c.BytesSent += uint64(len(tcp.Payload))
		c.PacketsSent++
	}
}

// NewAlertManager creates a new AlertManager
func NewAlertManager() *AlertManager {
	return &AlertManager{
		alerts:      make([]*Alert, 0),
		subscribers: make(map[string]chan *Alert),
	}
}

// AddAlert adds an alert
func (am *AlertManager) AddAlert(alert *Alert) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alerts = append(am.alerts, alert)
}

// GetRecentAlerts gets recent alerts
func (am *AlertManager) GetRecentAlerts(count int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	start := len(am.alerts) - count
	if start < 0 {
		start = 0
	}
	return am.alerts[start:]
}

// GetAlertsSince gets alerts since a time
func (am *AlertManager) GetAlertsSince(since time.Time) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var result []*Alert
	for _, alert := range am.alerts {
		if alert.Timestamp.After(since) {
			result = append(result, alert)
		}
	}
	return result
}

// LookupIP looks up an IP in IOC database
func (ioc *IOCDatabase) LookupIP(ip string) (IOCEntry, bool) {
	ioc.mu.RLock()
	defer ioc.mu.RUnlock()
	entry, exists := ioc.IPs[ip]
	return entry, exists
}

// LookupDomain looks up a domain in IOC database
func (ioc *IOCDatabase) LookupDomain(domain string) (IOCEntry, bool) {
	ioc.mu.RLock()
	defer ioc.mu.RUnlock()
	entry, exists := ioc.Domains[domain]
	return entry, exists
}

// Count returns total IOC count
func (ioc *IOCDatabase) Count() int {
	ioc.mu.RLock()
	defer ioc.mu.RUnlock()
	return len(ioc.IPs) + len(ioc.Domains) + len(ioc.URLs) + len(ioc.Hashes)
}

// parseCSVIOCs parses CSV IOCs
// parseCSVIOCs parses CSV IOCs with different formats
func (ioc *IOCDatabase) parseCSVIOCs(data []byte, source string) error {
	// Try different CSV formats
	reader := csv.NewReader(bytes.NewReader(data))
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // Allow variable number of fields
	
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	ioc.mu.Lock()
	defer ioc.mu.Unlock()

	// Handle different CSV formats based on source
	for _, record := range records {
		if len(record) == 0 {
			continue
		}

		// Try to extract IP from different positions
		var ip string
		for _, field := range record {
			field = strings.TrimSpace(field)
			if net.ParseIP(field) != nil {
				ip = field
				break
			}
			
			// Check for IP in URLs or other patterns
			if strings.Contains(field, ".") && len(field) > 6 {
				// Try to extract IP from strings like "http://1.2.3.4/path"
				re := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
				if matches := re.FindString(field); matches != "" && net.ParseIP(matches) != nil {
					ip = matches
					break
				}
			}
		}

		if ip != "" {
			// Create IOC entry
			entry := IOCEntry{
				Type:        "IP",
				Value:       ip,
				ThreatType:  getThreatTypeFromSource(source),
				Confidence:  0.8,
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Description: fmt.Sprintf("Malicious IP from %s", source),
				Source:      source,
				Tags:        getTagsFromSource(source),
			}
			
			ioc.IPs[ip] = entry
		}
	}

	ioc.LastUpdate = time.Now()
	return nil
}

// Helper function to determine threat type from source URL
func getThreatTypeFromSource(source string) string {
	source = strings.ToLower(source)
	
	switch {
	case strings.Contains(source, "feodotracker"):
		return "C2"
	case strings.Contains(source, "sslbl"):
		return "SSL"
	case strings.Contains(source, "emergingthreats"):
		return "compromised"
	case strings.Contains(source, "alienvault"):
		return "reputation"
	case strings.Contains(source, "binarydefense"):
		return "banlist"
	default:
		return "malicious"
	}
}

// Helper function to get tags from source
func getTagsFromSource(source string) []string {
	source = strings.ToLower(source)
	var tags []string
	
	if strings.Contains(source, "feodotracker") {
		tags = append(tags, "C2", "feodo", "trickbot")
	}
	if strings.Contains(source, "sslbl") {
		tags = append(tags, "SSL", "malware", "botnet")
	}
	if strings.Contains(source, "emergingthreats") {
		tags = append(tags, "compromised", "et", "rules")
	}
	
	if len(tags) == 0 {
		tags = []string{"malicious"}
	}
	
	return tags
}
// parseJSONIOCs parses JSON IOCs
func (ioc *IOCDatabase) parseJSONIOCs(data []byte, source string) error {
	var iocs []map[string]interface{}
	if err := json.Unmarshal(data, &iocs); err != nil {
		return err
	}

	ioc.mu.Lock()
	defer ioc.mu.Unlock()

	for _, entry := range iocs {
		if value, ok := entry["value"].(string); ok {
			if net.ParseIP(value) != nil {
				ioc.IPs[value] = IOCEntry{
					Type:        "IP",
					Value:       value,
					ThreatType:  "malicious",
					Confidence:  0.8,
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
					Description: "Malicious IP from " + source,
					Source:      source,
					Tags:        []string{"malicious"},
				}
			}
		}
	}

	ioc.LastUpdate = time.Now()
	return nil
}

// parseTextIOCs parses text IOCs
func (ioc *IOCDatabase) parseTextIOCs(data []byte, source string) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	ioc.mu.Lock()
	defer ioc.mu.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if net.ParseIP(line) != nil {
			ioc.IPs[line] = IOCEntry{
				Type:        "IP",
				Value:       line,
				ThreatType:  "malicious",
				Confidence:  0.8,
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Description: "Malicious IP from " + source,
				Source:      source,
				Tags:        []string{"malicious"},
			}
		}
	}

	ioc.LastUpdate = time.Now()
	return nil
}

// Utility functions
func generateConnectionID(srcIP, dstIP net.IP, srcPort, dstPort uint16) string {
	return fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
}

func generateAlertID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("alert-%d-%x", time.Now().UnixNano(), b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func isSuspiciousPort(port uint16) bool {
	suspiciousPorts := map[uint16]bool{
		4444:   true, // Metasploit
		5555:   true, // Android debug
		6666:   true, // IRC
		7777:   true, // Default malware
		8080:   true, // Proxy
		8443:   true, // HTTPS alt
		31337:  true, // Elite/BackOrifice
		3389:   true, // RDP
		5900:   true, // VNC
		22:     true, // SSH (often targeted)
		23:     true, // Telnet
		21:     true, // FTP
		25:     true, // SMTP
	}
	return suspiciousPorts[port]
}

func isExternalIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}

	for _, cidr := range privateRanges {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet.Contains(ip) {
			return false
		}
	}
	return true
}

func isEncryptedOrCompressed(data []byte) bool {
	entropy := calculateEntropyBytes(data)
	return entropy > 7.5
}

func calculateEntropyBytes(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func isRegularInterval(intervals []time.Duration, min, max time.Duration) bool {
	if len(intervals) < 3 {
		return false
	}

	var sum time.Duration
	for _, i := range intervals {
		sum += i
	}
	mean := sum / time.Duration(len(intervals))

	var variance float64
	for _, i := range intervals {
		diff := float64(i - mean)
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	stdDev := math.Sqrt(variance)
	return stdDev < float64(mean)*0.2 && mean >= min && mean <= max
}

func getPortList(portScans map[uint16]time.Time) []uint16 {
	ports := make([]uint16, 0, len(portScans))
	for port := range portScans {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

func isSuspiciousURI(uri string) bool {
	suspiciousPatterns := []string{
		"/etc/passwd",
		"/bin/bash",
		"cmd.exe",
		"powershell",
		"..",
		".git/config",
		".env",
		"phpinfo",
		"wp-admin",
		"admin",
		"config",
		"backup",
		"sql",
		"database",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(uri), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func containsExploitPatterns(uri string) bool {
	exploitPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)union.*select`),
		regexp.MustCompile(`(?i)<script.*>`),
		regexp.MustCompile(`(?i)\.\./\.\./`),
		regexp.MustCompile(`(?i)exec\(`),
		regexp.MustCompile(`(?i)eval\(`),
		regexp.MustCompile(`(?i)\.\.\\\.\.`),
		regexp.MustCompile(`(?i)%00`),
		regexp.MustCompile(`(?i)\.\.%00`),
	}

	for _, pattern := range exploitPatterns {
		if pattern.MatchString(uri) {
			return true
		}
	}
	return false
}

func extractSNI(payload []byte) string {
	sniMarker := []byte{0x00, 0x00}
	sniIndex := bytes.Index(payload, sniMarker)
	if sniIndex != -1 && sniIndex+4 < len(payload) {
		length := int(payload[sniIndex+2])<<8 | int(payload[sniIndex+3])
		if sniIndex+4+length <= len(payload) {
			return string(payload[sniIndex+4 : sniIndex+4+length])
		}
	}
	return ""
}

func isDGADomain(domain string) bool {
	entropy := calculateEntropy(domain)
	// DGA domains often have high entropy and multiple hyphens
	return entropy > 3.5 && strings.Count(domain, "-") > 2
}

func calculateEntropy(s string) float64 {
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func getAlertTimeline(alerts []*Alert) []time.Time {
	timeline := make([]time.Time, len(alerts))
	for i, alert := range alerts {
		timeline[i] = alert.Timestamp
	}
	return timeline
}

func (a *APTAnalyzer) getMitigationSteps(category string) []string {
	mitigations := map[string][]string{
		"PORT_SCAN":          {"Block source IP temporarily", "Increase monitoring on targeted ports"},
		"SYN_FLOOD":          {"Enable SYN cookies", "Rate limit connections from source"},
		"MALWARE_SIGNATURE":  {"Quarantine affected system", "Scan for malware"},
		"DATA_EXFILTRATION":  {"Block outbound connection", "Investigate source system"},
		"BEACONING":          {"Isolate system from network", "Investigate for C2 communication"},
		"IOC_MATCH":          {"Block malicious IP", "Investigate affected systems"},
		"MALICIOUS_DOMAIN":   {"Block domain", "Investigate DNS requests"},
		"DGA_DOMAIN":         {"Block domain", "Monitor for additional DGA domains"},
		"SYN_FIN_ATTACK":     {"Block source IP", "Check for other attack patterns"},
		"SUSPICIOUS_PORT":    {"Monitor connection", "Check if service should be exposed"},
		"SUSPICIOUS_URI":     {"Block request", "Investigate source IP"},
		"WEB_EXPLOIT":        {"Block source IP", "Patch vulnerable application"},
		"MULTI_STAGE_ATTACK": {"Isolate affected systems", "Conduct forensic investigation"},
	}

	if steps, exists := mitigations[category]; exists {
		return steps
	}
	return []string{"Investigate further", "Monitor system activity"}
}

func (a *APTAnalyzer) getReferences(category string) []string {
	references := map[string][]string{
		"PORT_SCAN":          {"https://nvd.nist.gov/vuln/detail/CVE-1999-0526"},
		"SYN_FLOOD":          {"https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/"},
		"MALWARE_SIGNATURE":  {"https://attack.mitre.org/techniques/T1204/"},
		"DATA_EXFILTRATION":  {"https://attack.mitre.org/techniques/T1048/"},
		"BEACONING":          {"https://attack.mitre.org/techniques/T1071/"},
		"IOC_MATCH":          {"https://attack.mitre.org/techniques/T1588/"},
		"MALICIOUS_DOMAIN":   {"https://attack.mitre.org/techniques/T1583/"},
		"DGA_DOMAIN":         {"https://attack.mitre.org/techniques/T1568/"},
		"SYN_FIN_ATTACK":     {"https://en.wikipedia.org/wiki/SYN_flood"},
		"WEB_EXPLOIT":        {"https://attack.mitre.org/techniques/T1190/"},
		"MULTI_STAGE_ATTACK": {"https://attack.mitre.org/tactics/TA0001/"},
	}

	if refs, exists := references[category]; exists {
		return refs
	}
	return []string{"https://attack.mitre.org/"}
}

func (a *APTAnalyzer) sendNotification(alert *Alert) {
	if a.config.NotificationWebhook == "" {
		return
	}

	notification := map[string]interface{}{
		"alert": alert,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	data, err := json.Marshal(notification)
	if err != nil {
		a.logger.Error("Failed to marshal notification", zap.Error(err))
		return
	}

	resp, err := http.Post(a.config.NotificationWebhook, "application/json", bytes.NewReader(data))
	if err != nil {
		a.logger.Error("Failed to send notification", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.logger.Error("Notification webhook returned error", zap.Int("status", resp.StatusCode))
	}
}

func (a *APTAnalyzer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		a.logger.Error("Failed to upgrade WebSocket", zap.Error(err))
		return
	}
	defer conn.Close()

	// Send alerts in real-time
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			alerts := a.alerts.GetRecentAlerts(10)
			if len(alerts) > 0 {
				if err := conn.WriteJSON(alerts); err != nil {
					a.logger.Error("Failed to send WebSocket message", zap.Error(err))
					return
				}
			}
		case <-a.shutdown:
			return
		}
	}
}

func (a *APTAnalyzer) handleAlertsAPI(w http.ResponseWriter, r *http.Request) {
	alerts := a.alerts.GetRecentAlerts(100)
	json.NewEncoder(w).Encode(alerts)
}

func (a *APTAnalyzer) handleConnectionsAPI(w http.ResponseWriter, r *http.Request) {
	connections := a.connections.GetAll()
	json.NewEncoder(w).Encode(connections)
}

func (a *APTAnalyzer) handleStatisticsAPI(w http.ResponseWriter, r *http.Request) {
	a.stats.mu.RLock()
	defer a.stats.mu.RUnlock()
	json.NewEncoder(w).Encode(a.stats)
}

func (a *APTAnalyzer) handleIOCsAPI(w http.ResponseWriter, r *http.Request) {
	iocCount := map[string]int{
		"ips":     len(a.iocDB.IPs),
		"domains": len(a.iocDB.Domains),
		"urls":    len(a.iocDB.URLs),
		"hashes":  len(a.iocDB.Hashes),
	}
	json.NewEncoder(w).Encode(iocCount)
}

func (a *APTAnalyzer) handleGeoAPI(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{"enabled": a.config.GeoIPEnabled})
}

func (a *APTAnalyzer) saveState() {
	statePath := filepath.Join(a.config.StoragePath, "state.json")
	state := map[string]interface{}{
		"last_update": time.Now(),
		"ioc_count":   a.iocDB.Count(),
		"stats":       a.stats,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		a.logger.Error("Failed to marshal state", zap.Error(err))
		return
	}

	if err := os.WriteFile(statePath, data, 0644); err != nil {
		a.logger.Error("Failed to save state", zap.Error(err))
	}
}

func (a *APTAnalyzer) saveAlerts(alerts []*Alert) {
	if len(alerts) == 0 {
		return
	}

	date := time.Now().Format("2006-01-02")
	alertDir := filepath.Join(a.config.StoragePath, "alerts")
	if err := os.MkdirAll(alertDir, 0755); err != nil {
		a.logger.Error("Failed to create alerts directory", zap.Error(err))
		return
	}

	alertFile := filepath.Join(alertDir, fmt.Sprintf("alerts-%s.json", date))

	var existingAlerts []*Alert
	if data, err := os.ReadFile(alertFile); err == nil {
		json.Unmarshal(data, &existingAlerts)
	}

	allAlerts := append(existingAlerts, alerts...)
	data, err := json.MarshalIndent(allAlerts, "", "  ")
	if err != nil {
		a.logger.Error("Failed to marshal alerts", zap.Error(err))
		return
	}

	if err := os.WriteFile(alertFile, data, 0644); err != nil {
		a.logger.Error("Failed to save alerts", zap.Error(err))
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return getDefaultConfig(), nil
		}
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func getDefaultConfig() *Config {
	return &Config{
		Interfaces:        []string{"any"},
		PrometheusEnabled: true,
		WebUIEnabled:      true,
		AlertThresholds: AlertConfig{
			PortScanThreshold:    50,
			SynFloodThreshold:    1000,
			BeaconIntervalMin:    time.Second * 30,
			BeaconIntervalMax:    time.Minute * 5,
			DataExfilThreshold:   100 * 1024 * 1024, // 100MB
			ConnectionRateLimit:  100,
			MaliciousIPThreshold: 5,
		},
		IOCSources: []string{
			"https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
			"https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
		},
		GeoIPEnabled:       true,
		StoragePath:        "/var/lib/apt-analyzer",
		RetentionDays:      30,
		CaptureFilter:      "tcp",
		MaxPacketRate:      10000,
		LogLevel:           "info",
		NotificationWebhook: "",
	}
}

func dumpDefaultConfig() {
	config := getDefaultConfig()
	data, err := yaml.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
}

func printUsage() {
	fmt.Println(`APT TCP Analyzer - Advanced Persistent Threat Detection

Usage:
  apt-analyzer [flags]

Flags:
  --config string      Path to configuration file (default "/etc/apt-analyzer/config.yaml")
  --interface string   Network interface to capture (default "any")
  --debug              Enable debug mode
  --dump-config        Dump default configuration and exit
  --help               Show help

Features:
  • Real-time TCP traffic analysis
  • IOC (Indicators of Compromise) matching
  • Behavioral analysis (beaconing, port scanning, data exfiltration)
  • GeoIP integration
  • HTTP/TLS inspection
  • Web UI dashboard
  • Prometheus metrics
  • Alert correlation
  • Persistence and reporting

Examples:
  # Run with default configuration
  apt-analyzer

  # Run on specific interface
  apt-analyzer --interface eth0

  # Debug mode
  apt-analyzer --debug

  # Custom configuration
  apt-analyzer --config /path/to/config.yaml
`)
}
