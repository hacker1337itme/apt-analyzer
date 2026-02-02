# apt-analyzer
apt-analyzer

  # USAGE
  
    Real-time Packet Analysis: Uses gopacket for efficient packet capture and analysis

    IOC Integration: Real-time threat intelligence feeds

   # Behavioral Detection:

        Port scanning detection

        Beaconing analysis

        Data exfiltration detection

        SYN flood detection

   # Protocol Analysis:

        HTTP request/response parsing

        TLS handshake analysis

        Protocol anomaly detection

   1 GeoIP Integration: Geographical threat analysis

   2 Web UI: Real-time dashboard with charts and alerts

   3 Prometheus Metrics: Comprehensive monitoring metrics

   4 Alert Correlation: Multi-stage attack detection

   5 Persistence: Alert storage and reporting

   6 Scalable Architecture: Goroutine-based concurrent processing

The Complete configuration file for the APT TCP Analyzer:

```yaml
# APT TCP Analyzer Configuration
# Version: 2.0.0

# Network interfaces to monitor
# Use "any" to capture on all interfaces
interfaces:
  - "eth0"
  - "any"

# Enable Prometheus metrics endpoint on port 9090
prometheus_enabled: true

# Enable Web UI on port 8080
webui_enabled: true

# Alert thresholds configuration
alert_thresholds:
  # Number of unique ports scanned within 1 minute to trigger port scan alert
  port_scan_threshold: 50
  
  # Number of SYN packets per second to trigger SYN flood alert
  syn_flood_threshold: 1000
  
  # Minimum interval between connections to be considered beaconing (seconds)
  beacon_interval_min: 30s
  
  # Maximum interval between connections to be considered beaconing (seconds)
  beacon_interval_max: 5m
  
  # Amount of data sent to external IP to trigger data exfiltration alert (bytes)
  data_exfil_threshold: 104857600  # 100MB
  
  # Maximum connections per second from a single source IP
  connection_rate_limit: 100
  
  # Number of alerts from same IP to consider it malicious
  malicious_ip_threshold: 5

# IOC (Indicators of Compromise) sources
# The analyzer will periodically fetch IOCs from these sources
ioc_sources:
  - "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  - "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
  - "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
  - "https://reputation.alienvault.com/reputation.data"
  - "https://www.binarydefense.com/banlist.txt"

# Enable GeoIP lookups for source IPs
geoip_enabled: true

# Path for storing application data (alerts, logs, state)
storage_path: "/var/lib/apt-analyzer"

# Number of days to retain alerts and logs
retention_days: 30

# Whitelisted IPs/CIDRs (no alerts will be generated for these)
whitelist:
  - "192.168.1.0/24"
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "127.0.0.0/8"
  - "::1/128"

# Blacklisted IPs/CIDRs (always generate alerts for these)
blacklist: []

# BPF capture filter (see tcpdump syntax)
# Default: capture only TCP traffic
capture_filter: "tcp"

# Maximum packets per second to process (0 for unlimited)
max_packet_rate: 10000

# Log level: debug, info, warn, error
log_level: "info"

# Webhook URL for alert notifications (optional)
# Supports Slack, Discord, or custom webhooks
notification_webhook: ""
# Example Slack webhook: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
# Example Discord webhook: "https://discord.com/api/webhooks/000000000000000000/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Advanced settings (optional)

# Suspicious ports to monitor
suspicious_ports:
  - 4444    # Metasploit
  - 5555    # Android debug
  - 6666    # IRC
  - 7777    # Default malware
  - 8080    # HTTP proxy
  - 8443    # HTTPS alt
  - 31337   # Elite/BackOrifice
  - 3389    # RDP
  - 5900    # VNC
  - 22      # SSH
  - 23      # Telnet
  - 21      # FTP
  - 25      # SMTP
  - 1433    # MSSQL
  - 3306    # MySQL
  - 5432    # PostgreSQL
  - 27017   # MongoDB

# High-risk countries for threat scoring
high_risk_countries:
  - "Russia"
  - "China"
  - "North Korea"
  - "Iran"
  - "Syria"
  - "Cuba"
  - "Sudan"

# Malware signature patterns to detect in payloads
malware_signatures:
  - "eval(base64_decode("
  - "powershell -e "
  - "cmd.exe /c "
  - "<script>alert(1)</script>"
  - "../../../../etc/passwd"
  - "union select"
  - "exec("
  - "system("
  - "wget http"
  - "curl http"

# Suspicious URI patterns
suspicious_uri_patterns:
  - "/etc/passwd"
  - "/bin/bash"
  - ".git/config"
  - ".env"
  - "phpinfo"
  - "wp-admin"
  - "admin"
  - "config"
  - "backup"
  - "sql"
  - "database"
  - "login"
  - "password"
  - "credential"

# Alert severity mapping
alert_severity:
  CRITICAL:
    - "MALWARE_SIGNATURE"
    - "SYN_FLOOD"
    - "DATA_EXFILTRATION"
  HIGH:
    - "PORT_SCAN"
    - "BEACONING"
    - "IOC_MATCH"
    - "MALICIOUS_DOMAIN"
    - "DGA_DOMAIN"
    - "MULTI_STAGE_ATTACK"
  MEDIUM:
    - "SUSPICIOUS_PORT"
    - "SUSPICIOUS_URI"
    - "WEB_EXPLOIT"
    - "SYN_FIN_ATTACK"
  LOW:
    - "HTTP_ERROR"
    - "UNUSUAL_PROTOCOL"

# Email notification settings (optional)
email_notifications:
  enabled: false
  smtp_server: "smtp.gmail.com:587"
  smtp_username: ""
  smtp_password: ""
  from_address: "apt-analyzer@example.com"
  to_addresses:
    - "admin@example.com"
    - "security@example.com"
  tls_enabled: true

# Database settings (optional - for storing alerts in SQL database)
database:
  enabled: false
  type: "sqlite"  # sqlite, mysql, postgres
  connection_string: "/var/lib/apt-analyzer/alerts.db"  # For sqlite
  # connection_string: "user:password@tcp(localhost:3306)/apt_analyzer"  # For mysql
  # connection_string: "host=localhost user=postgres password=secret dbname=apt_analyzer port=5432 sslmode=disable"  # For postgres

# Scheduled reporting
reports:
  daily_enabled: true
  daily_time: "08:00"
  weekly_enabled: true
  weekly_day: "Monday"
  weekly_time: "09:00"
  monthly_enabled: true
  monthly_day: 1
  monthly_time: "10:00"

# Auto-blocking settings (requires iptables/nftables)
auto_blocking:
  enabled: false
  duration: "24h"  # Duration to block IPs
  threshold: 3     # Number of high/critical alerts before blocking
  firewall_backend: "iptables"  # iptables or nftables

# Performance tuning
performance:
  connection_timeout: "5m"      # Time to keep inactive connections in memory
  max_connections: 100000       # Maximum connections to track
  alert_window_size: 1000       # Number of alerts to keep in memory for correlation
  worker_pool_size: 4           # Number of packet processing workers

# Debug settings (for troubleshooting)
debug:
  log_packets: false           # Log every packet (warning: very verbose)
  log_payloads: false          # Log packet payloads
  save_malicious_packets: true # Save packets that triggered alerts
  packet_save_path: "/var/lib/apt-analyzer/packets"
```

## Installation instructions:

1. **Save the configuration file:**
```bash
sudo mkdir -p /etc/apt-analyzer
sudo nano /etc/apt-analyzer/config.yaml
# Paste the configuration above and adjust as needed
```

2. **Create required directories:**
```bash
sudo mkdir -p /var/lib/apt-analyzer/{alerts,logs,packets,state}
sudo mkdir -p /var/log/apt-analyzer
```

3. **Install GeoIP database (optional):**
```bash
# On Ubuntu/Debian:
sudo apt-get update
sudo apt-get install geoip-database

# On CentOS/RHEL:
sudo yum install geoip

# Or download manually:
sudo mkdir -p /usr/share/GeoIP
sudo wget -O /usr/share/GeoIP/GeoLite2-Country.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb
```

4. **Create systemd service file:**
```bash
sudo nano /etc/systemd/system/apt-analyzer.service
```

```ini
[Unit]
Description=APT TCP Analyzer
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/apt-analyzer --config /etc/apt-analyzer/config.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=apt-analyzer

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/apt-analyzer /var/log/apt-analyzer
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

5. **Enable and start the service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable apt-analyzer
sudo systemctl start apt-analyzer
sudo systemctl status apt-analyzer
```

6. **Check logs:**
```bash
sudo journalctl -u apt-analyzer -f
```

## Web UI Setup:

If you enabled the Web UI, you'll need to create the web interface files:

1. **Create web UI directory:**
```bash
sudo mkdir -p /var/www/apt-analyzer
```

2. **Create a basic HTML interface:**
```bash
sudo nano /var/www/apt-analyzer/index.html
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APT TCP Analyzer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #007bff;
            padding-bottom: 10px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        .stat-label {
            font-size: 14px;
            color: #666;
        }
        .alert-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .alert-table th, .alert-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .alert-table th {
            background-color: #f2f2f2;
        }
        .severity-high {
            color: #dc3545;
            font-weight: bold;
        }
        .severity-medium {
            color: #ffc107;
            font-weight: bold;
        }
        .severity-low {
            color: #28a745;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>APT TCP Analyzer Dashboard</h1>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="packets-processed">0</div>
                <div class="stat-label">Packets Processed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="alerts-generated">0</div>
                <div class="stat-label">Alerts Generated</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="connections-tracked">0</div>
                <div class="stat-label">Connections Tracked</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="uptime">0s</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>
        
        <h2>Recent Alerts</h2>
        <table class="alert-table" id="alerts-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Source IP</th>
                    <th>Destination</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody id="alerts-body">
                <!-- Alerts will be populated here -->
            </tbody>
        </table>
    </div>
    
    <script>
        // WebSocket connection for real-time updates
        const ws = new WebSocket(`ws://${window.location.host}/ws`);
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            updateDashboard(data);
        };
        
        ws.onopen = function() {
            console.log('WebSocket connected');
            // Fetch initial data
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => updateDashboard(data));
            fetch('/api/statistics')
                .then(response => response.json())
                .then(data => updateStats(data));
        };
        
        function updateDashboard(alerts) {
            const tableBody = document.getElementById('alerts-body');
            tableBody.innerHTML = '';
            
            alerts.forEach(alert => {
                const row = document.createElement('tr');
                
                const severityClass = `severity-${alert.Severity.toLowerCase()}`;
                
                row.innerHTML = `
                    <td>${new Date(alert.Timestamp).toLocaleString()}</td>
                    <td><span class="${severityClass}">${alert.Severity}</span></td>
                    <td>${alert.Category}</td>
                    <td>${alert.SourceIP}</td>
                    <td>${alert.DestIP}:${alert.DestPort}</td>
                    <td>${alert.Description}</td>
                `;
                
                tableBody.appendChild(row);
            });
        }
        
        function updateStats(stats) {
            document.getElementById('packets-processed').textContent = stats.PacketsProcessed.toLocaleString();
            document.getElementById('alerts-generated').textContent = stats.AlertsGenerated.toLocaleString();
            document.getElementById('connections-tracked').textContent = stats.ConnectionsTracked.toLocaleString();
            
            // Calculate uptime
            const uptime = Math.floor((Date.now() - new Date(stats.StartTime).getTime()) / 1000);
            document.getElementById('uptime').textContent = formatUptime(uptime);
        }
        
        function formatUptime(seconds) {
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;
            
            if (days > 0) return `${days}d ${hours}h`;
            if (hours > 0) return `${hours}h ${minutes}m`;
            if (minutes > 0) return `${minutes}m ${secs}s`;
            return `${secs}s`;
        }
        
        // Auto-refresh statistics every 30 seconds
        setInterval(() => {
            fetch('/api/statistics')
                .then(response => response.json())
                .then(data => updateStats(data));
        }, 30000);
    </script>
</body>
</html>
```

## Usage examples:

1. **Run with custom interface:**
```bash
sudo ./apt-analyzer --interface eth0 --debug
```

2. **Check Prometheus metrics:**
```bash
curl http://localhost:9090/metrics
```

3. **Access Web UI:**
Open browser to `http://localhost:8080`

4. **View API endpoints:**
- `http://localhost:8080/api/alerts` - Recent alerts (JSON)
- `http://localhost:8080/api/connections` - Active connections (JSON)
- `http://localhost:8080/api/statistics` - Runtime statistics (JSON)
- `http://localhost:8080/api/iocs` - IOC database stats (JSON)

## Troubleshooting:

1. **Permission errors:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/apt-analyzer
```

2. **Missing dependencies:**
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

3. **Check if interface exists:**
```bash
ip link show
```

4. **Test packet capture:**
```bash
sudo tcpdump -i eth0 -c 10
```

This configuration provides a comprehensive setup for monitoring network traffic for APT indicators with real-time alerts, web interface, and Prometheus metrics.
