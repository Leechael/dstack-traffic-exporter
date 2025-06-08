# Traffic Exporter

Comprehensive network traffic monitoring solution that combines HAProxy SNI log analysis with QEMU virtual machine network monitoring.

## Features

### HAProxy SNI Monitoring
- Monitors HAProxy log files for SNI-based traffic statistics
- Real-time log file tailing with position tracking
- Exports Prometheus metrics for SNI traffic

### QEMU Process Monitoring
- Automatically discovers QEMU virtual machine processes
- Monitors network traffic using `/proc/{pid}/net/dev`
- Exports time-windowed traffic statistics (30s, 1min, 5min, 15min, 1h)
- Uses UUID extraction from QEMU command lines as labels

## Quick Start

### 1. Build the Exporter
```bash
go build -o traffic-exporter .

# Or build for Linux
make linux
```

### 2. Basic Usage (Default)
```bash
# Monitors both HAProxy logs and QEMU processes
./traffic-exporter
```

### 3. Custom Configuration
```bash
# Custom log file and monitoring interval
./traffic-exporter -log=/var/log/haproxy.log -qemu-monitor-interval=10s
```

### 4. Custom Port
```bash
# Use different Prometheus port
./traffic-exporter -port=9200
```

## Command Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-log` | `/var/log/haproxy.log` | HAProxy log file to monitor |
| `-pos` | `.traffic-exporter.pos` | Position file for log tracking |
| `-port` | `9100` | Prometheus metrics port |
| `-reset` | `false` | Reset position and start from beginning |
| `-qemu-monitor-interval` | `5s` | QEMU monitoring interval |

## Default Behavior

The exporter automatically enables both monitoring features:

1. **HAProxy Log Monitoring**: Continuously tails the specified log file
2. **QEMU Process Monitoring**: Discovers and monitors all QEMU processes
3. **Metrics Export**: Provides Prometheus metrics on the specified port

If HAProxy log file is not available, the exporter continues with QEMU monitoring only.

## Exported Metrics

### HAProxy SNI Metrics
- `haproxy_sni_total_bytes{sni}` - Total bytes per SNI
- `haproxy_sni_connections{sni}` - Total connections per SNI  
- `haproxy_sni_zero_bytes{sni}` - Zero byte connections per SNI

### QEMU Network Metrics

The following Prometheus metrics are exported for each QEMU process:

- `qemu_network_total_bytes{uuid,direction}` - Cumulative bytes transferred since process start
- `qemu_network_30s_bytes{uuid,direction}` - Bytes transferred in the last 30 seconds
- `qemu_network_1min_bytes{uuid,direction}` - Bytes transferred in the last 1 minute
- `qemu_network_5min_bytes{uuid,direction}` - Bytes transferred in the last 5 minutes
- `qemu_network_15min_bytes{uuid,direction}` - Bytes transferred in the last 15 minutes
- `qemu_network_1h_bytes{uuid,direction}` - Bytes transferred in the last 1 hour

Where:
- `uuid`: Extracted from QEMU command line (e.g., from `run/vm/{UUID}/` or `guest-cid={CID}`)
- `direction`: Either `rx` (received) or `tx` (transmitted)

## UUID Extraction Patterns

The exporter automatically extracts UUIDs from QEMU command lines using these patterns:

1. **Path-based**: `run/vm/{UUID}/`
   - Example: `run/vm/abc123-def456/` → `abc123-def456`

2. **CID-based**: `guest-cid={number}`
   - Example: `guest-cid=1001` → `CID-1001`

## HTTP Endpoints

- **GET `/metrics`** - Prometheus metrics endpoint
- **POST `/reset`** - Reset all statistics (both HAProxy SNI and QEMU metrics)

## Usage Examples

### Example 1: Default Usage
```bash
# Start with all default settings
./traffic-exporter

# Check metrics
curl http://localhost:9100/metrics
```

### Example 2: Custom Configuration
```bash
# Custom log file and faster QEMU monitoring
./traffic-exporter \
  -log=/var/log/haproxy.log \
  -qemu-monitor-interval=3s
```

### Example 3: Production Setup
```bash
# Production configuration
./traffic-exporter \
  -log=/var/log/haproxy.log \
  -qemu-monitor-interval=30s \
  -port=9200 \
  -pos=/var/lib/traffic-exporter/position
```

### Example 4: Reset and Restart
```bash
# Start from beginning of log file
./traffic-exporter -reset
```

## Sample Metrics Output

```
# HAProxy SNI metrics
haproxy_sni_total_bytes{sni="example.com"} 1048576
haproxy_sni_connections{sni="example.com"} 42
haproxy_sni_zero_bytes{sni="example.com"} 2

# QEMU network metrics
qemu_network_total_bytes{uuid="vm-12345",direction="rx"} 2097152
qemu_network_total_bytes{uuid="vm-12345",direction="tx"} 1048576
qemu_network_30s_bytes{uuid="vm-12345",direction="rx"} 8192
qemu_network_30s_bytes{uuid="vm-12345",direction="tx"} 4096
qemu_network_1min_bytes{uuid="vm-12345",direction="rx"} 16384
qemu_network_1min_bytes{uuid="vm-12345",direction="tx"} 8192
```

## Testing

Run the included test script to verify functionality:

```bash
./test_qemu_monitoring.sh
```

This script will:
- Start the exporter with default settings
- Check for running QEMU processes
- Display sample metrics
- Demonstrate the reset functionality

## System Requirements

- Linux system with `/proc` filesystem
- Go 1.16+ for building
- Appropriate permissions to read `/proc/{pid}/` directories
- QEMU processes with identifiable UUID patterns
- HAProxy log files (optional, exporter continues without them)

## How It Works

### HAProxy SNI Monitoring
1. Tails the specified HAProxy log file
2. Parses log lines to extract SNI and byte count information
3. Maintains position tracking for reliability
4. Updates Prometheus metrics in real-time

### QEMU Process Monitoring
1. Scans `/proc` for all process directories
2. Reads `/proc/{pid}/cmdline` to identify QEMU processes
3. Extracts UUIDs using regex patterns
4. Reads network stats from `/proc/{pid}/net/dev`
5. Maintains time-windowed statistics using snapshots

## Memory Management

The exporter includes automatic memory management:
- Removes statistics for terminated QEMU processes
- Cleans snapshots older than 1 hour to prevent memory growth
- Efficient data structures for long-running monitoring

## Prometheus Integration

Configure Prometheus to scrape the exporter:

```yaml
scrape_configs:
  - job_name: 'traffic-exporter'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 30s
```

## Grafana Dashboard

Create dashboards using the exported metrics:

```promql
# QEMU network traffic rate (bytes/sec)
rate(qemu_network_total_bytes[5m])

# Top 10 VMs by traffic
topk(10, sum(rate(qemu_network_total_bytes[5m])) by (uuid))

# HAProxy SNI traffic rate
rate(haproxy_sni_total_bytes[5m])

# Top SNIs by connection count
topk(10, haproxy_sni_connections)
```

## Architecture

The exporter consists of several independent components:

- **HAProxy Log Tailer**: Monitors log files using the `tail` library
- **QEMU Process Scanner**: Periodically discovers QEMU processes
- **Network Stats Collector**: Reads `/proc/{pid}/net/dev` for each process
- **Metrics Updater**: Periodically updates Prometheus metrics
- **HTTP Server**: Serves metrics and provides reset endpoint

All components run concurrently and are designed to be robust and fault-tolerant.

## Troubleshooting

### No QEMU processes found
- Verify QEMU processes are running: `ps aux | grep qemu-system`
- Check UUID extraction patterns in command lines
- Ensure proper permissions to read `/proc`

### HAProxy log file issues
- Check if the log file exists and is readable
- Verify correct log file path
- Check file permissions

### Metrics not updating
- Check the monitoring interval setting
- Verify network activity on QEMU processes
- Check logs for error messages

### Permission errors
- Ensure the exporter has permission to read `/proc/{pid}/` directories
- Consider running with appropriate user privileges

### High memory usage
- Check if QEMU processes are being properly cleaned up
- Verify snapshot cleanup is working (logs should show cleanup activity)
- Consider reducing monitoring interval for very active systems

## Building and Deployment

### Local Development
```bash
# Build for current platform
go build -o traffic-exporter .

# Run tests
go test ./...

# Run with debug logging
./traffic-exporter -log=/dev/null  # Skip HAProxy, QEMU only
```

### Production Deployment
```bash
# Build optimized binary
make linux

# Deploy binary
scp traffic-exporter-linux-amd64 user@server:/usr/local/bin/traffic-exporter

# Create systemd service (optional)
sudo systemctl enable traffic-exporter
sudo systemctl start traffic-exporter
```

### Docker Deployment
```dockerfile
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY traffic-exporter-linux-amd64 /usr/local/bin/traffic-exporter
EXPOSE 9100
CMD ["/usr/local/bin/traffic-exporter"]
```

## License

This project is open source. Please refer to the LICENSE file for details. 