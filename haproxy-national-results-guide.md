# HAProxy National Results Configuration Guide for Examinations

## Introduction

This guide provides instructions for setting up HAProxy to handle national examination results traffic. HAProxy is a reliable, high-performance TCP/HTTP load balancer that can help manage the significant traffic spikes during examination result announcements in Sudan.

## Server Preparation on Rocky Linux 9 VM

### 1. VM Requirements

For a production HAProxy server handling national examination results, configure your VM with:

- **CPU**: Minimum 4 vCPUs (8+ recommended for high traffic)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 50GB SSD-backed storage
- **Network**: Multiple network interfaces with at least 1Gbps throughput

#### Validation:
```bash
# Check CPU resources
lscpu

# Check memory
free -h

# Check storage
df -h

# Check network interfaces
ip a
```

### 2. Base System Setup

```bash
# Log in as root or a user with sudo privileges

# Update the system
sudo dnf update -y

# Install necessary tools
sudo dnf install -y vim wget curl tar zip unzip net-tools telnet chrony socat

# Configure timezone for Sudan
sudo timedatectl set-timezone Africa/Khartoum

# Enable and start chronyd for time synchronization
sudo systemctl enable --now chronyd
```

#### Validation:
```bash
# Verify timezone is set to Sudan
timedatectl

# Check chrony status and synchronization
chronyc tracking
chronyc sources

# Verify installed packages
rpm -qa | grep -E 'vim|wget|curl|net-tools|telnet|chrony|socat'
```

### 3. Network Configuration

```bash
# Configure network interfaces
sudo nmcli connection modify ens192 ipv4.addresses 196.192.113.X/26
sudo nmcli connection modify ens192 ipv4.gateway 196.192.113.Y
sudo nmcli connection modify ens192 ipv4.dns "8.8.8.8,8.8.4.4"
sudo nmcli connection modify ens192 ipv4.method manual
sudo nmcli connection down ens192 && sudo nmcli connection up ens192

# Configure hostname
sudo hostnamectl set-hostname haproxy-results.example.gov.sd

# Add hostname to /etc/hosts
echo "196.192.113.X haproxy-results.example.gov.sd haproxy-results" | sudo tee -a /etc/hosts
```

#### Validation:
```bash
# Verify network configuration
ip addr show
ip route

# Test connectivity
ping -c 4 8.8.8.8
ping -c 4 google.com

# Verify hostname configuration
hostname
hostname -f
cat /etc/hosts
```

### 4. Security Configuration

```bash
# Update firewall configuration
sudo dnf install -y firewalld
sudo systemctl enable --now firewalld

# Configure firewall for HAProxy
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=8404/tcp  # HAProxy stats
sudo firewall-cmd --reload

# Set up SELinux
sudo dnf install -y policycoreutils-python-utils
sudo setsebool -P haproxy_connect_any 1
```

#### Validation:
```bash
# Verify firewall rules
sudo firewall-cmd --list-all

# Check SELinux status
sestatus

# Verify SELinux boolean for HAProxy
getsebool -a | grep haproxy_connect
```

### 5. Install HAProxy

```bash
# Install EPEL repository
sudo dnf install -y epel-release

# Install HAProxy 2.4+ from EPEL
sudo dnf install -y haproxy

# Check HAProxy version
haproxy -v
```

#### Validation:
```bash
# Verify HAProxy installation
rpm -q haproxy

# Check HAProxy version (should be 2.4+)
haproxy -v

# Check installed files and directories
rpm -ql haproxy
```

### 6. System Tuning for HAProxy

```bash
# Create sysctl configuration for HAProxy
cat <<EOF | sudo tee /etc/sysctl.d/haproxy.conf
# Maximum number of open files/file descriptors
fs.file-max = 200000

# Maximum read buffer
net.core.rmem_max = 16777216

# Maximum write buffer
net.core.wmem_max = 16777216

# Maximum number of incoming connections
net.core.somaxconn = 65535

# Maximum backlog connections
net.core.netdev_max_backlog = 30000

# TCP time-wait buckets pool size
net.ipv4.tcp_max_tw_buckets = 2000000

# Fast recycling of TIME_WAIT sockets
net.ipv4.tcp_tw_recycle = 1

# Allow reusing sockets in TIME_WAIT state
net.ipv4.tcp_tw_reuse = 1
EOF

# Apply sysctl settings
sudo sysctl -p /etc/sysctl.d/haproxy.conf

# Configure user limits for haproxy user
cat <<EOF | sudo tee /etc/security/limits.d/haproxy.conf
haproxy soft nofile 200000
haproxy hard nofile 200000
EOF
```

#### Validation:
```bash
# Verify sysctl parameters
sysctl fs.file-max
sysctl net.core.somaxconn
sysctl net.ipv4.tcp_tw_reuse

# Check user limits for haproxy user
grep haproxy /etc/security/limits.d/haproxy.conf
```

### 7. Create Directory Structure for Modular Configuration

```bash
# Create the haproxy.d directory for modular configuration files
sudo mkdir -p /etc/haproxy/haproxy.d

# Create directories for custom error pages
sudo mkdir -p /etc/haproxy/errors/

# Create directory for HAProxy socket
sudo mkdir -p /run/haproxy/
sudo chown haproxy:haproxy /run/haproxy/

# Create directory for Let's Encrypt certificates
sudo mkdir -p /etc/letsencrypt/live/results.example.gov.sd/
```

#### Validation:
```bash
# Verify directory structure
ls -la /etc/haproxy/
ls -la /etc/haproxy/haproxy.d/
ls -la /run/haproxy/
ls -la /etc/letsencrypt/

# Verify directory permissions
namei -l /run/haproxy/
```

### 8. Install and Configure Certbot for Let's Encrypt

```bash
# Install certbot
sudo dnf install -y certbot

# Install domain validation plugin (choose one based on your setup)
# For HTTP validation:
sudo dnf install -y python3-certbot-apache

# Or for DNS validation (if you control the domain's DNS):
sudo dnf install -y python3-certbot-dns-cloudflare
# or another DNS provider plugin as needed

# Obtain certificate using HTTP validation
sudo certbot certonly --standalone --preferred-challenges http \
  -d results.example.gov.sd \
  --email admin@example.gov.sd \
  --agree-tos

# Set up automatic renewal
echo "0 0,12 * * * root python -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew --quiet --post-hook 'systemctl reload haproxy'" | sudo tee -a /etc/crontab

# Create a script to combine certificates for HAProxy
cat <<'EOF' | sudo tee /usr/local/bin/update-haproxy-certs.sh
#!/bin/bash
DOMAIN="results.example.gov.sd"
LETSENCRYPT_DIR="/etc/letsencrypt/live/$DOMAIN"
HAPROXY_CERT_DIR="/etc/haproxy/certs"

mkdir -p $HAPROXY_CERT_DIR

cat $LETSENCRYPT_DIR/fullchain.pem $LETSENCRYPT_DIR/privkey.pem > $HAPROXY_CERT_DIR/$DOMAIN.pem
chmod 600 $HAPROXY_CERT_DIR/$DOMAIN.pem

systemctl reload haproxy
EOF

# Make the script executable
sudo chmod +x /usr/local/bin/update-haproxy-certs.sh

# Run it once to create the initial certificate
sudo mkdir -p /etc/haproxy/certs
sudo /usr/local/bin/update-haproxy-certs.sh

# Add to certbot renewal hooks
sudo mkdir -p /etc/letsencrypt/renewal-hooks/post
sudo ln -sf /usr/local/bin/update-haproxy-certs.sh /etc/letsencrypt/renewal-hooks/post/haproxy-cert-update
```

#### Validation:
```bash
# Verify certbot installation
certbot --version

# Check certificate status
certbot certificates

# Verify certificate files
ls -la /etc/letsencrypt/live/results.example.gov.sd/
ls -la /etc/haproxy/certs/

# Verify certificate validity
openssl x509 -in /etc/haproxy/certs/results.example.gov.sd.pem -text -noout | grep -E 'Not Before|Not After|Subject:'

# Check renewal configuration
grep -r certbot /etc/crontab
ls -la /etc/letsencrypt/renewal-hooks/post/
```

### 9. Create Custom Error Pages

```bash
# Create simple error pages for common HTTP errors
for code in 400 403 408 500 502 503 504; do
  echo "<html><body><h1>Error ${code}</h1><p>National Examination Results: An error occurred.</p></body></html>" | \
  sudo tee /etc/haproxy/errors/${code}.http
done
```

#### Validation:
```bash
# Verify error pages
ls -la /etc/haproxy/errors/
cat /etc/haproxy/errors/503.http
```

### 10. Setup Monitoring

```bash
# Install monitoring tools
sudo dnf install -y htop iftop iotop sysstat

# Enable system statistics collection
sudo systemctl enable --now sysstat

# Create a basic monitoring script
cat <<EOF | sudo tee /usr/local/bin/check_haproxy.sh
#!/bin/bash
echo "HAProxy Status Check: \$(date)"
echo "-------------------------"
systemctl status haproxy --no-pager
echo ""
echo "Connection Statistics:"
ss -s | grep -A 5 "TCP:"
echo ""
echo "HAProxy Process Resources:"
ps -o pid,user,%cpu,%mem,vsz,rss,stat,start,time,command -p \$(pgrep haproxy)
EOF

sudo chmod +x /usr/local/bin/check_haproxy.sh

# Add to crontab to run hourly
(crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/check_haproxy.sh >> /var/log/haproxy_status.log") | crontab -
```

#### Validation:
```bash
# Verify monitoring tools installation
rpm -qa | grep -E 'htop|iftop|iotop|sysstat'

# Check sysstat service status
systemctl status sysstat

# Test monitoring script
/usr/local/bin/check_haproxy.sh

# Verify crontab setup
crontab -l | grep check_haproxy
```

## HAProxy Modular Configuration

### 1. Configure Main HAProxy Configuration File

```bash
# Create a main HAProxy configuration file that includes files from haproxy.d directory
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.cfg
# Global settings
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    
    # Performance tuning
    maxconn 100000
    nbproc 4
    nbthread 4
    cpu-map auto:1/1-4 0-3
    tune.ssl.default-dh-param 2048
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

# Default parameters
defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

# Include configuration files from haproxy.d directory
include /etc/haproxy/haproxy.d/*.cfg
EOF
```

#### Validation:
```bash
# Check syntax of the main configuration file
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Verify file permissions
ls -la /etc/haproxy/haproxy.cfg

# Review the configuration
grep -n ^ /etc/haproxy/haproxy.cfg
```

### 2. Create Frontend Configuration

```bash
# Create the frontend configuration file
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/10-frontend.cfg
# Frontend configuration for National Examination Results
frontend national_results_frontend
    # Define listening ports - HTTP on port 80 and HTTPS on 443 with SSL certificate
    bind *:80                      # Listen on all interfaces on port 80
    bind *:443 ssl crt /etc/haproxy/certs/results.example.gov.sd.pem
                                   # Listen securely on port 443 with our SSL certificate
    
    # Force HTTPS for all traffic - Redirects any HTTP connections to HTTPS for security
    http-request redirect scheme https unless { ssl_fc }
                                   # This helps protect student data during transmission
    
    # Basic DDOS protection - Track and limit request rates per IP address
    stick-table type ip size 100k expire 30s store http_req_rate(60s)
                                   # Track up to 100,000 IPs for 30 seconds
    http-request track-sc0 src     # Associate current request with the source IP
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
                                   # Block IPs making more than 100 requests per minute
    
    # Simple path-based ACLs - Identify requests to static content
    acl path_static path_beg /static
                                   # Match URLs that begin with /static
    
    # Simple backend routing based on path
    use_backend static_backend if path_static
                                   # Route static content requests to dedicated static servers
    
    # Default backend for all other requests (dynamic content)
    default_backend results_backend
                                   # All other traffic goes to the main results servers
EOF
```

#### Validation:
```bash
# Check syntax of the frontend configuration
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Verify file permissions
ls -la /etc/haproxy/haproxy.d/10-frontend.cfg

# Review the frontend configuration
grep -n ^ /etc/haproxy/haproxy.d/10-frontend.cfg
```

### 3. Create Backend Configurations

```bash
# Create the results backend configuration for Windows webservers
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/20-results-backend.cfg
# Results backend configuration (dynamic content)
backend results_backend
    # Load balancing algorithm
    balance roundrobin             # Distribute load evenly across Windows servers
                                   # Ensures no single server gets overloaded during peak times
    
    # Health check configuration - Critical for high availability during results period
    option httpchk HEAD / HTTP/1.1\r\nHost:\ results.example.gov.sd
                                   # Check server health using HTTP HEAD request
    http-check expect status 200   # Server is considered healthy if it returns HTTP 200
    
    # Session persistence - Important for maintaining student's session state
    cookie SERVERID insert indirect nocache
                                   # Track which server a student is connected to
                                   # Prevents session loss if student checks multiple results
    
    # Connection limits and timeouts - Calibrated for Windows IIS servers
    server win-results1 win-results1.example.gov.sd:80 check cookie s1 maxconn 1500
                                   # Server 1: Max 1500 concurrent connections, enable health checks
    server win-results2 win-results2.example.gov.sd:80 check cookie s2 maxconn 1500
                                   # Server 2: Same configuration
    server win-results3 win-results3.example.gov.sd:80 check cookie s3 maxconn 1500
                                   # Server 3: Same configuration
    server win-results4 win-results4.example.gov.sd:80 check cookie s4 maxconn 1500
                                   # Server 4: Same configuration - all 4 Windows IIS servers
    
    # Windows-specific timeouts - Optimized for IIS response patterns
    timeout connect 10000          # Allow 10 seconds to establish connection
    timeout server 30000           # Allow 30 seconds for server to respond
                                   # Windows might need more time under heavy load
    
    # Compression options - Reduces bandwidth usage (important for rural areas in Sudan)
    compression algo gzip          # Use gzip compression algorithm
    compression type text/html text/plain text/css application/javascript application/json
                                   # Compress these content types
                                   # Reduces data usage for students on limited connections
    
    # ASP.NET health check - Specific to Windows IIS application
    option httpchk GET /healthcheck.aspx
                                   # Check ASP.NET application health
                                   # Ensures the application layer is working, not just IIS
EOF

# Create the static content backend configuration
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/30-static-backend.cfg
# Static content backend configuration
backend static_backend
    # Load balancing algorithm optimized for static content
    balance leastconn             # Send request to server with fewest connections
                                  # Better for static content with varying file sizes
    
    # Health check specific to static content
    option httpchk HEAD /static/healthcheck.html HTTP/1.1\r\nHost:\ results.example.gov.sd
                                  # Verify static content server is responding
    
    # Cache settings - Critical for reducing server load during peak times
    http-response set-header Cache-Control "max-age=3600"
                                  # Tell browsers to cache static content for 1 hour
                                  # Drastically reduces repeated requests for logos, CSS, etc.
    
    # Windows IIS servers for static content (using the same 4 servers)
    server win-results1 win-results1.example.gov.sd:80 check
                                  # Server 1 with health checks enabled
    server win-results2 win-results2.example.gov.sd:80 check
                                  # Server 2 with health checks enabled
    server win-results3 win-results3.example.gov.sd:80 check
                                  # Server 3 with health checks enabled
    server win-results4 win-results4.example.gov.sd:80 check
                                  # Server 4 with health checks enabled
EOF
```

#### Validation:
```bash
# Check syntax of all backend configurations
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Verify file permissions
ls -la /etc/haproxy/haproxy.d/20-results-backend.cfg
ls -la /etc/haproxy/haproxy.d/30-static-backend.cfg

# Test backend server connectivity
nc -zv win-results1.example.gov.sd 80
nc -zv win-static1.example.gov.sd 80

# Review backend configurations
grep -n ^ /etc/haproxy/haproxy.d/20-results-backend.cfg
grep -n ^ /etc/haproxy/haproxy.d/30-static-backend.cfg
```

### 4. Create Statistics Configuration

```bash
# Create the statistics configuration
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/40-stats.cfg
# HAProxy statistics configuration
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST
    stats realm HAProxy\ Statistics
    stats auth admin:StrongPassword123
EOF
```

#### Validation:
```bash
# Check syntax of the statistics configuration
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Verify file permissions
ls -la /etc/haproxy/haproxy.d/40-stats.cfg

# Review statistics configuration
grep -n ^ /etc/haproxy/haproxy.d/40-stats.cfg
```

### 5. Test and Apply Configuration

```bash
# Test the HAProxy configuration
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# If successful, enable and start HAProxy
sudo systemctl enable haproxy
sudo systemctl restart haproxy

# Verify the service is running
sudo systemctl status haproxy
```

#### Validation:
```bash
# Verify HAProxy is running
systemctl is-active haproxy

# Check for any startup errors
sudo journalctl -u haproxy -n 50

# Verify HAProxy is listening on configured ports
sudo ss -tulpn | grep haproxy

# Test the statistics page
curl -u admin:StrongPassword123 http://localhost:8404/stats

# Test the main service (will redirect to HTTPS)
curl -I http://localhost

# Check backend status using the admin socket
echo "show info" | sudo socat stdio /run/haproxy/admin.sock
echo "show stat" | sudo socat stdio /run/haproxy/admin.sock | cut -d ',' -f 1-2,18-20
```

## High Availability Configuration

For high availability, consider setting up HAProxy in an active-passive configuration using Keepalived:

```bash
# Install Keepalived
sudo dnf install -y keepalived

# Configure Keepalived on the primary HAProxy server
cat <<'EOF' | sudo tee /etc/keepalived/keepalived.conf
vrrp_script check_haproxy {
    script "pidof haproxy"
    interval 2
    weight 2
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 101
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass SecurePassword123
    }
    virtual_ipaddress {
        196.192.113.100/26
    }
    track_script {
        check_haproxy
    }
}
EOF

# Enable and start Keepalived
sudo systemctl enable keepalived
sudo systemctl start keepalived
```

#### Validation:
```bash
# Verify Keepalived installation
rpm -q keepalived

# Check Keepalived configuration syntax
sudo keepalived -t -f /etc/keepalived/keepalived.conf

# Verify Keepalived is running
systemctl status keepalived

# Check logs for any issues
sudo journalctl -u keepalived -n 50

# Check if virtual IP is assigned
ip addr show | grep 196.192.113.100
```

## Windows-Specific Backend Considerations

When using HAProxy with Windows IIS servers, consider these specific optimizations:

1. **Health Checks for Windows Servers**:
   ```bash
   # Create a simple health check file on Windows servers
   # Save this as C:\inetpub\wwwroot\healthcheck.html
   echo "<html><body>OK</body></html>" > healthcheck.html
   ```

   #### Validation:
   ```powershell
   # On Windows server, verify the health check file exists
   Test-Path C:\inetpub\wwwroot\healthcheck.html
   
   # Test the health check file is accessible via HTTP
   Invoke-WebRequest -Uri http://localhost/healthcheck.html
   ```

2. **IIS Configuration**:
   ```powershell
   # On each Windows server, run PowerShell as Administrator
   # Install IIS if not already installed
   Install-WindowsFeature -name Web-Server -IncludeManagementTools
   
   # Enable compression for better performance
   Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic
   Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionDynamic
   
   # Set appropriate application pool settings
   Import-Module WebAdministration
   Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel -value @{idleTimeout="00:00:00"}
   Set-ItemProperty IIS:\AppPools\DefaultAppPool -name recycling -value @{periodicRestart="00:00:00"}
   
   # Increase connection limits
   Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/serverRuntime" -name "uploadReadAheadSize" -value 65536
   ```

   #### Validation:
   ```powershell
   # Verify IIS installation
   Get-WindowsFeature Web-Server | Format-Table -AutoSize
   
   # Check if compression is enabled
   Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -like "IIS-Http*Compression*"} | Format-Table -AutoSize
   
   # Verify app pool settings
   Get-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel | Select-Object idleTimeout
   
   # Check connection limits
   Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/serverRuntime" -name "uploadReadAheadSize"
   
   # Test IIS is responding
   Invoke-WebRequest -Uri http://localhost/ | Select-Object StatusCode, StatusDescription
   ```

3. **Handling Windows Updates**:
   Configure your Windows servers to update during off-peak hours, and make sure at least one server remains online during updates:
   ```powershell
   # Configure automatic updates on Windows servers
   $AutoUpdateNotificationLevels = @{
       "Not configured" = 0
       "Disabled" = 1
       "Notify before download" = 2
       "Notify before installation" = 3
       "Scheduled installation" = 4
   }
   
   # Schedule updates for 2AM Sunday
   $AutoUpdateKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
   Set-ItemProperty -Path $AutoUpdateKey -Name "AUOptions" -Value $AutoUpdateNotificationLevels["Scheduled installation"]
   Set-ItemProperty -Path $AutoUpdateKey -Name "ScheduledInstallDay" -Value 0 # Sunday
   Set-ItemProperty -Path $AutoUpdateKey -Name "ScheduledInstallTime" -Value 2 # 2 AM
   ```

   #### Validation:
   ```powershell
   # Verify Windows Update settings
   Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" | Select-Object AUOptions, ScheduledInstallDay, ScheduledInstallTime
   
   # Check Windows Update service is running
   Get-Service wuauserv | Format-Table -AutoSize
   ```

## Traffic Surge Handling

During examination result announcements, implement these strategies:

1. **Queueing**: To handle traffic surges, implement a connection queue
2. **Circuit Breaking**: Implement circuit breaking to prevent cascading failures
3. **Caching**: Add a caching layer in front of HAProxy

Example queue configuration:

```bash
# Create a surge protection configuration
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/60-surge-protection.cfg
# Queue settings for traffic surges
frontend national_results_frontend
    # Increase connection limits for surge periods
    maxconn 10000
    timeout queue 60s
    
    # Circuit breaking for backend health
    default-server on-marked-down shutdown-sessions
EOF
```

#### Validation:
```bash
# Check syntax of surge protection configuration
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Verify the configuration is loaded
sudo systemctl restart haproxy
echo "show info" | sudo socat stdio /run/haproxy/admin.sock | grep maxconn

# Test maximum connection settings
echo "show stat" | sudo socat stdio /run/haproxy/admin.sock | grep national_results_frontend
```

## VM-Specific Optimization

Since HAProxy is running on a virtual machine rather than physical hardware, consider these VM-specific optimizations:

1. **Avoid Memory Overcommitment**: Ensure the VM host isn't overcommitting memory resources
2. **Reduce Context Switching**: Pin vCPUs to physical cores if possible
3. **Paravirtualized Drivers**: Use paravirtualized drivers for disk and network
4. **VM Resource Monitoring**: Monitor VM resource contention at the hypervisor level
5. **Storage Optimization**: Place HAProxy logs on a separate volume from the OS

```bash
# Create a separate volume for logs (if available)
sudo lvcreate -L 10G -n haproxy-logs vg_name
sudo mkfs.xfs /dev/vg_name/haproxy-logs
sudo mkdir -p /var/log/haproxy
echo "/dev/vg_name/haproxy-logs /var/log/haproxy xfs defaults 0 0" | sudo tee -a /etc/fstab
sudo mount -a

# Configure HAProxy logging to use the separate volume
sudo sed -i 's/log \/dev\/log local0/log \/var\/log\/haproxy\/haproxy.log local0/' /etc/haproxy/haproxy.cfg
```

#### Validation:
```bash
# Verify volume creation
sudo lvs | grep haproxy-logs

# Check mount point
df -h | grep haproxy

# Verify fstab entry
grep haproxy /etc/fstab

# Test logging to the separate volume
sudo systemctl restart rsyslog
sudo systemctl restart haproxy
ls -la /var/log/haproxy/
```

## Load Testing

Before the examination results announcement day, perform load testing to ensure the system can handle peak traffic:

```bash
# Install load testing tools
sudo dnf install -y httpd-tools

# Test with 1000 concurrent connections, 100000 total requests
ab -n 100000 -c 1000 https://results.example.gov.sd/

# Gradually increase load to find the breaking point
for i in 500 1000 2000 4000; do
  echo "Testing with $i concurrent connections"
  ab -n 10000 -c $i https://results.example.gov.sd/
  sleep 5
done
```

#### Validation:
```bash
# During load testing, monitor HAProxy stats
watch -n1 "echo 'show stat' | sudo socat stdio /run/haproxy/admin.sock | cut -d ',' -f 1-2,18-20,47-51"

# Monitor system resources
htop

# Check for error responses
tail -f /var/log/haproxy/haproxy.log | grep 503

# Monitor network connections
ss -s
```

## Troubleshooting

Common issues and solutions:

1. **503 Service Unavailable**
   - Check backend server health using `echo "show servers state" | sudo socat stdio /run/haproxy/admin.sock`
   - Review connection limits in the configuration
   - Verify server resources with `htop` and `iftop`
   - For Windows servers, verify IIS is running: `Invoke-Command -ComputerName win-results1 -ScriptBlock { Get-Service -Name W3SVC | Select-Object Status }`

2. **Slow Response Times**
   - Analyze HAProxy logs: `sudo tail -f /var/log/haproxy.log`
   - Adjust timeouts in the configuration files
   - Check Windows server performance using Performance Monitor
   - Consider scaling backend servers

3. **Certificate Issues**
   - Check certificate expiration: `certbot certificates`
   - Verify certificate installation: `openssl x509 -in /etc/haproxy/certs/results.example.gov.sd.pem -text -noout`
   - Test SSL configuration: `openssl s_client -connect results.example.gov.sd:443`

## Security Recommendations

1. Implement IP allowlisting for administrative access
2. Regular security audits
3. Keep HAProxy updated to the latest stable version
4. Use strong TLS configurations
5. Implement rate limiting and DDOS protection
6. Ensure Windows servers have current security patches

## Architecture Diagram

```
                   ┌─────────────┐
                   │ DNS Servers │
                   └──────┬──────┘
                          │
                          ▼
┌───────────┐      ┌────────────┐      ┌─────────────┐
│ Monitoring├─────►│   HAProxy  │◄─────┤ Management  │
└───────────┘      │Load Balancer│     │   Systems   │
                   └─┬─────┬─┬─┬─┘     └─────────────┘
                     │     │ │ │
           ┌─────────┘     │ │ └──────────┐
           │               │ │            │
           ▼               ▼ ▼            ▼
     ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
     │Windows 1 │    │Windows 2 │    │Windows 3 │    │Windows 4 │
     │  (IIS)   │    │  (IIS)   │    │  (IIS)   │    │  (IIS)   │
     └──────────┘    └──────────┘    └──────────┘    └──────────┘
```

## Daily Health Check Procedures

Create a daily health check script to ensure the system is running optimally:

```bash
# Create daily health check script
cat <<'EOF' | sudo tee /usr/local/bin/haproxy_health.sh
#!/bin/bash
echo "HAProxy Daily Health Check - $(date)"
echo "===================================="

# Check HAProxy service status
echo "1. HAProxy Service Status:"
systemctl is-active haproxy && echo "✓ HAProxy is running" || echo "❌ HAProxy is NOT running"

# Check certificate expiration
echo -e "\n2. SSL Certificate Status:"
CERT_FILE="/etc/haproxy/certs/results.example.gov.sd.pem"
if [ -f "$CERT_FILE" ]; then
  EXPIRY=$(openssl x509 -in $CERT_FILE -noout -enddate | cut -d= -f2)
  EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
  NOW_EPOCH=$(date +%s)
  DAYS_LEFT=$(( ($EXPIRY_EPOCH - $NOW_EPOCH) / 86400 ))
  if [ $DAYS_LEFT -lt 15 ]; then
    echo "❌ Certificate expires in $DAYS_LEFT days: $EXPIRY"
  else
    echo "✓ Certificate valid for $DAYS_LEFT more days"
  fi
else
  echo "❌ Certificate file not found"
fi

# Check backend server health
echo -e "\n3. Backend Server Health:"
echo "show servers state" | sudo socat stdio /run/haproxy/admin.sock | \
  grep -v '#' | awk '{print $3,$4,$5,$6}' | \
  while read name addr status weight; do
    if [ "$status" = "2" ]; then
      echo "✓ $name ($addr) is UP"
    else
      echo "❌ $name ($addr) is DOWN"
    fi
  done

# Check current connections
echo -e "\n4. Current Connections:"
CURR_CONN=$(echo "show info" | sudo socat stdio /run/haproxy/admin.sock | grep CurrConns | cut -d: -f2)
echo "Current connections: $CURR_CONN"

# Check system resources
echo -e "\n5. System Resources:"
echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
echo "Memory Usage: $(free -h | grep Mem | awk '{print "Used: "$3"/"$2" ("int($3/$2*100)"%)"}')"
echo "Disk Usage: $(df -h / | tail -1 | awk '{print $5" used, "$4" free"}')"

echo -e "\nHealth check completed at $(date)"
EOF

# Make script executable
sudo chmod +x /usr/local/bin/haproxy_health.sh

# Add daily cron job
echo "0 7 * * * root /usr/local/bin/haproxy_health.sh > /var/log/haproxy_health.log 2>&1" | sudo tee -a /etc/crontab
```

#### Validation:
```bash
# Test the health check script
sudo /usr/local/bin/haproxy_health.sh

# Verify cron setup
grep haproxy_health /etc/crontab
```

## Conclusion

This configuration provides a robust starting point for handling national examination results traffic with Windows backend servers. Regular testing under load conditions is essential to ensure the system performs as expected during actual examination result announcements in Sudan.

## References

- [HAProxy Documentation](https://www.haproxy.org/doc/)
- [HAProxy Best Practices](https://www.haproxy.com/blog/haproxy-configuration-best-practices/)
- [Rocky Linux Documentation](https://docs.rockylinux.org/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Microsoft IIS Documentation](https://docs.microsoft.com/en-us/iis/)