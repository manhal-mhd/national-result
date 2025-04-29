# HAProxy National Results Configuration Guide

## Introduction

This guide provides instructions for setting up HAProxy to handle national election results traffic. HAProxy is a reliable, high-performance TCP/HTTP load balancer that can help manage the significant traffic spikes during election result announcements.

## Server Preparation on Rocky Linux 9 VM

### 1. VM Requirements

For a production HAProxy server handling national results, configure your VM with:

- **CPU**: Minimum 4 vCPUs (8+ recommended for high traffic)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 50GB SSD-backed storage
- **Network**: Multiple network interfaces with at least 1Gbps throughput

### 2. Base System Setup

```bash
# Log in as root or a user with sudo privileges

# Update the system
sudo dnf update -y

# Install necessary tools
sudo dnf install -y vim wget curl tar zip unzip net-tools telnet chrony

# Configure timezone
sudo timedatectl set-timezone Africa/Johannesburg

# Enable and start chronyd for time synchronization
sudo systemctl enable --now chronyd
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
sudo hostnamectl set-hostname haproxy-results.example.gov

# Add hostname to /etc/hosts
echo "196.192.113.X haproxy-results.example.gov haproxy-results" | sudo tee -a /etc/hosts
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

### 5. Install HAProxy

```bash
# Install EPEL repository
sudo dnf install -y epel-release

# Install HAProxy 2.4+ from EPEL
sudo dnf install -y haproxy

# Check HAProxy version
haproxy -v
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
sudo mkdir -p /etc/letsencrypt/live/results.example.gov/
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
  -d results.example.gov \
  -d api.results.example.gov \
  --email admin@example.gov \
  --agree-tos

# Set up automatic renewal
echo "0 0,12 * * * root python -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew --quiet --post-hook 'systemctl reload haproxy'" | sudo tee -a /etc/crontab

# Create a script to combine certificates for HAProxy
cat <<'EOF' | sudo tee /usr/local/bin/update-haproxy-certs.sh
#!/bin/bash
DOMAIN="results.example.gov"
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

### 9. Create Custom Error Pages

```bash
# Create simple error pages for common HTTP errors
for code in 400 403 408 500 502 503 504; do
  echo "<html><body><h1>Error ${code}</h1><p>National Results: An error occurred.</p></body></html>" | \
  sudo tee /etc/haproxy/errors/${code}.http
done
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

### 2. Create Frontend Configuration

```bash
# Create the frontend configuration file
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/10-frontend.cfg
# Frontend configuration for National Results
frontend national_results_frontend
    # Bind to ports 80 and 443 with SSL
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/results.example.gov.pem
    
    # HTTPS redirect
    http-request redirect scheme https unless { ssl_fc }
    
    # DDOS protection
    stick-table type ip size 100k expire 30s store conn_rate(3s),bytes_in_rate(60s),http_req_rate(60s)
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
    
    # ACL definitions
    acl results_path path_beg /results
    acl api_path path_beg /api
    acl static_path path_beg /static
    
    # Backend routing
    use_backend results_backend if results_path
    use_backend api_backend if api_path
    use_backend static_backend if static_path
    default_backend results_backend
EOF
```

### 3. Create Backend Configurations

```bash
# Create the results backend configuration
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/20-results-backend.cfg
# Results backend configuration (dynamic content)
backend results_backend
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    cookie SERVERID insert indirect nocache
    
    # Connection limits and timeouts
    server results1 results1.example.gov:8080 check cookie s1 maxconn 3000
    server results2 results2.example.gov:8080 check cookie s2 maxconn 3000
    server results3 results3.example.gov:8080 check cookie s3 maxconn 3000
    
    # Compression options
    compression algo gzip
    compression type text/html text/plain text/css application/javascript application/json
EOF

# Create the API backend configuration
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/30-api-backend.cfg
# API backend configuration
backend api_backend
    balance roundrobin
    option httpchk GET /api/health
    http-check expect status 200
    
    # Rate limiting
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request deny if { sc_http_req_rate(0) gt 50 }
    
    # Servers
    server api1 api1.example.gov:8081 check maxconn 2000
    server api2 api2.example.gov:8081 check maxconn 2000
EOF

# Create the static content backend configuration
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/40-static-backend.cfg
# Static content backend configuration
backend static_backend
    balance leastconn
    option httpchk GET /static/health
    
    # Cache headers
    http-response set-header Cache-Control "max-age=3600"
    
    server static1 static1.example.gov:8082 check
    server static2 static2.example.gov:8082 check
EOF
```

### 4. Create Statistics Configuration

```bash
# Create the statistics configuration
cat <<'EOF' | sudo tee /etc/haproxy/haproxy.d/50-stats.cfg
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

## Traffic Surge Handling

During result announcements, implement these strategies:

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

## Troubleshooting

Common issues and solutions:

1. **503 Service Unavailable**
   - Check backend server health using `echo "show servers state" | sudo socat stdio /run/haproxy/admin.sock`
   - Review connection limits in the configuration
   - Verify server resources with `htop` and `iftop`

2. **Slow Response Times**
   - Analyze HAProxy logs: `sudo tail -f /var/log/haproxy.log`
   - Adjust timeouts in the configuration files
   - Consider scaling backend servers

3. **Certificate Issues**
   - Check certificate expiration: `certbot certificates`
   - Verify certificate installation: `openssl x509 -in /etc/haproxy/certs/results.example.gov.pem -text -noout`
   - Test SSL configuration: `openssl s_client -connect results.example.gov:443`

## Security Recommendations

1. Implement IP allowlisting for administrative access
2. Regular security audits
3. Keep HAProxy updated to the latest stable version
4. Use strong TLS configurations
5. Implement rate limiting and DDOS protection

## Conclusion

This configuration provides a robust starting point for handling national results traffic. Regular testing under load conditions is essential to ensure the system performs as expected during actual election result announcements.

## References

- [HAProxy Documentation](https://www.haproxy.org/doc/)
- [HAProxy Best Practices](https://www.haproxy.com/blog/haproxy-configuration-best-practices/)
- [Rocky Linux Documentation](https://docs.rockylinux.org/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)