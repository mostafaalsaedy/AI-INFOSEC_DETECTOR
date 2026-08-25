# InfoSec AI Monitor - Deployment Guide

Covers all three deployable components:

1. **A monitoring API** - the Laravel backend (sections 1-9 below) *or* the
   FastAPI backend (see [Deploying the Python Backend](#-deploying-the-python-backend)).
   Deploy one, not both against the same database.
2. **The dashboard** - see [Deploying the Dashboard](#-deploying-the-dashboard).
3. **The browser extension** - see section 8 and
   [Provisioning the Extension Secret](#-provisioning-the-extension-secret).

Finish with the [Post-Deployment Checklist](#-post-deployment-checklist).

This comprehensive guide will help you deploy the InfoSec AI monitoring system in your organization.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Browser Ext    │───▶│   Laravel API   │───▶│     Database    │
│  (Client-side)  │    │   (Backend)     │    │   (MySQL/PostgreSQL) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Admin Dashboard│
                       │   (Web Interface)│
                       └─────────────────┘
```

## 📋 Prerequisites

### System Requirements
- **Server**: Linux (Ubuntu 20.04+ recommended) or similar
- **PHP**: 8.2 or higher
- **Database**: MySQL 8.0+ or PostgreSQL 13+
- **Web Server**: Nginx or Apache
- **Memory**: Minimum 4GB RAM (8GB+ recommended)
- **Storage**: Minimum 50GB (scales with data retention)

### Required Software
- Composer (PHP dependency manager)
- Node.js 16+ and npm (for frontend build)
- Redis (for caching and queues)
- SSL certificate (required for production)

## 🚀 Installation Steps

### 1. Server Setup

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install PHP and extensions
sudo apt install php8.2 php8.2-fpm php8.2-mysql php8.2-redis php8.2-mbstring \
                 php8.2-xml php8.2-curl php8.2-zip php8.2-intl -y

# Install Composer
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer

# Install Redis
sudo apt install redis-server -y
sudo systemctl enable redis-server

# Install and configure MySQL
sudo apt install mysql-server -y
sudo mysql_secure_installation
```

### 2. Database Setup

```sql
-- Connect to MySQL as root
mysql -u root -p

-- Create database and user
CREATE DATABASE infosec_ai_monitor;
CREATE USER 'infosec_monitor'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON infosec_ai_monitor.* TO 'infosec_monitor'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 3. Application Deployment

```bash
# Clone or upload the project
cd /var/www/
sudo git clone <your-repository> infosec-ai-monitor
cd infosec-ai-monitor/backend

# Set proper permissions
sudo chown -R www-data:www-data /var/www/infosec-ai-monitor
sudo chmod -R 755 storage bootstrap/cache

# Install PHP dependencies
composer install --optimize-autoloader --no-dev

# Environment configuration
cp .env.example .env
php artisan key:generate

# Edit .env file with your configuration
nano .env
```

### 4. Environment Configuration

Update your `.env` file with the following critical settings:

```ini
# Application
APP_NAME="InfoSec AI Monitor"
APP_ENV=production
APP_DEBUG=false
APP_URL=https://your-domain.com

# Database
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_DATABASE=infosec_ai_monitor
DB_USERNAME=infosec_monitor
DB_PASSWORD=your_secure_password

# Security
EXTENSION_SECRET=your_very_secure_random_string

# Email for alerts
MAIL_MAILER=smtp
MAIL_HOST=your-smtp-server.com
MAIL_FROM_ADDRESS=security-alerts@your-domain.com

# Alert recipients
ALERTS_DEFAULT_RECIPIENTS="security@your-domain.com"
ALERTS_CRITICAL_RECIPIENTS="ciso@your-domain.com,security-team@your-domain.com"
```

### 5. Database Migration

```bash
# Run database migrations
php artisan migrate

# Seed initial data (optional)
php artisan db:seed
```

### 6. Web Server Configuration

#### Nginx Configuration

Create `/etc/nginx/sites-available/infosec-ai-monitor`:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    root /var/www/infosec-ai-monitor/backend/public;
    index index.php;

    # SSL Configuration
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # Rate limiting for API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        try_files $uri $uri/ /index.php?$query_string;
    }

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Block access to sensitive files
    location ~ /\. {
        deny all;
    }

    location ~ /(web\.config|\.env) {
        deny all;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

```bash
# Enable the site
sudo ln -s /etc/nginx/sites-available/infosec-ai-monitor /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7. Process Management

Create a systemd service for Laravel queue workers:

Create `/etc/systemd/system/infosec-queue-worker.service`:

```ini
[Unit]
Description=InfoSec AI Monitor Queue Worker
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
Restart=always
RestartSec=3
ExecStart=/usr/bin/php /var/www/infosec-ai-monitor/backend/artisan queue:work --sleep=3 --tries=3 --max-time=3600
WorkingDirectory=/var/www/infosec-ai-monitor/backend

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start the service
sudo systemctl enable infosec-queue-worker.service
sudo systemctl start infosec-queue-worker.service
```

### 8. Browser Extension Deployment

#### Chrome/Edge Extension

1. **Package the extension:**
```bash
cd extension/
zip -r infosec-ai-monitor.zip . -x "*.git*" "node_modules/*"
```

2. **Deploy via Chrome Web Store or Enterprise Policy:**

For enterprise deployment, create a policy file:

`/etc/opt/chrome/policies/managed/infosec-monitor.json`:
```json
{
    "ExtensionInstallForcelist": [
        "your-extension-id;https://your-domain.com/updates.xml"
    ],
    "ExtensionSettings": {
        "your-extension-id": {
            "installation_mode": "force_installed",
            "update_url": "https://your-domain.com/updates.xml"
        }
    }
}
```

#### Firefox Extension

Deploy via Firefox Enterprise Policy or internal add-on distribution.

### 9. Security Hardening

#### Firewall Configuration
```bash
# UFW firewall rules
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (redirects to HTTPS)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

#### Log Monitoring
```bash
# Install fail2ban for intrusion prevention
sudo apt install fail2ban -y

# Configure fail2ban for the application
sudo tee /etc/fail2ban/jail.local << EOF
[infosec-api]
enabled = true
filter = infosec-api
logpath = /var/www/infosec-ai-monitor/backend/storage/logs/laravel.log
maxretry = 5
bantime = 3600
findtime = 600

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 600
bantime = 3600
EOF

sudo systemctl restart fail2ban
```

## 🔧 Configuration

### Critical Configuration Items

1. **Extension Secret**: Generate a strong random string for `EXTENSION_SECRET`
2. **Database Credentials**: Use dedicated database user with minimal privileges
3. **SSL Certificate**: Required for production deployment
4. **Rate Limiting**: Configure appropriate limits for your organization size
5. **Data Retention**: Set appropriate `DATA_RETENTION_DAYS` for compliance

### Alert Configuration

Configure alert recipients and notification channels:

```ini
# Email alerts (required)
ALERTS_EMAIL_ENABLED=true
ALERTS_DEFAULT_RECIPIENTS="security@company.com"

# Slack integration (optional)
ALERTS_SLACK_ENABLED=true
ALERTS_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Custom webhook (optional)
ALERTS_WEBHOOK_ENABLED=true
ALERTS_WEBHOOK_URL=https://your-siem.company.com/webhook
```

## 📊 Monitoring and Maintenance

### Health Checks

```bash
# Check application health
curl https://your-domain.com/api/v1/health

# Check queue status
php artisan queue:monitor

# Check database connection
php artisan tinker
>>> DB::connection()->getPdo();
```

### Log Monitoring

Monitor these log files:
- Application logs: `/var/www/infosec-ai-monitor/backend/storage/logs/`
- Nginx logs: `/var/log/nginx/`
- PHP-FPM logs: `/var/log/php8.2-fpm.log`
- MySQL logs: `/var/log/mysql/`

### Backup Strategy

```bash
#!/bin/bash
# Daily backup script

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/infosec-ai-monitor"

# Database backup
mysqldump -u infosec_monitor -p infosec_ai_monitor > $BACKUP_DIR/db_$DATE.sql

# Application files backup
tar -czf $BACKUP_DIR/app_$DATE.tar.gz /var/www/infosec-ai-monitor

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

### Performance Optimization

```bash
# Optimize Laravel
php artisan config:cache
php artisan route:cache
php artisan view:cache
php artisan optimize

# MySQL optimization
sudo mysql -u root -p < database/optimization.sql
```

## 🔐 Security Considerations

### Access Control
- Use strong, unique passwords for all accounts
- Implement 2FA for admin accounts
- Regular access reviews and user deprovisioning
- Network segmentation for database servers

### Data Protection
- Enable database encryption at rest
- Use TLS 1.2+ for all communications
- Regular security updates and patching
- Implement proper backup encryption

### Monitoring
- Set up intrusion detection systems
- Monitor for unusual API usage patterns
- Regular security audits and penetration testing
- Log monitoring and SIEM integration

## 📞 Support and Troubleshooting

### Common Issues

1. **Extension not connecting to API**
   - Check CORS settings
   - Verify SSL certificate validity
   - Check firewall rules

2. **High memory usage**
   - Tune PHP-FPM pool settings
   - Optimize database queries
   - Implement proper caching

3. **Queue jobs failing**
   - Check Laravel logs
   - Verify Redis connection
   - Restart queue workers

### Getting Help

- Check application logs for error details
- Review Laravel documentation for framework issues
- Monitor system resources (CPU, memory, disk)
- Use `php artisan tinker` for debugging

For production deployments, consider implementing comprehensive monitoring with tools like:
- **Application Performance**: New Relic, DataDog
- **Infrastructure**: Prometheus + Grafana
- **Log Management**: ELK Stack or Splunk
- **Security**: SIEM integration

## 🔄 Updates and Maintenance

### Regular Maintenance Tasks

1. **Daily**
   - Monitor system resources
   - Check application logs
   - Verify backup completion

2. **Weekly**
   - Review security alerts
   - Update system packages
   - Database maintenance

3. **Monthly**
   - Security audits
   - Performance reviews
   - Documentation updates

### Update Process

```bash
# Backup current installation
./backup.sh

# Update application
cd /var/www/infosec-ai-monitor/backend
composer update
php artisan migrate
php artisan optimize:clear
php artisan optimize

# Test functionality
curl https://your-domain.com/api/v1/health

# Restart services
sudo systemctl restart nginx
sudo systemctl restart infosec-queue-worker
```

This deployment guide ensures a secure, scalable, and maintainable installation of the InfoSec AI monitoring system.
---

## 🐍 Deploying the Python Backend

The sections above cover the Laravel backend. The FastAPI backend in
`backend-python/` is an alternative implementation of the same API — deploy one
or the other, not both against the same database.

### Option A: Docker Compose (recommended for a single host)

```bash
cd backend-python

cp .env.example .env
# Generate each secret separately - never reuse one value for all three:
python -c "import secrets; print(secrets.token_urlsafe(48))"

docker compose up -d
docker compose ps
curl http://localhost:8000/health
```

Compose brings up the API, PostgreSQL, Redis and a Celery worker. Put a TLS
terminator (nginx, Caddy, or a cloud load balancer) in front of port 8000 —
the API itself speaks plain HTTP.

### Option B: systemd on a bare host

```bash
cd /var/www/infosec-ai-monitor/backend-python

python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
# Add the ML extras only if you want model-backed detection (~4 GB):
# .venv/bin/pip install -r requirements-ml.txt && .venv/bin/python -m spacy download en_core_web_sm

cp .env.example .env   # then fill in the secrets and DATABASE_URL
```

`/etc/systemd/system/infosec-api.service`:

```ini
[Unit]
Description=InfoSec AI Monitor API
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=www-data
WorkingDirectory=/var/www/infosec-ai-monitor/backend-python
EnvironmentFile=/var/www/infosec-ai-monitor/backend-python/.env
# UvicornWorker is required: the app is ASGI and serves WebSockets.
ExecStart=/var/www/infosec-ai-monitor/backend-python/.venv/bin/gunicorn app.main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 4 \
    --bind 127.0.0.1:8000 \
    --access-logfile - \
    --error-logfile -
Restart=always
RestartSec=5

# Hardening: the service needs no write access outside its own directories.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/www/infosec-ai-monitor/backend-python/logs \
               /var/www/infosec-ai-monitor/backend-python/models \
               /var/www/infosec-ai-monitor/backend-python/exports

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/infosec-worker.service`:

```ini
[Unit]
Description=InfoSec AI Monitor Celery worker
After=network.target redis.service

[Service]
Type=exec
User=www-data
WorkingDirectory=/var/www/infosec-ai-monitor/backend-python
EnvironmentFile=/var/www/infosec-ai-monitor/backend-python/.env
ExecStart=/var/www/infosec-ai-monitor/backend-python/.venv/bin/celery \
    -A app.services.celery_app worker \
    --loglevel=info \
    --queues=default,ml_processing,notifications,privacy,analytics,high_priority
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now infosec-api infosec-worker
sudo systemctl status infosec-api
```

### nginx for the Python backend

The WebSocket endpoint needs the upgrade headers; without them the dashboard
falls back to polling and live updates stop working.

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /ws/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    # Monitoring connections are long-lived; the default 60s timeout would
    # tear them down every minute.
    proxy_read_timeout 3600s;
}
```

### Option C: Kubernetes

Manifests are in `backend-python/k8s/`. Replace the placeholder values in
`secrets.yaml` before applying — they are examples, not usable secrets.

```bash
cd backend-python/k8s
kubectl apply -k .
kubectl -n infosec get pods
```

See [backend-python/k8s/README.md](backend-python/k8s/README.md).

---

## 🖥️ Deploying the Dashboard

The dashboard is a static build; it needs no Node runtime in production.

```bash
cd dashboard
npm ci

# Point the build at your API. Baked in at build time, so rebuild to change it.
echo "VITE_API_URL=https://monitor.example.com" > .env.production

npm run build          # emits build/
```

Serve `build/` from any static host. With nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name monitor.example.com;

    root /var/www/infosec-ai-monitor/dashboard/build;
    index index.html;

    # Client-side routing: unknown paths must return index.html, not 404.
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Hashed asset filenames are safe to cache indefinitely.
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # index.html must never be cached, or users get a stale asset manifest.
    location = /index.html {
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }
}
```

If the dashboard and the API are on different origins, add the dashboard origin
to `ALLOWED_ORIGINS` in the API's `.env`. Same-origin deployment (API under
`/api` on the dashboard's domain) avoids CORS entirely and is simpler to secure.

---

## 🔑 Provisioning the Extension Secret

The extension and the API must hold the same `EXTENSION_SECRET`, or every
collection request is rejected with a 401.

```bash
# Generate once, then set the same value in both places.
python -c "import secrets; print(secrets.token_hex(32))"
```

1. Put it in the API's `.env` as `EXTENSION_SECRET`.
2. Push it to browsers via enterprise policy so it never ships inside the
   packaged extension:

```json
{
  "3rdparty": {
    "extensions": {
      "<your-extension-id>": {
        "apiEndpoint": "https://monitor.example.com/api/v1",
        "extensionSecret": "<the same value>"
      }
    }
  }
}
```

Rotating the secret invalidates in-flight queued payloads on clients that have
not yet received the new value. Roll it out to browsers first, then to the API.

---

## ✅ Post-Deployment Checklist

Run through this before declaring the deployment live:

- [ ] `curl https://your-domain/api/v1/health` returns `healthy`
- [ ] An unauthenticated request to a dashboard endpoint returns **401**, not a redirect or a 500
- [ ] An unsigned request to `/api/v1/collect` returns **401**
- [ ] A correctly signed extension request returns **200**
- [ ] TLS certificate is valid and HTTP redirects to HTTPS
- [ ] `DEBUG=false` / `APP_DEBUG=false` — confirm `/docs` is not reachable
- [ ] `SECRET_KEY`, `EXTENSION_SECRET` and `ANONYMIZATION_SALT` are distinct random values
- [ ] Database and Redis are not reachable from the public internet
- [ ] The retention purge is scheduled and has run at least once
- [ ] Database backups are running **and a restore has been tested**
- [ ] Alert delivery verified end-to-end on each enabled channel
- [ ] The dashboard loads, authenticates, and shows a live WebSocket connection
- [ ] Monitored users have been informed and consent has been obtained
