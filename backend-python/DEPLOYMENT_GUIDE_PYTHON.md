# InfoSec AI Monitor - Python/FastAPI Deployment Guide

This comprehensive guide covers deploying the advanced Python/FastAPI implementation with ML capabilities.

## 🏗️ Advanced Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Browser Ext    │───▶│   FastAPI API   │───▶│   PostgreSQL    │
│  (Client-side)  │    │   (Python)      │    │   (Database)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                         │
                              ▼                         ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Celery Tasks   │    │      Redis      │
                       │  (Background)   │    │  (Cache/Queue)  │
                       └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   ML Pipeline   │
                       │ (TensorFlow/    │
                       │  PyTorch)       │
                       └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  WebSocket      │
                       │  Real-time      │
                       │  Monitoring     │
                       └─────────────────┘
```

## 📋 Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04+ / CentOS 8+ / RHEL 8+
- **Python**: 3.9+ (3.11 recommended)
- **Memory**: 8GB+ (16GB recommended for ML)
- **Storage**: 100GB+ SSD
- **CPU**: 4+ cores (8+ for ML workloads)
- **GPU**: Optional (NVIDIA CUDA for TensorFlow/PyTorch acceleration)

### Required Software Stack
```bash
# System packages
- Python 3.11+
- PostgreSQL 14+
- Redis 6.2+
- Nginx 1.20+
- Supervisor/Systemd
- Git
- Build tools (gcc, make, etc.)

# Optional for GPU acceleration
- NVIDIA drivers
- CUDA toolkit
- cuDNN library
```

## 🚀 Installation Steps

### 1. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install system dependencies
sudo apt install -y python3.11 python3.11-venv python3.11-dev \
    postgresql-14 postgresql-contrib redis-server nginx \
    git curl wget build-essential libssl-dev libffi-dev \
    libpq-dev supervisor htop

# Install Python package manager
curl -sSL https://install.python-poetry.org | python3 -
# or
pip3 install poetry
```

### 2. Database Setup

```bash
# PostgreSQL setup
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE infosec_ai_monitor;
CREATE USER infosec_monitor WITH PASSWORD 'your_secure_password';
ALTER USER infosec_monitor CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE infosec_ai_monitor TO infosec_monitor;

-- Enable required extensions
\c infosec_ai_monitor
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";
EOF
```

### 3. Redis Configuration

```bash
# Configure Redis
sudo nano /etc/redis/redis.conf

# Key configurations:
# maxmemory 2gb
# maxmemory-policy allkeys-lru
# save 900 1
# save 300 10
# save 60 10000

sudo systemctl enable redis-server
sudo systemctl restart redis-server
```

### 4. Application Deployment

```bash
# Create application directory
sudo mkdir -p /opt/infosec-ai-monitor
sudo chown $USER:$USER /opt/infosec-ai-monitor
cd /opt/infosec-ai-monitor

# Clone repository
git clone <repository-url> .

# Set up Python virtual environment
cd backend-python
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies with Poetry (recommended)
poetry install --no-dev
# or with pip
pip install -r requirements.txt

# Install ML models and dependencies
python -m spacy download en_core_web_sm
```

### 5. Environment Configuration

Create production `.env` file:

```bash
# Copy example and edit
cp .env.example .env
nano .env
```

**Critical Environment Variables:**

```ini
# Application
APP_NAME="InfoSec AI Monitor"
APP_ENV=production
DEBUG=false
HOST=0.0.0.0
PORT=8000
SECRET_KEY=your_very_secure_secret_key_here
EXTENSION_SECRET=your_extension_auth_secret

# Database
DATABASE_URL=postgresql+asyncpg://infosec_monitor:password@localhost/infosec_ai_monitor
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_CACHE_TTL=3600

# Celery
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/1

# Security
ALLOWED_ORIGINS=["https://your-domain.com"]
ALLOWED_HOSTS=["your-domain.com"]
ANONYMIZATION_SALT=your_anonymization_salt

# ML Configuration
ML_MODEL_PATH=models/
ML_CONFIDENCE_THRESHOLD=0.7
ML_RETRAIN_INTERVAL_HOURS=24

# Email/Alerts
EMAIL_HOST=smtp.company.com
EMAIL_USER=alerts@company.com
EMAIL_PASSWORD=secure_email_password
ALERT_RECIPIENTS_DEFAULT=["security@company.com"]
ALERT_RECIPIENTS_CRITICAL=["ciso@company.com"]

# Privacy & Compliance
DATA_RETENTION_DAYS=365
CONSENT_EXPIRY_DAYS=180
```

### 6. Database Migration

```bash
# Install Alembic for migrations
pip install alembic

# Initialize database
python -c "
import asyncio
from app.core.database import init_db
asyncio.run(init_db())
"
```

### 7. ML Model Setup

```bash
# Create models directory
mkdir -p models/

# Download and prepare ML models
python scripts/setup_ml_models.py

# Test ML service
python -c "
import asyncio
from app.services.ml_service import MLRiskAnalyzer
async def test():
    analyzer = MLRiskAnalyzer()
    await analyzer.initialize()
    health = await analyzer.health_check()
    print(f'ML Service Health: {health}')
asyncio.run(test())
"
```

### 8. Process Management with Supervisor

Create `/etc/supervisor/conf.d/infosec-ai-monitor.conf`:

```ini
[group:infosec-ai-monitor]
programs=infosec-api,infosec-celery-worker,infosec-celery-beat

[program:infosec-api]
directory=/opt/infosec-ai-monitor/backend-python
command=/opt/infosec-ai-monitor/backend-python/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
user=infosec
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/supervisor/infosec-api.log
stdout_logfile_maxbytes=50MB
stdout_logfile_backups=10
environment=PATH="/opt/infosec-ai-monitor/backend-python/venv/bin"

[program:infosec-celery-worker]
directory=/opt/infosec-ai-monitor/backend-python
command=/opt/infosec-ai-monitor/backend-python/venv/bin/python -m celery -A app.services.celery_app worker --loglevel=info --concurrency=4 --queues=default,ml_processing,notifications,privacy,analytics
user=infosec
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/supervisor/infosec-celery-worker.log
stdout_logfile_maxbytes=50MB
stdout_logfile_backups=10
environment=PATH="/opt/infosec-ai-monitor/backend-python/venv/bin"

[program:infosec-celery-beat]
directory=/opt/infosec-ai-monitor/backend-python
command=/opt/infosec-ai-monitor/backend-python/venv/bin/python -m celery -A app.services.celery_app beat --loglevel=info --scheduler=redbeat.RedBeatScheduler
user=infosec
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/supervisor/infosec-celery-beat.log
stdout_logfile_maxbytes=50MB
stdout_logfile_backups=10
environment=PATH="/opt/infosec-ai-monitor/backend-python/venv/bin"
```

### 9. Nginx Configuration

Create `/etc/nginx/sites-available/infosec-ai-monitor`:

```nginx
upstream infosec_backend {
    least_conn;
    server 127.0.0.1:8000;
    # Add more servers for load balancing
    # server 127.0.0.1:8001;
    # server 127.0.0.1:8002;
}

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/s;

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/your-domain.crt;
    ssl_certificate_key /etc/ssl/private/your-domain.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
    
    # Logging
    access_log /var/log/nginx/infosec-ai-monitor.access.log;
    error_log /var/log/nginx/infosec-ai-monitor.error.log;
    
    # API endpoints with rate limiting
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
        
        proxy_pass http://infosec_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
    
    # WebSocket support
    location /ws/ {
        proxy_pass http://infosec_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket timeouts
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://infosec_backend;
        access_log off;
    }
    
    # Metrics endpoint (restrict access)
    location /metrics {
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        
        proxy_pass http://infosec_backend;
    }
    
    # Static files (if any)
    location /static/ {
        alias /opt/infosec-ai-monitor/backend-python/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Block common attack patterns
    location ~ /(\.|wp-admin|wp-content|phpmyadmin) {
        deny all;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

### 10. Monitoring and Logging

#### Prometheus Configuration

Create `/etc/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'infosec-ai-monitor'
    static_configs:
      - targets: ['localhost:8000']
    scrape_interval: 5s
    metrics_path: /metrics
    scheme: https
    tls_config:
      insecure_skip_verify: true
```

#### Log Management

```bash
# Configure log rotation
sudo nano /etc/logrotate.d/infosec-ai-monitor

/var/log/supervisor/infosec-*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    postrotate
        supervisorctl reread
        supervisorctl update
    endscript
}
```

## 🔧 Advanced Configuration

### High Availability Setup

#### Load Balancing
```nginx
upstream infosec_backend {
    least_conn;
    server 10.0.1.10:8000 weight=3;
    server 10.0.1.11:8000 weight=3;
    server 10.0.1.12:8000 weight=2 backup;
}
```

#### Database Clustering (PostgreSQL)
```bash
# Master-slave replication setup
# Primary server configuration in postgresql.conf:
wal_level = replica
max_wal_senders = 3
wal_keep_size = 64MB
```

#### Redis Clustering
```bash
# Redis Sentinel for high availability
redis-sentinel /etc/redis/sentinel.conf
```

### ML Model Optimization

#### GPU Acceleration (if available)
```bash
# Install CUDA support
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
pip install tensorflow-gpu

# Configure GPU memory growth
export TF_GPU_MEMORY_GROWTH=true
```

#### Model Caching
```python
# In production, enable model caching
ML_MODEL_CACHE_SIZE=1000
ML_MODEL_CACHE_TTL=3600
```

### Security Hardening

#### Firewall Configuration
```bash
# UFW firewall rules
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 80/tcp    # HTTP (redirects)
sudo ufw deny 5432/tcp   # PostgreSQL (internal only)
sudo ufw deny 6379/tcp   # Redis (internal only)
sudo ufw enable
```

#### Application Security
```bash
# Set secure file permissions
sudo chown -R infosec:infosec /opt/infosec-ai-monitor
sudo chmod -R 755 /opt/infosec-ai-monitor
sudo chmod 600 /opt/infosec-ai-monitor/backend-python/.env

# Secure log files
sudo chown -R infosec:adm /var/log/supervisor/infosec-*
sudo chmod 640 /var/log/supervisor/infosec-*
```

## 📊 Monitoring & Operations

### Health Checks

```bash
# API health check
curl -f https://your-domain.com/health

# Celery health check
cd /opt/infosec-ai-monitor/backend-python
source venv/bin/activate
python -c "from app.services.celery_app import celery_health_check; print(celery_health_check.delay().get())"

# Database health check
psql -h localhost -U infosec_monitor -d infosec_ai_monitor -c "SELECT 1;"

# Redis health check
redis-cli ping
```

### Performance Monitoring

#### Application Metrics
```bash
# View FastAPI metrics
curl https://your-domain.com/metrics

# Celery monitoring
celery -A app.services.celery_app inspect active
celery -A app.services.celery_app inspect scheduled
celery -A app.services.celery_app inspect reserved
```

#### System Metrics
```bash
# Monitor resource usage
htop
iotop
nethogs

# Database performance
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity;"

# Redis performance
redis-cli info stats
```

### Backup Strategy

#### Database Backup
```bash
#!/bin/bash
# /opt/infosec-ai-monitor/scripts/backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/backups/infosec-ai-monitor"
mkdir -p $BACKUP_DIR

# Database backup
pg_dump -h localhost -U infosec_monitor -d infosec_ai_monitor | \
    gzip > $BACKUP_DIR/database_$DATE.sql.gz

# ML models backup
tar -czf $BACKUP_DIR/models_$DATE.tar.gz /opt/infosec-ai-monitor/backend-python/models/

# Configuration backup
tar -czf $BACKUP_DIR/config_$DATE.tar.gz /opt/infosec-ai-monitor/backend-python/.env

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

## 🚨 Troubleshooting

### Common Issues

1. **High Memory Usage (ML Models)**
   ```bash
   # Monitor memory usage
   free -h
   ps aux --sort=-%mem | head
   
   # Optimize model loading
   # Set in .env:
   ML_LAZY_LOADING=true
   ML_MODEL_CACHE_SIZE=100
   ```

2. **Celery Tasks Failing**
   ```bash
   # Check Celery worker logs
   sudo supervisorctl tail -f infosec-celery-worker
   
   # Restart workers
   sudo supervisorctl restart infosec-celery-worker
   
   # Clear failed tasks
   python -c "from app.services.celery_app import purge_all_tasks; purge_all_tasks()"
   ```

3. **Database Performance Issues**
   ```sql
   -- Monitor slow queries
   SELECT query, calls, total_time, mean_time 
   FROM pg_stat_statements 
   ORDER BY mean_time DESC LIMIT 10;
   
   -- Check indexes
   SELECT schemaname, tablename, attname, n_distinct, correlation 
   FROM pg_stats WHERE tablename = 'ai_interactions';
   ```

4. **WebSocket Connection Issues**
   ```bash
   # Check nginx WebSocket config
   sudo nginx -t
   
   # Test WebSocket endpoint
   wscat -c wss://your-domain.com/ws/monitor
   ```

### Performance Optimization

#### Database Optimization
```sql
-- Create additional indexes for frequent queries
CREATE INDEX CONCURRENTLY idx_ai_interactions_platform_time 
ON ai_interactions(platform, created_at DESC);

CREATE INDEX CONCURRENTLY idx_ai_interactions_risk_analysis 
ON ai_interactions(risk_level, risk_score DESC) 
WHERE risk_level IN ('high', 'critical');

-- Analyze tables for query optimization
ANALYZE ai_interactions;
ANALYZE security_alerts;
ANALYZE user_sessions;
```

#### Application Optimization
```python
# Optimize FastAPI performance
# In main.py:
app.add_middleware(
    GZipMiddleware, 
    minimum_size=1000
)

# Configure connection pooling
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30
```

## 🔄 Updates and Maintenance

### Zero-Downtime Deployment

```bash
#!/bin/bash
# deployment script
set -e

echo "Starting zero-downtime deployment..."

# Pull latest code
git fetch origin
git checkout production
git pull origin production

# Install dependencies
source venv/bin/activate
pip install -r requirements.txt --no-deps

# Run migrations
python -c "import asyncio; from app.core.database import init_db; asyncio.run(init_db())"

# Reload services gracefully
sudo supervisorctl reread
sudo supervisorctl update

# Test health
sleep 5
curl -f https://your-domain.com/health

echo "Deployment completed successfully"
```

### ML Model Updates

```bash
# Script to update ML models
#!/bin/bash
cd /opt/infosec-ai-monitor/backend-python
source venv/bin/activate

# Backup current models
cp -r models/ models_backup_$(date +%Y%m%d)/

# Download new models
python scripts/update_ml_models.py

# Restart Celery workers to load new models
sudo supervisorctl restart infosec-celery-worker

echo "ML models updated successfully"
```

This deployment guide provides a production-ready setup for the advanced Python/FastAPI implementation with comprehensive ML capabilities, real-time monitoring, and enterprise-grade security features.