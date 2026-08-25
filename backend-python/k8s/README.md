# InfoSec AI Monitor - Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the InfoSec AI Monitor system in production.

## 🏗️ **Architecture Overview**

The Kubernetes deployment consists of:

- **API Service**: FastAPI backend with auto-scaling (3-10 replicas)
- **Celery Workers**: Background task processing with auto-scaling (3-15 replicas)  
- **PostgreSQL**: Primary database with persistent storage
- **Redis**: Cache and message broker with persistent storage
- **Ingress**: NGINX-based load balancing with SSL termination
- **Monitoring**: Prometheus, Grafana, and AlertManager integration

## 📋 **Prerequisites**

### Required Tools
- `kubectl` (v1.24+)
- `helm` (v3.8+) 
- `kustomize` (v4.5+)
- Docker registry access for images

### Required Kubernetes Resources
- **Kubernetes cluster** (v1.24+) 
- **Storage class** for persistent volumes (`fast-ssd` recommended)
- **NGINX Ingress Controller**
- **cert-manager** (for SSL certificates)
- **Prometheus Operator** (for monitoring)

### Recommended Add-ons
- **Metrics Server** (for HPA)
- **Vertical Pod Autoscaler**
- **External DNS** (for DNS management)
- **External Secrets Operator** (for secret management)

## 🚀 **Deployment Instructions**

### 1. Prepare the Environment

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Create the secrets. They are NOT part of the kustomization and no filled-in
# secrets.yaml is committed, so a cluster can never start with placeholders.
# Generate three distinct values - reusing one weakens all three.
kubectl -n infosec-ai-monitor create secret generic infosec-secrets   --from-literal=SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"   --from-literal=EXTENSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"   --from-literal=ANONYMIZATION_SALT="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"   --from-literal=DATABASE_URL='postgresql+asyncpg://infosec_monitor:CHANGE_ME@postgres-service:5432/infosec_ai_monitor'

kubectl -n infosec-ai-monitor create secret generic postgres-secret   --from-literal=POSTGRES_USER='infosec_monitor'   --from-literal=POSTGRES_PASSWORD='CHANGE_ME'   --from-literal=POSTGRES_DB='infosec_ai_monitor'

kubectl -n infosec-ai-monitor create secret tls tls-secret   --cert=fullchain.pem --key=privkey.pem

# Apply configuration
kubectl apply -f configmap.yaml
```

> See `secrets.example.yaml` for the full list of keys, including the optional
> email, Slack and webhook settings. In production prefer External Secrets
> Operator, Sealed Secrets or Vault over creating secrets by hand.

### 2. Deploy Infrastructure

```bash
# Deploy PostgreSQL
kubectl apply -f postgres.yaml

# Deploy Redis  
kubectl apply -f redis.yaml

# Wait for databases to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=database --timeout=300s
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=cache --timeout=300s
```

### 3. Deploy Application Services

```bash
# Deploy API service
kubectl apply -f api.yaml

# Deploy Celery workers
kubectl apply -f celery.yaml

# Wait for API to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=api --timeout=300s
```

### 4. Configure Ingress and Monitoring

```bash
# Deploy ingress
kubectl apply -f ingress.yaml

# Deploy monitoring
kubectl apply -f monitoring.yaml
```

### 5. Using Kustomize (Recommended)

```bash
# Deploy entire stack
kubectl apply -k .

# Or with custom overlay
kubectl apply -k overlays/production
```

## 🔧 **Configuration**

### Environment Variables

Key configuration is managed through ConfigMaps and Secrets:

- **`infosec-config`**: Application configuration
- **`infosec-secrets`**: Sensitive data (passwords, API keys)
- **`postgres-secret`**: Database credentials
- **`tls-secret`**: SSL certificates

### Persistent Storage

- **PostgreSQL**: 20Gi SSD storage
- **Redis**: 5Gi SSD storage  
- **ML Models**: 10Gi shared storage (ReadWriteMany)

### Resource Requirements

**Minimum Requirements:**
- **CPU**: 8 cores total
- **Memory**: 16GB RAM total
- **Storage**: 50GB persistent storage

**Recommended Production:**
- **CPU**: 16+ cores
- **Memory**: 32GB+ RAM
- **Storage**: 100GB+ SSD

## 📊 **Monitoring & Observability**

### Prometheus Metrics

The deployment includes comprehensive monitoring:

- **API metrics**: Request rates, latencies, errors
- **ML metrics**: Model inference times, accuracy
- **Business metrics**: Security alerts, risk scores
- **Infrastructure metrics**: CPU, memory, disk usage

### Grafana Dashboards

Pre-configured dashboards for:
- **System Overview**: High-level metrics
- **API Performance**: Request metrics and latencies  
- **Security Analytics**: Risk scores and alerts
- **ML Model Performance**: Model accuracy and drift
- **Infrastructure Health**: Resource utilization

### Alerting Rules

Critical alerts configured for:
- **Service availability**: API/database downtime
- **Performance issues**: High latency, error rates
- **Security events**: Critical alerts, compliance violations
- **Resource exhaustion**: Memory, disk, CPU limits
- **ML model failures**: Model errors, accuracy degradation

## 🔐 **Security Configuration**

### Network Policies

- **Ingress restrictions**: Only allowed traffic
- **Pod-to-pod communication**: Restricted to necessary services
- **External access**: Database/Redis only from app pods

### Pod Security

- **Non-root containers**: All containers run as non-root users
- **ReadOnlyRootFilesystem**: Where possible
- **Dropped capabilities**: Minimal required capabilities
- **Security contexts**: Proper user/group assignments

### Secrets Management

**Development:**
- Kubernetes native secrets (base64 encoded)

**Production Recommended:**
- **External Secrets Operator** with HashiCorp Vault
- **AWS Secrets Manager** integration
- **Azure Key Vault** integration
- **Google Secret Manager** integration

## 📈 **Scaling Configuration**

### Horizontal Pod Autoscaler (HPA)

**API Service:**
- **Min replicas**: 3
- **Max replicas**: 10
- **Target CPU**: 70%
- **Target Memory**: 80%

**Celery Workers:**
- **Min replicas**: 3
- **Max replicas**: 15
- **Target CPU**: 70%
- **Custom metrics**: Queue length

### Vertical Pod Autoscaler (VPA)

VPA can be enabled for automatic resource recommendation:

```bash
kubectl apply -f - <<EOF
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: api-vpa
  namespace: infosec-ai-monitor
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  updatePolicy:
    updateMode: "Auto"
EOF
```

## 🛠️ **Maintenance Operations**

### Database Migrations

```bash
# Run migrations
kubectl exec -it deployment/api -- python -c "
import asyncio
from app.core.database import init_db
asyncio.run(init_db())
"
```

### Backup Operations

```bash
# Database backup
kubectl exec -it deployment/postgres -- pg_dump -U infosec_monitor infosec_ai_monitor > backup.sql

# Redis backup  
kubectl exec -it deployment/redis -- redis-cli BGSAVE
```

### Log Collection

```bash
# View API logs
kubectl logs -f deployment/api

# View Celery worker logs
kubectl logs -f deployment/celery-worker

# View all logs
kubectl logs -f -l app.kubernetes.io/name=infosec-ai-monitor
```

### Health Checks

```bash
# Check service health
kubectl get pods -l app.kubernetes.io/name=infosec-ai-monitor

# Check ingress
kubectl get ingress -n infosec-ai-monitor

# Port forward for local testing
kubectl port-forward svc/api-service 8000:8000
```

## 🚨 **Troubleshooting**

### Common Issues

**1. Pods in CrashLoopBackOff**
```bash
kubectl describe pod <pod-name>
kubectl logs <pod-name> --previous
```

**2. Database Connection Issues**
```bash
kubectl exec -it deployment/postgres -- psql -U infosec_monitor -d infosec_ai_monitor -c "SELECT 1;"
```

**3. Redis Connection Issues**
```bash
kubectl exec -it deployment/redis -- redis-cli ping
```

**4. Ingress Issues**
```bash
kubectl describe ingress infosec-ingress
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller
```

### Performance Issues

**1. High Memory Usage**
```bash
kubectl top pods -n infosec-ai-monitor
```

**2. High CPU Usage**
```bash
kubectl top nodes
```

**3. Disk Space Issues**
```bash
kubectl exec -it deployment/postgres -- df -h
```

## 🔄 **CI/CD Integration**

### GitOps with ArgoCD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: infosec-ai-monitor
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/company/infosec-ai-monitor
    targetRevision: HEAD
    path: k8s
  destination:
    server: https://kubernetes.default.svc
    namespace: infosec-ai-monitor
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### Helm Chart

For complex environments, consider converting to a Helm chart:

```bash
helm create infosec-ai-monitor
# Convert YAML files to Helm templates
# Add values.yaml for environment-specific configuration
```

## 📚 **Additional Resources**

- **[Kubernetes Documentation](https://kubernetes.io/docs/)**
- **[NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/)**
- **[cert-manager Documentation](https://cert-manager.io/docs/)**
- **[Prometheus Operator](https://prometheus-operator.dev/)**
- **[Grafana Documentation](https://grafana.com/docs/)**

## 📞 **Support**

For deployment issues or questions:
- **Documentation**: [https://docs.infosecmonitor.ai](https://docs.infosecmonitor.ai)
- **Issues**: [GitHub Issues](https://github.com/company/infosec-ai-monitor/issues)
- **Support**: support@infosecmonitor.ai