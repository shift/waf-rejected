# Backup and Disaster Recovery Guide

## Overview

This guide covers backup strategies, disaster recovery procedures, and business continuity planning for WAF-Rejected in production environments.

## Backup Strategy

### Data Categories

#### 1. Security Event Data
- **Type**: Time-series security events, audit logs
- **Retention**: 7 years (compliance requirement)
- **Backup Frequency**: Daily incremental, weekly full
- **Storage**: Encrypted S3-compatible object storage

#### 2. Configuration Data
- **Type**: Application configuration, policies, rules
- **Retention**: 1 year
- **Backup Frequency**: On change + daily
- **Storage**: Git repository + encrypted backup

#### 3. System State
- **Type**: Kubernetes state, secrets, certificates
- **Retention**: 30 days
- **Backup Frequency**: Hourly
- **Storage**: Encrypted backup storage

### Backup Implementation

#### Automated Backups

```yaml
# Kubernetes CronJob for daily backups
apiVersion: batch/v1
kind: CronJob
metadata:
  name: waf-rejected-backup
  namespace: security
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: waf-rejected-backup:latest
            env:
            - name: BACKUP_TYPE
              value: "full"
            - name: S3_BUCKET
              value: "waf-rejected-backups"
            volumeMounts:
            - name: data
              mountPath: /data
          volumes:
          - name: data
            persistentVolumeClaim:
              claimName: waf-rejected-data
          restartPolicy: OnFailure
```

#### Manual Backup Procedure

```bash
#!/bin/bash
# Manual backup script

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/${BACKUP_DATE}"

# Create backup directory
mkdir -p ${BACKUP_DIR}

# Backup security events database
kubectl exec -n security deployment/waf-rejected -- \
  sled export /var/log/waf/security.db > ${BACKUP_DIR}/security.db

# Backup audit logs
kubectl cp security/waf-rejected-pod:/var/audit ${BACKUP_DIR}/audit -c waf-ingress

# Backup configuration
helm get values waf-rejected -n security > ${BACKUP_DIR}/helm-values.yaml
kubectl get configmap waf-rejected-config -n security -o yaml > ${BACKUP_DIR}/configmap.yaml

# Compress and encrypt
tar -czf ${BACKUP_DIR}.tar.gz ${BACKUP_DIR}
openssl enc -aes-256-cbc -salt -in ${BACKUP_DIR}.tar.gz -out ${BACKUP_DIR}.enc -k ${ENCRYPTION_KEY}

# Upload to S3
aws s3 cp ${BACKUP_DIR}.enc s3://waf-rejected-backups/

# Cleanup
rm -rf ${BACKUP_DIR} ${BACKUP_DIR}.tar.gz ${BACKUP_DIR}.enc
```

## Disaster Recovery

### Recovery Time Objectives (RTO)

- **Critical Security Events**: 1 hour
- **Application Availability**: 4 hours
- **Full Data Recovery**: 24 hours

### Recovery Point Objectives (RPO)

- **Security Events**: 1 hour
- **Configuration**: 1 hour
- **System State**: 1 hour

### Recovery Procedures

#### 1. Application Recovery

```bash
#!/bin/bash
# Application recovery script

# Scale down current deployment
kubectl scale deployment waf-rejected --replicas=0 -n security

# Restore from backup
BACKUP_DATE="20240115_020000"
aws s3 cp s3://waf-rejected-backups/${BACKUP_DATE}.enc ${BACKUP_DATE}.enc
openssl enc -d -aes-256-cbc -in ${BACKUP_DATE}.enc -out ${BACKUP_DATE}.tar.gz -k ${ENCRYPTION_KEY}
tar -xzf ${BACKUP_DATE}.tar.gz

# Restore database
kubectl cp ${BACKUP_DATE}/security.db security/waf-rejected-pod:/var/log/waf/security.db -c waf-ingress

# Restore audit logs
kubectl cp ${BACKUP_DATE}/audit security/waf-rejected-pod:/var/audit -c waf-ingress

# Deploy with restored configuration
helm upgrade --install waf-rejected ./infrastructure/helm \
  --namespace security \
  --values ${BACKUP_DATE}/helm-values.yaml \
  --wait

# Scale up
kubectl scale deployment waf-rejected --replicas=3 -n security
```

#### 2. Configuration Recovery

```bash
# Restore ConfigMap
kubectl apply -f ${BACKUP_DATE}/configmap.yaml

# Restore Secrets (if needed)
kubectl create secret generic waf-api-keys --from-env-file=api-keys.env -n security

# Restart pods to pick up new configuration
kubectl rollout restart deployment/waf-rejected -n security
```

#### 3. Certificate Recovery

```bash
# Restore TLS certificates
kubectl create secret tls waf-tls-cert \
  --cert=${BACKUP_DATE}/tls.crt \
  --key=${BACKUP_DATE}/tls.key \
  -n security

# Update ingress
kubectl apply -f infrastructure/kubernetes/ingress.yaml
```

### Failover Procedures

#### Regional Failover

```bash
# Switch to backup region
kubectl config use-context production-us-west

# Deploy to backup region
helm install waf-rejected-dr ./infrastructure/helm \
  --namespace security \
  --set replicaCount=5 \
  --set upstream.url="https://backup-backend.us-west.example.com"

# Update DNS
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456789 \
  --change-batch file://dns-failover.json
```

#### Service Failover

```bash
# Check service health
kubectl get pods -n security

# If primary unhealthy, switch to backup
kubectl patch service waf-rejected -n security \
  -p '{"spec":{"selector":{"app":"waf-rejected-backup"}}}'

# Scale down unhealthy deployment
kubectl scale deployment waf-rejected --replicas=0 -n security
```

## Business Continuity

### High Availability Configuration

```yaml
# Multi-zone deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-rejected
spec:
  replicas: 6  # 2 per zone
  topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app: waf-rejected
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchLabels:
            app: waf-rejected
        topologyKey: kubernetes.io/hostname
```

### Load Balancing

```yaml
# Global load balancer configuration
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: waf-rejected-global
  annotations:
    kubernetes.io/ingress.class: "gce"
    networking.gke.io/managed-certificates: "waf-global-cert"
spec:
  rules:
  - host: waf.example.com
    http:
      paths:
      - path: /*
        pathType: ImplementationSpecific
        backend:
          service:
            name: waf-rejected
            port:
              number: 80
```

## Testing and Validation

### Backup Testing

```bash
#!/bin/bash
# Backup validation script

# Create test data
kubectl exec deployment/waf-rejected -n security -- \
  sled put /var/log/waf/security.db test-key test-value

# Run backup
./scripts/backup.sh

# Simulate disaster (delete data)
kubectl exec deployment/waf-rejected -n security -- \
  sled delete /var/log/waf/security.db test-key

# Run recovery
./scripts/recovery.sh

# Validate recovery
kubectl exec deployment/waf-rejected -n security -- \
  sled get /var/log/waf/security.db test-key
```

### Disaster Recovery Testing

```bash
#!/bin/bash
# DR testing script

# Create test environment
kubectl create namespace security-test

# Deploy test instance
helm install waf-rejected-test ./infrastructure/helm \
  --namespace security-test \
  --set replicaCount=1

# Generate test traffic
# ... load testing ...

# Simulate failure
kubectl delete namespace security-test

# Test recovery time
START_TIME=$(date +%s)
# ... recovery steps ...
END_TIME=$(date +%s)

RECOVERY_TIME=$((END_TIME - START_TIME))
echo "Recovery completed in ${RECOVERY_TIME} seconds"

# Validate functionality
curl -f https://waf-test.example.com/health
```

## Monitoring and Alerting

### Backup Health Monitoring

```yaml
# Prometheus alerting rules
groups:
  - name: backup-alerts
    rules:
      - alert: BackupFailed
        expr: waf_backup_success == 0
        for: 1h
        labels:
          severity: critical
        annotations:
          summary: "WAF-Rejected backup failed"
          description: "Backup job failed for the last hour"

      - alert: OldBackup
        expr: (time() - waf_backup_last_success) > 86400
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "WAF-Rejected backup is outdated"
          description: "Last successful backup was more than 24 hours ago"
```

### Recovery Testing Schedule

- **Monthly**: Full backup and recovery test
- **Quarterly**: Regional failover test
- **Annually**: Complete disaster recovery simulation

## Compliance Considerations

### Data Retention Compliance

- **GDPR**: Data minimization, retention limits
- **HIPAA**: Protected health information handling
- **PCI-DSS**: Cardholder data protection
- **SOX**: Financial data retention requirements

### Audit Trail Integrity

- **Cryptographic signatures** on backup files
- **Chain of custody** documentation
- **Access logging** for backup operations
- **Regular integrity checks** of archived data

## Maintenance

### Regular Tasks

- **Backup verification**: Weekly integrity checks
- **Retention cleanup**: Automated deletion of expired data
- **Storage optimization**: Compression and deduplication
- **Access review**: Regular review of backup access permissions

### Emergency Contacts

- **Primary**: Security Operations Center (SOC)
- **Secondary**: DevOps Engineering Team
- **Tertiary**: Executive Leadership

### Documentation Updates

- **Post-incident**: Update procedures based on lessons learned
- **Technology changes**: Update scripts for new tools/versions
- **Regulatory changes**: Update procedures for new compliance requirements