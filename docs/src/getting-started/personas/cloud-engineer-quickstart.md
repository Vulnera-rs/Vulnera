# Cloud Engineer Quick Start (10 Minutes)

**For:** Cloud/infrastructure engineers scanning S3 buckets, repositories, and cloud-hosted projects.

**Goal:** Scan cloud resources at scale with automated workflows.

## Step 1: Install & Authenticate

```bash
# Install CLI
curl -L https://github.com/Vulnera-rs/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
chmod +x vulnera

# Authenticate with API key (get from https://vulnera.studio/dashboard/keys)
vulnera auth login --api-key YOUR_API_KEY
```

## Step 2: Scan S3 Buckets

### Scan Single Bucket

```bash
vulnera analyze s3://my-bucket/src \
  --aws-profile default \
  --recursive
```

### Scan Multiple Buckets

```bash
# Create scanning config
cat > s3-scan-config.toml << EOF
[buckets]
include_patterns = ["prod-*", "app-*"]
exclude_patterns = ["archive-*", "temp-*"]
max_file_size = 1000000  # 1MB
EOF

vulnera analyze-cloud s3 \
  --config s3-scan-config.toml \
  --format json \
  --output s3-findings.json
```

### AWS Credentials

```bash
# Use AWS profile
export AWS_PROFILE=production
vulnera analyze s3://production-bucket/

# Or explicit credentials
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
vulnera analyze s3://my-bucket/
```

## Step 3: Scan GitHub Repositories

### Single Repository

```bash
vulnera analyze github://owner/repo \
  --branch main \
  --depth full
```

### Organization-Wide Scan

```bash
# Scan all repositories in organization
vulnera scan-repos \
  --source github \
  --org my-company \
  --visibility public,private \
  --output org-findings.json
```

### Exclude Patterns

```bash
vulnera scan-repos \
  --source github \
  --org my-company \
  --exclude "tests/*,vendor/*,node_modules/*" \
  --max-file-size 1000000
```

## Step 4: Cloud-Native CI/CD Pipelines

### AWS CodePipeline

```yaml
# buildspec.yml
version: 0.2

phases:
  install:
    commands:
      - curl -L https://github.com/Vulnera-rs/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
      - chmod +x vulnera

  build:
    commands:
      - ./vulnera analyze . --all-modules --format json --output vulnera-findings.json
      - ./vulnera report vulnera-findings.json --format codepipeline

artifacts:
  files:
    - vulnera-findings.json
```

### Azure Pipelines

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: DownloadSecureFile@1
    inputs:
      secureFile: 'vulnera-api-key'

  - script: |
      curl -L https://github.com/Vulnera-rs/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
      chmod +x vulnera
      ./vulnera auth login --api-key $(cat $(Agent.TempDirectory)/vulnera-api-key)
      ./vulnera analyze . --all-modules

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: 'vulnera-findings.json'
```

### GCP Cloud Build

```yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'build'
      - '-t'
      - 'gcr.io/$PROJECT_ID/vulnera-scanner'
      - '.'

  - name: 'gcr.io/$PROJECT_ID/vulnera-scanner'
    env:
      - 'VULNERA_API_KEY=$_VULNERA_API_KEY'
    args:
      - 'analyze'
      - '/workspace'
      - '--all-modules'
      - '--format'
      - 'json'
```

## Step 5: Kubernetes & Container Scanning

### Scan Docker Images

```bash
# Before pushing to registry
docker run -v /path/to/app:/app vulnera-scanner \
  analyze /app \
  --all-modules \
  --severity high
```

### Kubernetes Deployment

```yaml
# kubernetes-job.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vulnera-scanner
spec:
  schedule: "0 2 * * *"  # 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: vulnera
            image: vulnera-scanner:latest
            env:
            - name: VULNERA_API_KEY
              valueFrom:
                secretKeyRef:
                  name: vulnera-credentials
                  key: api-key
            command:
            - sh
            - -c
            - |
              vulnera analyze /source --all-modules --format json > /results/findings.json
              vulnera report /results/findings.json --format kubernetes
            volumeMounts:
            - name: source
              mountPath: /source
            - name: results
              mountPath: /results
          volumes:
          - name: source
            emptyDir: {}
          - name: results
            persistentVolumeClaim:
              claimName: scan-results-pvc
          restartPolicy: OnFailure
```

## Step 6: Terraform Scanning

### Scan Infrastructure Code

```bash
# Scan Terraform modules for security issues
vulnera analyze ./terraform \
  --format json \
  --output tf-findings.json

# Filter by resource type
vulnera findings filter \
  --input tf-findings.json \
  --resource-type aws_security_group \
  --output sg-issues.json
```

### Terraform Module Registry Integration

```hcl
# main.tf
module "vulnera_scan" {
  source = "git::https://github.com/Vulnera-rs/Vulnera.git//terraform/modules/scanner"

  bucket_name = "my-infrastructure"
  schedule    = "cron(0 2 * * ? *)"  # Daily at 2 AM

  tags = {
    Environment = "production"
  }
}
```

## Step 7: Multi-Cloud Scanning

### Scan All Cloud Resources

```bash
# Scan across multiple cloud providers
vulnera scan-cloud \
  --providers aws,azure,gcp \
  --config multi-cloud-config.toml \
  --parallel 10

# Results aggregated by resource type
vulnera report cloud-findings.json \
  --group-by provider \
  --format html
```

### Configuration Example

```toml
[aws]
regions = ["us-east-1", "us-west-2", "eu-west-1"]
include_s3 = true
include_ec2_images = true
include_rds = true

[azure]
subscriptions = ["prod", "staging"]
include_storage = true

[gcp]
projects = ["project-prod", "project-staging"]
include_storage = true
```

## Step 8: Automated Compliance Reporting

### Generate Compliance Reports

```bash
# SOC 2 Report
vulnera report generate \
  --format soc2 \
  --period month \
  --include-trends \
  --output soc2-compliance.html

# HIPAA Report
vulnera report generate \
  --format hipaa \
  --include-remediation \
  --output hipaa-compliance.html
```

### Email Reports Automatically

```bash
# Schedule weekly reports
vulnera organizations notifications create \
  --org my-cloud-team \
  --name "Weekly Cloud Security" \
  --frequency weekly \
  --day monday \
  --time 9:00 \
  --recipients security@company.com
```

## Common Cloud Workflows

### Daily S3 Compliance Check

```bash
#!/bin/bash
# daily-s3-scan.sh

BUCKET="production-data"
DATE=$(date +%Y-%m-%d)
REPORT_DIR="/var/reports/vulnera"

vulnera analyze s3://${BUCKET} \
  --recursive \
  --format json \
  --output ${REPORT_DIR}/${DATE}-findings.json

# Alert if critical findings
CRITICAL_COUNT=$(jq '[.findings[] | select(.severity=="critical")] | length' ${REPORT_DIR}/${DATE}-findings.json)

if [ $CRITICAL_COUNT -gt 0 ]; then
  echo "Critical findings in $BUCKET: $CRITICAL_COUNT" | \
    mail -s "ALERT: S3 Security Issues" security@company.com
fi
```

### Multi-Region Analysis

```bash
# Parallel scanning across regions
for region in us-east-1 us-west-2 eu-west-1; do
  vulnera analyze-cloud s3 \
    --region $region \
    --output findings-${region}.json &
done
wait
```

## Performance Optimization

### Parallel Processing

```bash
# Scan multiple buckets in parallel
vulnera analyze-cloud s3 \
  --parallel-jobs 10 \
  --max-file-workers 8
```

### Caching

```bash
# Enable caching (24-hour default)
vulnera analyze s3://bucket \
  --cache enabled \
  --cache-ttl 86400
```

### Large Scale Scans

```bash
# For enterprise environments
vulnera analyze-cloud \
  --batch-size 1000 \
  --queue-depth 500 \
  --workers 32 \
  --output enterprise-findings.json
```

## Next Steps

1. **Setup organization for team coordination** → [DevSecOps Quick Start](devsecops-quickstart.md)
2. **Understand quota for large-scale scans** → [Quota & Pricing](../../user-guide/quota-pricing.md)

---

**Need enterprise support?** Contact [sales@vulnera.studio](mailto:sales@vulnera.studio)
