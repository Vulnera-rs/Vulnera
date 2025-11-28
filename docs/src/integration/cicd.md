# CI/CD Integration

Integrate Vulnera into your CI/CD pipelines for automated security scanning.

## GitHub Actions

### Basic Workflow

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnera-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Vulnera CLI
        run: |
          curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-amd64 -o vulnera
          chmod +x vulnera
      
      - name: Run vulnerability scan
        env:
          VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
          VULNERA_CI: "true"
        run: |
          ./vulnera analyze . --format sarif > results.sarif
        continue-on-error: true
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Block on Critical Vulnerabilities

```yaml
name: Security Gate

on: [pull_request]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Vulnera CLI
        run: |
          curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-amd64 -o vulnera
          chmod +x vulnera
      
      - name: Run security scan
        env:
          VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
          VULNERA_CI: "true"
        run: |
          ./vulnera analyze . --severity critical
          # Exit code 1 if critical vulnerabilities found
```

## GitLab CI

```yaml
stages:
  - test
  - security

security-scan:
  stage: security
  image: rust:latest
  variables:
    VULNERA_CI: "true"
    VULNERA_API_KEY: $VULNERA_API_KEY
  script:
    - cargo install --git https://github.com/k5602/Vulnera --features cli
    - vulnera-rust analyze . --format json > vulnera-report.json
  artifacts:
    reports:
      security: vulnera-report.json
    paths:
      - vulnera-report.json
  allow_failure: false
```

## Azure DevOps

```yaml
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: Bash@3
    displayName: 'Install Vulnera'
    inputs:
      targetType: 'inline'
      script: |
        curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-amd64 -o vulnera
        chmod +x vulnera

  - task: Bash@3
    displayName: 'Run Security Scan'
    env:
      VULNERA_API_KEY: $(VULNERA_API_KEY)
      VULNERA_CI: 'true'
    inputs:
      targetType: 'inline'
      script: |
        ./vulnera analyze . --format sarif > $(Build.ArtifactStagingDirectory)/results.sarif

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)/results.sarif'
      artifactName: 'security-results'
```

## Jenkins

### Jenkinsfile

```groovy
pipeline {
    agent any
    
    environment {
        VULNERA_API_KEY = credentials('vulnera-api-key')
        VULNERA_CI = 'true'
    }
    
    stages {
        stage('Install Vulnera') {
            steps {
                sh '''
                    curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-amd64 -o vulnera
                    chmod +x vulnera
                '''
            }
        }
        
        stage('Security Scan') {
            steps {
                sh './vulnera analyze . --format json > vulnera-report.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'vulnera-report.json'
                }
            }
        }
        
        stage('Security Gate') {
            steps {
                sh './vulnera analyze . --severity high'
            }
        }
    }
}
```

## Pre-commit Hook

### .pre-commit-config.yaml

```yaml
repos:
  - repo: local
    hooks:
      - id: vulnera-secrets
        name: Check for secrets
        entry: vulnera-rust secrets . --ci
        language: system
        pass_filenames: false
        always_run: true
```

### Manual Git Hook

`.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

echo "Running Vulnera security checks..."

# Check for secrets (critical only)
vulnera-rust --ci secrets . --severity critical
if [ $? -ne 0 ]; then
    echo "❌ Secrets detected! Please remove them before committing."
    exit 1
fi

echo "✅ Security checks passed"
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | No issues found | Continue pipeline |
| 1 | Vulnerabilities found | Fail or warn based on config |
| 2 | Configuration error | Fix configuration |
| 3 | Network error | Retry or use offline mode |
| 4 | Quota exceeded | Authenticate or wait |
| 5 | Authentication required | Add API key |
| 99 | Internal error | Report bug |

## Exit Code Handling

```bash
#!/bin/bash

vulnera-rust --ci deps . --severity high
exit_code=$?

case $exit_code in
    0)
        echo "✅ No vulnerabilities found"
        ;;
    1)
        echo "❌ Vulnerabilities found - failing build"
        exit 1
        ;;
    4)
        echo "⚠️ Quota exceeded - skipping scan"
        ;;
    *)
        echo "⚠️ Error occurred (exit code: $exit_code)"
        exit 1
        ;;
esac
```

## Output Formats

### SARIF (Recommended for GitHub/Azure)

```bash
vulnera-rust --format sarif analyze . > results.sarif
```

### JSON (Machine-readable)

```bash
vulnera-rust --format json analyze . > results.json
```

### Table (Human-readable)

```bash
vulnera-rust analyze .
```

## Best Practices

1. **Use API keys** for CI/CD to get higher rate limits
2. **Cache results** between runs when possible
3. **Set severity thresholds** appropriate for your risk tolerance
4. **Use SARIF format** for integration with GitHub Code Scanning
5. **Run in parallel** with other tests to reduce total build time
6. **Block on critical/high** vulnerabilities in production branches
7. **Allow warnings** on lower severity for development branches

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VULNERA_API_KEY` | API key for authentication |
| `VULNERA_CI` | Set to `true` for CI mode (cleaner output) |
| `VULNERA_OFFLINE` | Set to `true` for offline mode |
| `VULNERA__SERVER__PORT` | Override server port |
