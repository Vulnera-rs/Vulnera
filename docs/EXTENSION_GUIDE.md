# Extension Integration Guide

This guide provides best practices for integrating Vulnera's dependency analysis API into VS Code extensions, IDE plugins, and other development tools.

## Quick Start

The `/api/v1/dependencies/analyze` endpoint is optimized for extension usage with the following features:

- **Batch Processing**: Analyze multiple dependency files in a single request
- **Detail Levels**: Choose between minimal, standard, or full response data
- **Workspace Context**: Track analysis by workspace paths
- **Caching**: Automatic caching for faster repeated analysis
- **Compact Mode**: Reduced payload size for better performance

## Endpoint Overview

```
POST /api/v1/dependencies/analyze
```

### Request Structure

```json
{
  "files": [
    {
      "file_content": "{\"dependencies\": {\"express\": \"4.17.1\"}}",
      "ecosystem": "npm",
      "filename": "package.json",
      "workspace_path": "/workspace/frontend"
    }
  ],
  "enable_cache": true,
  "compact_mode": false
}
```

### Query Parameters

- `detail_level` (optional): `minimal`, `standard` (default), or `full`

## Detail Levels

### Minimal

Best for: Quick scans, background checks, status bar indicators

**Includes:**

- Vulnerabilities list only
- Basic metadata (counts, severity breakdown)

**Example:**

```bash
curl -X POST "http://localhost:3000/api/v1/dependencies/analyze?detail_level=minimal" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [{
      "file_content": "express@4.17.1",
      "ecosystem": "npm",
      "filename": "package.json"
    }]
  }'
```

### Standard (Default)

Best for: Interactive analysis, inline decorations, quick fixes

**Includes:**

- Vulnerabilities list
- Package list
- Version recommendations (nearest safe, latest safe)
- Complete metadata

**Example:**

```bash
curl -X POST "http://localhost:3000/api/v1/dependencies/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [{
      "file_content": "express@4.17.1\nlodash@4.17.20",
      "ecosystem": "npm",
      "filename": "package.json",
      "workspace_path": "/workspace/api"
    }]
  }'
```

### Full

Best for: Detailed reports, dependency tree visualization

**Includes:**

- All standard data
- Complete dependency graph (nodes and edges)
- Transitive dependency information

**Example:**

```bash
curl -X POST "http://localhost:3000/api/v1/dependencies/analyze?detail_level=full" \
  -H "Content-Type: application/json" \
  -d '{
    "files": [{
      "file_content": "...",
      "ecosystem": "npm"
    }]
  }'
```

## Response Structure

```json
{
  "results": [
    {
      "filename": "package.json",
      "ecosystem": "npm",
      "workspace_path": "/workspace/frontend",
      "vulnerabilities": [...],
      "packages": [...],
      "version_recommendations": [...],
      "metadata": {
        "total_packages": 25,
        "vulnerable_packages": 3,
        "total_vulnerabilities": 5,
        "severity_breakdown": {
          "critical": 1,
          "high": 2,
          "medium": 1,
          "low": 1
        },
        "analysis_duration_ms": 1250,
        "sources_queried": ["OSV", "NVD"]
      },
      "cache_hit": false
    }
  ],
  "metadata": {
    "total_files": 1,
    "successful": 1,
    "failed": 0,
    "duration_ms": 1250,
    "total_vulnerabilities": 5,
    "total_packages": 25,
    "critical_count": 1,
    "high_count": 2
  }
}
```

## Extension Best Practices

### 1. Batch Related Files

Group related dependency files (e.g., frontend + backend) in a single request:

```typescript
const files = [
  {
    file_content: await fs.readFile('frontend/package.json', 'utf-8'),
    ecosystem: 'npm',
    filename: 'package.json',
    workspace_path: '/frontend'
  },
  {
    file_content: await fs.readFile('backend/requirements.txt', 'utf-8'),
    ecosystem: 'pypi',
    filename: 'requirements.txt',
    workspace_path: '/backend'
  }
];

const response = await fetch('http://localhost:3000/api/v1/dependencies/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ files })
});
```

### 2. Use Appropriate Detail Levels

- **Status bar / Badge**: `minimal`
- **Inline decorations**: `standard`
- **Full report view**: `full`

```typescript
// For status bar
const quickScan = await analyze({ detail_level: 'minimal' });
updateStatusBar(`${quickScan.metadata.critical_count} critical vulnerabilities`);

// For detailed view
const fullReport = await analyze({ detail_level: 'full' });
showDependencyTree(fullReport.results[0].dependency_graph);
```

### 3. Leverage Workspace Paths

Track files by workspace path for better organization:

```typescript
const results = response.results.reduce((acc, result) => {
  acc[result.workspace_path] = result;
  return acc;
}, {});

// Update decorations per workspace
for (const [path, result] of Object.entries(results)) {
  updateDecorations(path, result.vulnerabilities);
}
```

### 4. Handle Authentication

For higher rate limits, use API key authentication:

```typescript
const response = await fetch('http://localhost:3000/api/v1/dependencies/analyze', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': apiKey  // or 'Authorization': `ApiKey ${apiKey}`
  },
  body: JSON.stringify({ files })
});
```

**Rate Limits:**

- Unauthenticated: 10 files per batch
- Authenticated: 16 files per batch (2x max_concurrent_packages)

### 5. Implement Debouncing

Avoid excessive API calls when files change:

```typescript
let debounceTimer;

function onFileChange(filePath) {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    analyzeFile(filePath);
  }, 500); // Wait 500ms after last change
}
```

### 6. Cache Results Intelligently

The API provides cache hints:

```typescript
if (result.cache_hit) {
  console.log('Results served from cache');
}

// Also cache on client side
const cacheKey = `${ecosystem}:${fileHash}`;
if (clientCache.has(cacheKey)) {
  return clientCache.get(cacheKey);
}
```

### 7. Display Quick Reference Counts

Use metadata for instant feedback:

```typescript
const { critical_count, high_count, total_vulnerabilities } = response.metadata;

if (critical_count > 0) {
  showNotification(`⚠️ ${critical_count} critical vulnerabilities found!`, 'error');
} else if (high_count > 0) {
  showNotification(`⚠ ${high_count} high severity vulnerabilities`, 'warning');
}
```

## Supported Ecosystems

- `npm` - Node.js (package.json, package-lock.json, yarn.lock)
- `pypi` / `pip` / `python` - Python (requirements.txt, Pipfile, pyproject.toml)
- `cargo` / `rust` - Rust (Cargo.toml, Cargo.lock)
- `maven` - Java (pom.xml, build.gradle)
- `go` - Go (go.mod, go.sum)
- `packagist` / `composer` / `php` - PHP (composer.json, composer.lock)

## Error Handling

```typescript
try {
  const response = await fetch(url, options);
  
  if (!response.ok) {
    if (response.status === 429) {
      showError('Rate limit exceeded. Please authenticate or try again later.');
    } else if (response.status === 400) {
      const error = await response.json();
      showError(`Invalid request: ${error.message}`);
    } else {
      showError('Analysis failed. Please try again.');
    }
    return;
  }
  
  const data = await response.json();
  
  // Check individual file results
  for (const result of data.results) {
    if (result.error) {
      console.error(`Failed to analyze ${result.filename}: ${result.error}`);
    }
  }
} catch (error) {
  showError(`Network error: ${error.message}`);
}
```

## Performance Tips

1. **Use minimal detail level** for background scans
2. **Batch files** to reduce HTTP overhead
3. **Enable caching** (default: true)
4. **Debounce file watchers** to avoid spam
5. **Use compact mode** when available (reduces payload size)
6. **Authenticate** for higher rate limits
7. **Implement client-side caching** for instant responses

## Example: VS Code Extension

```typescript
import * as vscode from 'vscode';

class VulneraExtension {
  private apiUrl = 'http://localhost:3000/api/v1/dependencies/analyze';
  
  async analyzeDependencies(document: vscode.TextDocument) {
    const files = [{
      file_content: document.getText(),
      ecosystem: this.detectEcosystem(document.fileName),
      filename: path.basename(document.fileName),
      workspace_path: vscode.workspace.asRelativePath(document.fileName)
    }];
    
    const response = await fetch(this.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files, enable_cache: true })
    });
    
    const data = await response.json();
    const result = data.results[0];
    
    // Update diagnostics
    this.updateDiagnostics(document, result.vulnerabilities);
    
    // Update status bar
    this.updateStatusBar(data.metadata);
  }
  
  private detectEcosystem(fileName: string): string {
    if (fileName.includes('package.json')) return 'npm';
    if (fileName.includes('requirements.txt')) return 'pypi';
    if (fileName.includes('Cargo.toml')) return 'cargo';
    // ... more ecosystems
    return 'unknown';
  }
}
```

## Configuration

Update `config/default.toml`:

```toml
[analysis]
extension_batch_size_limit = 25
enable_response_compression = true
cache_extension_results = true
```

## Support

For issues or feature requests, visit: <https://github.com/k5602/Vulnera>
