# IDE Extensions

This guide provides best practices for integrating Vulnera's API into VS Code extensions, IDE plugins, and other development tools.

## Overview

The `/api/v1/dependencies/analyze` endpoint is optimized for extension usage with:

- **Batch Processing** — Analyze multiple dependency files in a single request
- **Detail Levels** — Choose between minimal, standard, or full response data
- **Workspace Context** — Track analysis by workspace paths
- **Caching** — Automatic caching for faster repeated analysis
- **Compact Mode** — Reduced payload size for better performance

## Quick Start

### Basic Request

```typescript
const response = await fetch('http://localhost:3000/api/v1/dependencies/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    files: [{
      file_content: await fs.readFile('package.json', 'utf-8'),
      ecosystem: 'npm',
      filename: 'package.json',
      workspace_path: '/frontend'
    }],
    enable_cache: true
  })
});
```

## Detail Levels

### Minimal

Best for: Status bar indicators, background checks

```typescript
const response = await fetch(
  'http://localhost:3000/api/v1/dependencies/analyze?detail_level=minimal',
  { method: 'POST', headers, body }
);
```

### Standard (Default)

Best for: Inline decorations, quick fixes

```typescript
const response = await fetch(
  'http://localhost:3000/api/v1/dependencies/analyze',
  { method: 'POST', headers, body }
);
```

### Full

Best for: Detailed reports, dependency tree visualization

```typescript
const response = await fetch(
  'http://localhost:3000/api/v1/dependencies/analyze?detail_level=full',
  { method: 'POST', headers, body }
);
```

## Best Practices

### 1. Batch Related Files

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

const response = await analyze({ files });
```

### 2. Use Appropriate Detail Levels

```typescript
// For status bar
const quickScan = await analyze({ detail_level: 'minimal' });
updateStatusBar(`${quickScan.metadata.critical_count} critical`);

// For detailed view
const fullReport = await analyze({ detail_level: 'full' });
showDependencyTree(fullReport.results[0].dependency_graph);
```

### 3. Implement Debouncing

```typescript
let debounceTimer: NodeJS.Timeout;

function onFileChange(filePath: string) {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    analyzeFile(filePath);
  }, 500);
}
```

### 4. Handle Authentication

```typescript
const response = await fetch(url, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': apiKey
  },
  body: JSON.stringify({ files })
});
```

**Rate Limits:**

- Unauthenticated: 10 files per batch
- Authenticated: 16 files per batch

### 5. Cache Results

```typescript
if (result.cache_hit) {
  console.log('Results served from cache');
}

// Client-side caching
const cacheKey = `${ecosystem}:${fileHash}`;
if (clientCache.has(cacheKey)) {
  return clientCache.get(cacheKey);
}
```

### 6. Display Counts

```typescript
const { critical_count, high_count } = response.metadata;

if (critical_count > 0) {
  showNotification(`⚠️ ${critical_count} critical vulnerabilities!`, 'error');
} else if (high_count > 0) {
  showNotification(`⚠ ${high_count} high severity vulnerabilities`, 'warning');
}
```

## Error Handling

```typescript
try {
  const response = await fetch(url, options);
  
  if (!response.ok) {
    if (response.status === 429) {
      showError('Rate limit exceeded. Please authenticate.');
    } else if (response.status === 400) {
      const error = await response.json();
      showError(`Invalid request: ${error.message}`);
    }
    return;
  }
  
  const data = await response.json();
  
  for (const result of data.results) {
    if (result.error) {
      console.error(`Failed to analyze ${result.filename}: ${result.error}`);
    }
  }
} catch (error) {
  showError(`Network error: ${error.message}`);
}
```

## VS Code Extension Example

```typescript
import * as vscode from 'vscode';
import * as path from 'path';

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
    
    this.updateDiagnostics(document, result.vulnerabilities);
    this.updateStatusBar(data.metadata);
  }
  
  private detectEcosystem(fileName: string): string {
    if (fileName.includes('package.json')) return 'npm';
    if (fileName.includes('requirements.txt')) return 'pypi';
    if (fileName.includes('Cargo.toml')) return 'cargo';
    return 'unknown';
  }
}
```

## Supported Ecosystems

| Ecosystem | Aliases | File Patterns |
|-----------|---------|---------------|
| npm | `npm` | `package.json`, `package-lock.json`, `yarn.lock` |
| PyPI | `pypi`, `pip`, `python` | `requirements.txt`, `Pipfile`, `pyproject.toml` |
| Cargo | `cargo`, `rust` | `Cargo.toml`, `Cargo.lock` |
| Maven | `maven` | `pom.xml`, `build.gradle` |
| Go | `go` | `go.mod`, `go.sum` |
| Composer | `packagist`, `composer`, `php` | `composer.json`, `composer.lock` |

## Performance Tips

1. Use `minimal` detail level for background scans
2. Batch files to reduce HTTP overhead
3. Enable caching (default: `true`)
4. Debounce file watchers
5. Authenticate for higher rate limits
6. Implement client-side caching
