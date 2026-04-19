# vulnera-llm

LLM provider abstractions and auto-fix generation for Vulnera.

## Purpose

Integrate large language models for vulnerability explanations and remediation:

- **Provider abstraction** - Unified interface for multiple LLM backends
- **Resilience layer** - Circuit breaker and exponential backoff
- **Use case orchestration** - Explain, fix, query, enrich

## Supported Providers

- **Google AI (Gemini)** - Primary provider
- **OpenAI** - GPT-4, GPT-3.5-turbo
- **Azure OpenAI** - Enterprise Azure deployment

## Use Cases

1. **ExplainVulnerability** - Natural language explanations of findings
2. **GenerateCodeFix** - Context-aware code remediation
3. **NaturalLanguageQuery** - Chat interface for security questions
4. **EnrichFindings** - Add context and impact analysis

## Important Note

LLM features are **optional post-processing only**. They are never part of detection itself. All security detection happens via deterministic rules (SAST tree-sitter queries, entropy analysis, etc.) before any LLM involvement.

## Configuration

```toml
[llm]
provider = "google_ai"

# Per-use-case model overrides
[llm.models]
generate_fix = "gemini-1.5-pro"
explain = "gemini-1.5-flash"
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
