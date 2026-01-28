# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Argus is a visual QA agent that screenshots websites and uses Vision LLMs (GPT-4o/Claude) to detect critical layout bugs that would block usability. It's designed to run as a scheduled monitoring service.

## Common Commands

```bash
# Single URL analysis
python main.py https://example.com
python main.py https://example.com --model high-res    # Use GPT-4o instead of GPT-4o-mini
python main.py https://example.com --force             # Force AI analysis even if no visual change
python main.py https://example.com --provider anthropic

# Check budget status
python main.py --budget-status

# Run the scheduler (continuous monitoring)
python scheduler.py

# Docker deployment
docker build -t argus .
docker run -e OPENAI_API_KEY=sk-xxx argus
```

## Architecture

### Smart Monitor Flow (main.py)

1. **Screenshot capture** via Playwright (headless Chromium)
2. **Perceptual hash comparison** (pHash) against previous screenshot
3. **Conditional AI analysis**: Skip if no visual change detected (saves cost)
4. **Heartbeat audit**: Force AI check every 60 minutes regardless of visual change
5. **Verification flow**: When fast model (gpt-4o-mini) reports FAIL, automatically re-verify with high-res model (gpt-4o) to eliminate false positives
6. **Agent Memory**: When high-res overrules fast model, save those issues to `monitor_state.json` so fast model won't flag them again

### Key Files

- `main.py` - CLI tool and core analysis logic (~1500 lines)
- `scheduler.py` - Job orchestration, reads `config/clients.yaml`, runs main.py as subprocess
- `cost_tracker.py` - Budget enforcement with daily limits, reads `cost_policy.yaml`
- `notifier.py` - Webhook notifications (Slack, Discord, Teams)
- `monitor_state.json` - Persisted state: last screenshots, learned false positives per URL
- `config/clients.yaml` - Client/site definitions with intervals and webhooks
- `config/*.yaml` - Site-specific rules (auto-detected by domain)

### Cost Control System

The `cost_tracker.py` implements CircuitBreaker-style spending controls:

- Estimates cost before each API call
- Blocks calls if they would exceed daily limit (configured in `cost_policy.yaml`)
- Records actual spend to `spend_history.json`
- Scheduler reloads tracker state to see subprocess updates

### Agent Memory (Learned False Positives)

Stored in `monitor_state.json` under each URL's `learned_false_positives` array. The `build_learned_context()` function injects these into the prompt as override instructions. **Security note**: This data flows directly into LLM prompts without sanitization - potential prompt injection vector.

### Exit Codes

- `0` = PASS (no defects found)
- `1` = FAIL (defects detected)
- `2` = Error (crash, invalid config, budget exceeded)

## Environment Variables

```bash
OPENAI_API_KEY          # Required for OpenAI provider
ANTHROPIC_API_KEY       # Required for Anthropic provider
AZURE_KEYVAULT_URL      # Optional: Azure Key Vault URL for secrets (e.g., https://argus-secrets-dev.vault.azure.net)
```

When `AZURE_KEYVAULT_URL` is set, secrets are fetched from Key Vault first, then fall back to environment variables. Key Vault secret names use hyphens (e.g., `OPENAI-API-KEY`).

## Site Configuration

Site-specific rules are YAML files in `config/` named by domain (e.g., `www.bbc.com.yaml`):

```yaml
url: "https://www.bbc.com"
rules:
  - "IGNORE: Cookie consent popup"
  - "ALLOW: Text overlaying video thumbnails"
  - "CRITICAL: Navigation menu must never be obscured"
```

Auto-detected by domain when running `python main.py <url>`.
