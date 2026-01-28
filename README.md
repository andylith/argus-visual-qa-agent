# Argus

A visual QA agent that screenshots websites and uses GPT-4 Vision to detect critical layout bugs that would block usability.

## What It Does

Argus captures screenshots of websites and uses vision LLMs (GPT-4o or Claude) to identify layout defects like:

- Overlapping elements that hide content
- Buttons or controls cut off by the viewport
- Elements that prevent user interaction

It's designed to run as a scheduled monitoring service, comparing screenshots over time and only running AI analysis when visual changes are detected.

## Features

- **Smart monitoring**: Uses perceptual hashing to skip AI analysis when pages haven't changed
- **Cost control**: Built-in budget tracking with daily spend limits
- **Dual-model verification**: Fast model flags issues, high-res model confirms (reduces false positives)
- **Agent memory**: Learns from verification to avoid re-flagging known false positives
- **Multi-platform notifications**: Slack, Discord, Teams, or generic webhooks

## Security Research

This project was built to explore prompt injection vulnerabilities in AI agents. See [SECURITY_RESEARCH.md](SECURITY_RESEARCH.md) for documented attacks and mitigations.

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/argus.git
cd argus

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium

# Set up environment
cp .env.example .env
# Edit .env and add your OpenAI or Anthropic API key
```

## Usage

### Single URL Analysis

```bash
# Basic analysis
python main.py https://example.com

# Use high-res model (GPT-4o instead of GPT-4o-mini)
python main.py https://example.com --model high-res

# Force analysis even if no visual change
python main.py https://example.com --force

# Use Anthropic instead of OpenAI
python main.py https://example.com --provider anthropic

# Save screenshot
python main.py https://example.com --save-screenshot screenshot.png
```

### Scheduled Monitoring

```bash
# Configure clients in config/clients.yaml, then:
python scheduler.py
```

### Check Budget

```bash
python main.py --budget-status
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes* | OpenAI API key |
| `ANTHROPIC_API_KEY` | Yes* | Anthropic API key |
| `AZURE_KEYVAULT_URL` | No | Azure Key Vault URL for secrets |

*At least one API key required.

### Site-Specific Rules

Create YAML files in `config/` named by domain:

```yaml
# config/www.example.com.yaml
url: "https://www.example.com"
rules:
  - "IGNORE: Cookie consent banners"
  - "ALLOW: Carousel arrows on image edges"
  - "CRITICAL: Main navigation must be visible"
```

### Cost Policy

Edit `cost_policy.yaml` to set daily spend limits:

```yaml
daily_limit_usd: 5.00
models:
  gpt-4o-mini:
    max_calls_per_day: 100
  gpt-4o:
    max_calls_per_day: 20
```

## Output

Returns JSON with this structure:

```json
{
  "status": "PASS | FAIL",
  "confidence_score": 0-100,
  "defects": [
    {
      "element": "Login Button",
      "issue": "Cut off by viewport edge",
      "severity": "CRITICAL | MAJOR"
    }
  ],
  "reasoning": "Explanation of the analysis"
}
```

Exit codes: `0` = PASS, `1` = FAIL, `2` = Error

## License

MIT - see [LICENSE](LICENSE)
