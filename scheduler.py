import schedule
import time
import yaml
import subprocess
import sys
import os
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()  # Load .env file for AZURE_KEYVAULT_URL and other secrets

from cost_tracker import get_tracker, BudgetExceededError

# --- ROBUST PATH SETUP ---
# Get the directory where this script is running (e.g., /app)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Build the full path to clients.yaml
CONFIG_FILE = os.path.join(BASE_DIR, "config", "clients.yaml")

def load_clients():
    try:
        print(f"📂 Loading config from: {CONFIG_FILE}") # Debug print
        with open(CONFIG_FILE, "r") as f:
            data = yaml.safe_load(f)
            return data.get("clients", [])
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        # Debug: list files to see what Python sees
        config_dir = os.path.join(BASE_DIR, "config")
        if os.path.exists(config_dir):
            print(f"   Files found in {config_dir}: {os.listdir(config_dir)}")
        else:
            print(f"   Directory not found: {config_dir}")
        return []

def run_job(client, site):
    timestamp = datetime.now().strftime("%H:%M")
    client_name = client.get('name', 'Unknown Client')
    site_name = site.get('name', site['url'])
    
    print(f"[{timestamp}] 🚀 Running Argus for {client_name} -> {site_name}...")
    
    cmd = [
        sys.executable, "main.py",
        site['url'],
    ]

    # Only pass --config if explicitly specified, otherwise let main.py auto-detect by domain
    if site.get('rules_config'):
        cmd.extend(["--config", site['rules_config']])
    
    # 1. WEBHOOK LOGIC (Existing)
    webhook = site.get('webhook') or client.get('webhook')
    if webhook:
        cmd.extend(["--webhook", webhook])

    # 2. NOTIFICATION PREFERENCE LOGIC (New)
    # Check Site -> Client -> Default to None (let main.py use global default)
    notify_pass = site.get('notify_on_pass')
    if notify_pass is None:
        notify_pass = client.get('notify_on_pass')
        
    # If explicitly True, pass the flag. If False or None, don't pass it.
    if notify_pass is True:
        cmd.append("--notify-pass")
        
    try:
        # Run with UTF-8 encoding to support emojis
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        
        # HANDLE EXIT CODES
        if result.returncode == 0:
            print(f"✅ PASS: {site_name} (Clean)")
            
        elif result.returncode == 1:
            # Code 1 means the script ran successfully but found a bug
            print(f"❌ FAIL: {site_name} (Defects Found)")
            # We don't need to print stderr here because the notification was already sent
            
        else:
            # Code 2+ means the script actually crashed (Python error)
            print(f"⚠️ CRASH: Argus failed to run for {site['url']}")
            print(f"Error Log:\n{result.stderr}")
            
    except Exception as e:
        print(f"❌ Scheduler Error: {e}")

def print_budget_status():
    """Print current budget status."""
    tracker = get_tracker()
    tracker.reload()  # Reload from disk to see updates from main.py subprocess
    remaining = tracker.get_remaining_budget()
    daily_spend = tracker.get_daily_spend()
    daily_limit = tracker.daily_limit_usd
    
    # Calculate percentage used
    if daily_limit > 0:
        pct_used = (daily_spend / daily_limit) * 100
    else:
        pct_used = 0
    
    # Choose emoji based on budget status
    if pct_used >= 90:
        emoji = "🔴"
    elif pct_used >= 70:
        emoji = "🟡"
    else:
        emoji = "🟢"
    
    print(f"{emoji} Budget: ${daily_spend:.4f} / ${daily_limit:.2f} "
          f"({pct_used:.1f}% used, ${remaining:.4f} remaining)")
    
    return remaining > 0

def run_job(client, site):
    timestamp = datetime.now().strftime("%H:%M")
    client_name = client.get('name', 'Unknown Client')
    site_name = site.get('name', site['url'])
    
    # Check budget before running (reload to see updates from subprocess)
    tracker = get_tracker()
    tracker.reload()
    remaining = tracker.get_remaining_budget()

    if remaining <= 0:
        print(f"[{timestamp}] ⏸️  SKIPPED {site_name} - Budget exhausted")
        return
    
    print(f"[{timestamp}] 🚀 Running Argus for {client_name} -> {site_name}...")
    
    cmd = [
        sys.executable, "main.py",
        site['url'],
    ]

    if site.get('rules_config'):
        cmd.extend(["--config", site['rules_config']])
    
    webhook = site.get('webhook') or client.get('webhook')
    if webhook:
        cmd.extend(["--webhook", webhook])

    notify_pass = site.get('notify_on_pass')
    if notify_pass is None:
        notify_pass = client.get('notify_on_pass')
        
    if notify_pass is True:
        cmd.append("--notify-pass")
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        
        if result.returncode == 0:
            print(f"✅ PASS: {site_name}")
        elif result.returncode == 1:
            print(f"❌ FAIL: {site_name} (Defects Found)")
        else:
            print(f"⚠️ CRASH: Argus failed to run for {site['url']}")
            print(f"Error Log:\n{result.stderr}")

        # Show key diagnostic lines from subprocess
        if result.stdout:
            was_budget_blocked = False
            was_skipped = False

            for line in result.stdout.split('\n'):
                # Detect budget blocking
                if '[BUDGET]' in line and 'skipped' in line.lower():
                    was_budget_blocked = True
                # Detect AI skip (no visual change)
                if 'AI analysis: Skipped' in line:
                    was_skipped = True
                # Show cost and analysis info
                if any(x in line for x in ['[COST]', 'AI analysis:', '[BUDGET]']):
                    print(f"    {line}")

            # Add clear indicator for blocked/skipped jobs
            if was_budget_blocked:
                print(f"    ⚠️  BUDGET BLOCKED - No API call made (cached result returned)")
            elif was_skipped:
                print(f"    💤 SKIPPED - No visual change detected (cached result returned)")
        
        # Print budget status after each job
        print_budget_status()
        print()  # Blank line for readability
            
    except Exception as e:
        print(f"❌ Scheduler Error: {e}")


def start_agent():
    print("=" * 60)
    print("🕵️  Argus Agent Starting...")
    print("=" * 60)
    
    # Show initial budget status
    print("\n💰 Initial Budget Status:")
    print_budget_status()
    
    # Show 7-day summary
    tracker = get_tracker()
    summary = tracker.get_spend_summary(days=7)
    if summary["total_calls"] > 0:
        print(f"   Last 7 days: ${summary['total_usd']:.4f} across {summary['total_calls']} calls")
    print()
    
    clients = load_clients()
    
    job_count = 0
    for client in clients:
        for site in client['sites']:
            minutes = site.get('interval_minutes', 60)
            
            schedule.every(minutes).minutes.do(run_job, client, site)
            
            # Run once immediately on startup
            run_job(client, site) 
            job_count += 1
    
    # Schedule a budget status report every hour
    schedule.every().hour.do(print_budget_status)
            
    print(f"\n📅 Scheduled {job_count} monitoring jobs.")
    print("=" * 60)
    print()
    
    # The Infinite Loop
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    start_agent()