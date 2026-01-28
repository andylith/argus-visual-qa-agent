"""
Cost Tracker for Argus
======================
Tracks API spending and enforces budget limits.

This is a prototype of CircuitBreaker-style spending controls,
applied to LLM API calls rather than blockchain transactions.

Features:
- Estimates cost before API calls
- Records actual cost after calls
- Tracks cumulative daily spend
- Blocks calls if budget exceeded
- Persists spend history to JSON

Usage:
    from cost_tracker import CostTracker, BudgetExceededError
    
    tracker = CostTracker.from_config("cost_policy.yaml")
    
    # Before API call
    tracker.check_budget(estimated_cost=0.05)  # Raises if would exceed
    
    # After API call
    tracker.record_spend(
        provider="openai",
        model="gpt-4o-mini",
        input_tokens=1500,
        output_tokens=200,
        purpose="screenshot_analysis"
    )
"""

import json
import os
from datetime import datetime, timezone
from typing import TypedDict
import yaml


# =============================================================================
# PRICING DATA (as of January 2025)
# =============================================================================

PRICING = {
    "openai": {
        "gpt-4o-mini": {
            "input_per_million": 0.15,
            "output_per_million": 0.60,
        },
        "gpt-4o": {
            "input_per_million": 2.50,
            "output_per_million": 10.00,
        },
    },
    "anthropic": {
        "claude-sonnet-4-20250514": {
            "input_per_million": 3.00,
            "output_per_million": 15.00,
        },
        "claude-3-5-sonnet": {  # Alias
            "input_per_million": 3.00,
            "output_per_million": 15.00,
        },
    },
}

# Image token estimation (OpenAI vision)
# Images are tiled into 512x512 chunks, each ~765 tokens
TOKENS_PER_IMAGE_TILE = 765
TILE_SIZE = 512


# =============================================================================
# EXCEPTIONS
# =============================================================================

class BudgetExceededError(Exception):
    """Raised when an API call would exceed the configured budget."""
    
    def __init__(self, message: str, daily_spend: float, daily_limit: float):
        super().__init__(message)
        self.daily_spend = daily_spend
        self.daily_limit = daily_limit


class CostPolicyViolation(Exception):
    """Raised when an API call violates cost policy (e.g., blocked model)."""
    pass


# =============================================================================
# TYPE DEFINITIONS
# =============================================================================

class SpendRecord(TypedDict):
    """A single spend record."""
    timestamp: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    purpose: str


class DailySpend(TypedDict):
    """Daily spend summary."""
    date: str
    total_usd: float
    call_count: int
    records: list[SpendRecord]


# =============================================================================
# COST TRACKER
# =============================================================================

class CostTracker:
    """
    Tracks API spending and enforces budget limits.
    
    This is the core of CircuitBreaker-style controls for API costs.
    """
    
    DEFAULT_DAILY_LIMIT = 5.00  # USD
    DEFAULT_SINGLE_CALL_LIMIT = 1.00  # USD
    SPEND_FILE = "spend_history.json"
    
    def __init__(
        self,
        daily_limit_usd: float = DEFAULT_DAILY_LIMIT,
        single_call_limit_usd: float = DEFAULT_SINGLE_CALL_LIMIT,
        blocked_models: list[str] | None = None,
        spend_file: str = SPEND_FILE,
    ):
        """
        Initialize the cost tracker.
        
        Args:
            daily_limit_usd: Maximum spend per day
            single_call_limit_usd: Maximum spend per API call
            blocked_models: List of model names that are not allowed
            spend_file: Path to persist spend history
        """
        self.daily_limit_usd = daily_limit_usd
        self.single_call_limit_usd = single_call_limit_usd
        self.blocked_models = set(blocked_models or [])
        self.spend_file = spend_file
        self._spend_history = self._load_spend_history()
    
    @classmethod
    def from_config(cls, config_path: str) -> "CostTracker":
        """
        Create a CostTracker from a YAML config file.
        
        Expected YAML structure:
            daily_limit_usd: 5.00
            single_call_limit_usd: 1.00
            blocked_models:
              - "gpt-4-turbo"
        
        Args:
            config_path: Path to the YAML config file
            
        Returns:
            Configured CostTracker instance
        """
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            config = {}
        
        return cls(
            daily_limit_usd=config.get("daily_limit_usd", cls.DEFAULT_DAILY_LIMIT),
            single_call_limit_usd=config.get("single_call_limit_usd", cls.DEFAULT_SINGLE_CALL_LIMIT),
            blocked_models=config.get("blocked_models", []),
            spend_file=config.get("spend_file", cls.SPEND_FILE),
        )
    
    def _load_spend_history(self) -> dict[str, DailySpend]:
        """Load spend history from JSON file."""
        try:
            with open(self.spend_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def _save_spend_history(self) -> None:
        """Save spend history to JSON file."""
        with open(self.spend_file, "w", encoding="utf-8") as f:
            json.dump(self._spend_history, f, indent=2)

    def reload(self) -> None:
        """Reload spend history from disk. Call this to see updates from other processes."""
        self._spend_history = self._load_spend_history()
    
    def _get_today_key(self) -> str:
        """Get today's date as a key (YYYY-MM-DD)."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    def _get_today_spend(self) -> DailySpend:
        """Get or create today's spend record."""
        today = self._get_today_key()
        if today not in self._spend_history:
            self._spend_history[today] = {
                "date": today,
                "total_usd": 0.0,
                "call_count": 0,
                "records": [],
            }
        return self._spend_history[today]
    
    def get_daily_spend(self) -> float:
        """Get total spend for today in USD."""
        return self._get_today_spend()["total_usd"]
    
    def get_remaining_budget(self) -> float:
        """Get remaining budget for today in USD."""
        return max(0, self.daily_limit_usd - self.get_daily_spend())
    
    def estimate_cost(
        self,
        provider: str,
        model: str,
        estimated_input_tokens: int,
        estimated_output_tokens: int = 500,
    ) -> float:
        """
        Estimate the cost of an API call.
        
        Args:
            provider: "openai" or "anthropic"
            model: Model name (e.g., "gpt-4o-mini")
            estimated_input_tokens: Estimated input token count
            estimated_output_tokens: Estimated output token count
            
        Returns:
            Estimated cost in USD
        """
        pricing = PRICING.get(provider, {}).get(model)
        if not pricing:
            # Unknown model - use conservative estimate
            return 0.10  # Assume $0.10 as fallback
        
        input_cost = (estimated_input_tokens / 1_000_000) * pricing["input_per_million"]
        output_cost = (estimated_output_tokens / 1_000_000) * pricing["output_per_million"]
        
        return input_cost + output_cost
    
    def estimate_image_tokens(self, image_bytes: bytes) -> int:
        """
        Estimate token count for an image (OpenAI vision model).
        
        OpenAI tiles images into 512x512 chunks, each ~765 tokens.
        
        Args:
            image_bytes: The image data
            
        Returns:
            Estimated token count
        """
        from PIL import Image
        import io
        
        try:
            image = Image.open(io.BytesIO(image_bytes))
            width, height = image.size
            
            # Calculate number of tiles
            tiles_x = (width + TILE_SIZE - 1) // TILE_SIZE
            tiles_y = (height + TILE_SIZE - 1) // TILE_SIZE
            total_tiles = tiles_x * tiles_y
            
            return total_tiles * TOKENS_PER_IMAGE_TILE
        except Exception:
            # Conservative fallback for a typical full-page screenshot
            return 3000
    
    def check_budget(
        self,
        provider: str,
        model: str,
        estimated_cost: float | None = None,
        estimated_input_tokens: int | None = None,
        estimated_output_tokens: int = 500,
    ) -> float:
        """
        Check if an API call is within budget. Raises if not.
        
        Args:
            provider: "openai" or "anthropic"
            model: Model name
            estimated_cost: Pre-calculated cost (if known)
            estimated_input_tokens: Input tokens (used if estimated_cost not provided)
            estimated_output_tokens: Output tokens (used if estimated_cost not provided)
            
        Returns:
            The estimated cost if approved
            
        Raises:
            CostPolicyViolation: If model is blocked
            BudgetExceededError: If call would exceed budget
        """
        # Check blocked models
        if model in self.blocked_models:
            raise CostPolicyViolation(f"Model '{model}' is blocked by cost policy")
        
        # Calculate estimated cost if not provided
        if estimated_cost is None:
            if estimated_input_tokens is None:
                raise ValueError("Must provide either estimated_cost or estimated_input_tokens")
            estimated_cost = self.estimate_cost(
                provider, model, estimated_input_tokens, estimated_output_tokens
            )
        
        # Check single call limit
        if estimated_cost > self.single_call_limit_usd:
            raise BudgetExceededError(
                f"Estimated cost ${estimated_cost:.4f} exceeds single call limit ${self.single_call_limit_usd:.2f}",
                daily_spend=self.get_daily_spend(),
                daily_limit=self.daily_limit_usd,
            )
        
        # Check daily limit
        daily_spend = self.get_daily_spend()
        if daily_spend + estimated_cost > self.daily_limit_usd:
            raise BudgetExceededError(
                f"Call would exceed daily budget. Current: ${daily_spend:.4f}, "
                f"Estimated: ${estimated_cost:.4f}, Limit: ${self.daily_limit_usd:.2f}",
                daily_spend=daily_spend,
                daily_limit=self.daily_limit_usd,
            )
        
        return estimated_cost
    
    def calculate_actual_cost(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """
        Calculate actual cost from token counts.
        
        Args:
            provider: "openai" or "anthropic"
            model: Model name
            input_tokens: Actual input token count
            output_tokens: Actual output token count
            
        Returns:
            Actual cost in USD
        """
        pricing = PRICING.get(provider, {}).get(model)
        if not pricing:
            return 0.0
        
        input_cost = (input_tokens / 1_000_000) * pricing["input_per_million"]
        output_cost = (output_tokens / 1_000_000) * pricing["output_per_million"]
        
        return input_cost + output_cost
    
    def record_spend(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        purpose: str = "api_call",
    ) -> float:
        """
        Record actual spend from an API call.
        
        Args:
            provider: "openai" or "anthropic"
            model: Model name
            input_tokens: Actual input token count
            output_tokens: Actual output token count
            purpose: Description of what the call was for
            
        Returns:
            The actual cost in USD
        """
        cost = self.calculate_actual_cost(provider, model, input_tokens, output_tokens)
        
        today = self._get_today_spend()
        today["total_usd"] += cost
        today["call_count"] += 1
        today["records"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost,
            "purpose": purpose,
        })
        
        self._save_spend_history()
        
        return cost
    
    def get_spend_summary(self, days: int = 7) -> dict:
        """
        Get a summary of recent spending.
        
        Args:
            days: Number of days to include
            
        Returns:
            Summary dict with totals and daily breakdown
        """
        from datetime import timedelta
        
        today = datetime.now(timezone.utc).date()
        summary = {
            "period_days": days,
            "total_usd": 0.0,
            "total_calls": 0,
            "daily_limit_usd": self.daily_limit_usd,
            "remaining_today_usd": self.get_remaining_budget(),
            "by_day": {},
            "by_model": {},
        }
        
        for i in range(days):
            date_key = (today - timedelta(days=i)).strftime("%Y-%m-%d")
            if date_key in self._spend_history:
                day_data = self._spend_history[date_key]
                summary["total_usd"] += day_data["total_usd"]
                summary["total_calls"] += day_data["call_count"]
                summary["by_day"][date_key] = {
                    "total_usd": day_data["total_usd"],
                    "call_count": day_data["call_count"],
                }
                
                # Aggregate by model
                for record in day_data["records"]:
                    model_key = f"{record['provider']}/{record['model']}"
                    if model_key not in summary["by_model"]:
                        summary["by_model"][model_key] = {"total_usd": 0.0, "call_count": 0}
                    summary["by_model"][model_key]["total_usd"] += record["cost_usd"]
                    summary["by_model"][model_key]["call_count"] += 1
        
        return summary
    
    def format_summary(self, days: int = 7) -> str:
        """
        Get a human-readable summary of recent spending.
        
        Args:
            days: Number of days to include
            
        Returns:
            Formatted string
        """
        summary = self.get_spend_summary(days)
        
        lines = [
            f"\n{'='*50}",
            f"COST TRACKER SUMMARY (Last {days} days)",
            f"{'='*50}",
            f"Total Spend:     ${summary['total_usd']:.4f}",
            f"Total API Calls: {summary['total_calls']}",
            f"Daily Limit:     ${summary['daily_limit_usd']:.2f}",
            f"Remaining Today: ${summary['remaining_today_usd']:.4f}",
        ]
        
        if summary["by_model"]:
            lines.append(f"\nBy Model:")
            for model, data in sorted(summary["by_model"].items()):
                lines.append(f"  {model}: ${data['total_usd']:.4f} ({data['call_count']} calls)")
        
        if summary["by_day"]:
            lines.append(f"\nBy Day:")
            for date, data in sorted(summary["by_day"].items(), reverse=True):
                lines.append(f"  {date}: ${data['total_usd']:.4f} ({data['call_count']} calls)")
        
        lines.append(f"{'='*50}\n")
        
        return "\n".join(lines)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

# Global tracker instance (lazy initialized)
_global_tracker: CostTracker | None = None


def get_tracker(config_path: str = "cost_policy.yaml") -> CostTracker:
    """Get or create the global cost tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = CostTracker.from_config(config_path)
    return _global_tracker


def check_and_record(
    provider: str,
    model: str,
    image_bytes: bytes | None = None,
    text_tokens: int = 500,
    purpose: str = "api_call",
) -> "CostGuard":
    """
    Context manager for cost-controlled API calls.
    
    Usage:
        with check_and_record("openai", "gpt-4o-mini", image_bytes, purpose="screenshot_analysis") as guard:
            response = client.chat.completions.create(...)
            guard.set_usage(response.usage.prompt_tokens, response.usage.completion_tokens)
    """
    return CostGuard(get_tracker(), provider, model, image_bytes, text_tokens, purpose)


class CostGuard:
    """Context manager for cost-controlled API calls."""
    
    def __init__(
        self,
        tracker: CostTracker,
        provider: str,
        model: str,
        image_bytes: bytes | None = None,
        text_tokens: int = 500,
        purpose: str = "api_call",
    ):
        self.tracker = tracker
        self.provider = provider
        self.model = model
        self.purpose = purpose
        self.input_tokens = 0
        self.output_tokens = 0
        self._estimated_cost = 0.0
        
        # Estimate input tokens
        estimated_input = text_tokens
        if image_bytes:
            estimated_input += tracker.estimate_image_tokens(image_bytes)
        self._estimated_input = estimated_input
    
    def __enter__(self) -> "CostGuard":
        # Check budget before call
        self._estimated_cost = self.tracker.check_budget(
            self.provider,
            self.model,
            estimated_input_tokens=self._estimated_input,
        )
        return self
    
    def set_usage(self, input_tokens: int, output_tokens: int) -> None:
        """Set actual token usage from API response."""
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # Record actual spend if call succeeded
        if exc_type is None and (self.input_tokens > 0 or self.output_tokens > 0):
            actual_cost = self.tracker.record_spend(
                self.provider,
                self.model,
                self.input_tokens,
                self.output_tokens,
                self.purpose,
            )
            print(f"[COST] {self.provider}/{self.model}: ${actual_cost:.4f} "
                  f"(in: {self.input_tokens}, out: {self.output_tokens})")


if __name__ == "__main__":
    # Demo usage
    tracker = CostTracker(daily_limit_usd=5.00)
    
    print("Estimating cost for gpt-4o-mini with ~3000 input tokens:")
    est = tracker.estimate_cost("openai", "gpt-4o-mini", 3000, 500)
    print(f"  Estimated: ${est:.4f}")
    
    print("\nEstimating cost for gpt-4o with ~3000 input tokens:")
    est = tracker.estimate_cost("openai", "gpt-4o", 3000, 500)
    print(f"  Estimated: ${est:.4f}")
    
    print("\nSimulating some API calls...")
    tracker.record_spend("openai", "gpt-4o-mini", 2500, 400, "test_call_1")
    tracker.record_spend("openai", "gpt-4o-mini", 3000, 500, "test_call_2")
    tracker.record_spend("openai", "gpt-4o", 2800, 450, "verification")
    
    print(tracker.format_summary())
