from django.utils import timezone
from datetime import datetime

def format_timestamp(dt):
    """Format a timestamp to use January 1st, 2025 as the date while keeping the original time."""
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
    return datetime(2025, 1, 1, dt.hour, dt.minute, dt.second).strftime("%Y-%m-%d %H:%M:%S") 