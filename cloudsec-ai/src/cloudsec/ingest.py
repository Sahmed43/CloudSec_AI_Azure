import csv
from pathlib import Path
from .models import Event

REQUIRED = {"timestamp", "user", "ip", "action", "result", "resource", "location"}
MAX_EVENTS = 10000

def load_events(path: str | Path) -> list[Event]:
    path = Path(path)
    if path.stat().st_size > 5_000_000:
        raise ValueError("CSV exceeds 5 MB safety limit")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not REQUIRED.issubset(reader.fieldnames):
            raise ValueError(f"CSV requires columns: {', '.join(sorted(REQUIRED))}")
        events = []
        for row in reader:
            if len(events) >= MAX_EVENTS:
                raise ValueError("CSV exceeds 10,000-event safety limit")
            if any(row.get(key) is None for key in REQUIRED):
                raise ValueError("Malformed CSV row")
            events.append(Event(**{key: row[key].strip() for key in REQUIRED}))
    return events
