import json
from pathlib import Path
from .models import Finding

def save_report(findings: list[Finding], destination: str | Path, ai_text: str | None = None) -> None:
    report = {"project": "CloudSec AI", "source": "local heuristic analysis",
              "disclaimer": "Synthetic demo; findings are not confirmed incidents.",
              "findings": [f.to_dict() for f in findings], "ai_assessment": ai_text}
    Path(destination).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
