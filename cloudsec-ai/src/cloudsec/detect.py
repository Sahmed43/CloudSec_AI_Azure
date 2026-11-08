from collections import defaultdict
from datetime import datetime, timezone
from .models import Event, Finding

def _time(event: Event) -> datetime:
    try:
        value = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp: {event.timestamp}") from exc
    if value.tzinfo is None:
        raise ValueError("Timestamps must include a timezone")
    return value.astimezone(timezone.utc)

def detect(events: list[Event]) -> list[Finding]:
    """Transparent, educational heuristics; not production threat detection."""
    ordered = sorted(events, key=_time)
    findings = []
    by_actor = defaultdict(list)
    for event in ordered:
        by_actor[(event.user, event.ip)].append(event)
    for (user, ip), actor_events in sorted(by_actor.items()):
        failures = [e for e in actor_events if e.action == "login" and e.result == "failure"]
        # Sliding 10-minute window, 5 or more failed logins from the same user/IP.
        left = 0
        for right, event in enumerate(failures):
            while (_time(event) - _time(failures[left])).total_seconds() > 600:
                left += 1
            if right - left + 1 >= 5:
                count = right - left + 1
                findings.append(Finding("AUTH-001", "high", "Repeated failed sign-ins",
                    f"{count} failed sign-ins within 10 minutes for {user} from {ip}.",
                    [user], [ip], count,
                    "Validate the sign-in activity; consider conditional access, MFA, and account protection."))
                break
    # Privileged changes are review-worthy, not inherently malicious.
    changes = [e for e in ordered if e.action in {"role_assignment", "policy_change"} and e.result == "success"]
    for event in changes:
        findings.append(Finding("PRIV-001", "medium", "Privileged configuration change",
            f"Successful {event.action} affecting {event.resource} by {event.user}.",
            [event.user], [event.ip], 1,
            "Confirm change authorization and review audit records and least-privilege settings."))
    # Successful sign-ins from multiple locations for one user within 30 minutes.
    by_user = defaultdict(list)
    for event in ordered:
        if event.action == "login" and event.result == "success":
            by_user[event.user].append(event)
    for user, successes in sorted(by_user.items()):
        match = None
        for i, first in enumerate(successes):
            for second in successes[i+1:]:
                if (_time(second) - _time(first)).total_seconds() > 1800:
                    break
                if first.location != second.location and first.location and second.location:
                    match = (first, second)
                    break
            if match:
                break
        if match:
            findings.append(Finding("AUTH-002", "medium", "Rapid multi-location sign-ins",
                f"Successful sign-ins for {user} from {match[0].location} and {match[1].location} within 30 minutes; may be legitimate VPN usage.",
                [user], [match[0].ip, match[1].ip], 2,
                "Verify user activity, VPN use, and sign-in risk before taking action."))
    return sorted(findings, key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f.severity], f.rule_id, f.users))
