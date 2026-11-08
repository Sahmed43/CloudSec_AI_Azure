from dataclasses import asdict, dataclass

@dataclass(frozen=True)
class Event:
    timestamp: str
    user: str
    ip: str
    action: str
    result: str
    resource: str
    location: str

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    users: list[str]
    ips: list[str]
    evidence_count: int
    recommended_action: str

    def to_dict(self) -> dict:
        return asdict(self)
