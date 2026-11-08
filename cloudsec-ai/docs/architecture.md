# Architecture and trust boundaries

```mermaid
flowchart TD
    A[Synthetic CSV security events] --> B[CSV schema and size validation]
    B --> C[Python deterministic heuristics]
    C --> D[Streamlit dashboard / CLI JSON report]
    C --> E{Analyst clicks AI Analysis?}
    E -->|Yes| F[Minimized findings JSON]
    F --> G[Azure OpenAI chat completions]
    G --> H[Analyst reviews advisory text]
```

**Trust boundary:** The CSV and any field values are untrusted. Heuristic findings are
not proof of compromise. The language model only provides advisory narrative; it
cannot execute remediation. The app does not connect to Sentinel or ingest live Azure logs.

**Production hardening ideas:** Microsoft Entra ID authentication, Azure Key Vault,
managed identity where supported, network restrictions, rate limits, PII redaction,
structured model-output validation, audit trails, observability, and approval workflows.
