# Security policy

This is an educational prototype, not a production SIEM or incident response system.
Only upload synthetic/non-sensitive logs. Never commit `.env`, secrets, access tokens,
real customer data, or live incident evidence. The AI button sends selected finding
metadata to the configured Azure OpenAI endpoint. AI output is advisory and must be
verified by a human. Do not expose a deployed demo publicly without authentication,
rate limiting, and secret-management controls. For vulnerabilities, open a private
security advisory rather than publishing credentials or exploit details.
