"""Agentized CFW triage building blocks.

The package is intentionally side-effect free: importing it must not load
Tencent Cloud credentials, call LLM providers, or mutate local state. Existing
hourly scripts can adopt these modules incrementally.
"""

