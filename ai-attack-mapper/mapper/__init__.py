"""
mapper/

The AI Attack Mapper's classification engine (Gladwin -- Classification & Defense).
Classifies an alert against the five-category taxonomy and MITRE ATT&CK v20,
MITRE ATLAS 2026.09 and the OWASP LLM Top 10 (2026), with deterministic severity.

Entry points:
  classify.classify_alert(_full)  one alert
  pipeline.classify_pending_alerts  production path (alert_store queue -> save_classification)
  pilot                             Model Selection Pilot on the dev / held-out split
  dashboard_app                     streamlit run mapper/dashboard_app.py
See README.md.
"""
