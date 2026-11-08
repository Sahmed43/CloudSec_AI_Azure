# ruff: noqa: E402
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from cloudsec.ai import summarize
from cloudsec.detect import detect
from cloudsec.ingest import load_events

load_dotenv()
st.set_page_config(page_title="CloudSec AI", page_icon="🛡️", layout="wide")
st.title("🛡️ CloudSec AI | Security Triage Lab")
st.caption("Educational demonstration using synthetic logs and transparent heuristics. No live Azure ingestion.")
st.warning("Use synthetic/non-sensitive data only. Clicking AI Analysis sends finding details to your configured Azure OpenAI resource.")
source = st.file_uploader("Upload synthetic event CSV (max 5 MB)", type=["csv"])
if source is None:
    path = Path(__file__).resolve().parents[1] / "data" / "synthetic_events.csv"
else:
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as temp:
        temp.write(source.getvalue())
        path = Path(temp.name)
try:
    events = load_events(path)
    findings = detect(events)
    left, right = st.columns(2)
    left.metric("Events analyzed", len(events))
    right.metric("Heuristic findings", len(findings))
    st.subheader("Event sample")
    st.dataframe(pd.DataFrame([e.__dict__ for e in events]), use_container_width=True)
    st.subheader("Detection findings")
    st.dataframe(pd.DataFrame([f.to_dict() for f in findings]), use_container_width=True)
    if st.button("Run Azure OpenAI analysis", type="primary"):
        with st.spinner("Requesting Azure OpenAI analysis..."):
            try:
                st.markdown(summarize(findings))
            except Exception as exc:
                st.error(f"AI request failed: {type(exc).__name__}. Check Azure settings and deployment access.")
except (ValueError, OSError) as exc:
    st.error(str(exc))
finally:
    if source is not None:
        path.unlink(missing_ok=True)
