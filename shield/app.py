import streamlit as st
import time

import config
from pipeline.analyzer import FraudAnalyzer
from pipeline.rag import RAGEngine
from monitor.network import get_network_status, get_bytes_transferred


@st.cache_resource
def load_rag_engine():
    engine = RAGEngine()
    engine.build_index()
    return engine


@st.cache_resource
def load_analyzer():
    rag = load_rag_engine()
    return FraudAnalyzer(rag_engine=rag)


st.set_page_config(
    page_title=config.APP_TITLE,
    page_icon=config.APP_ICON,
    layout="wide",
)

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #ED1C24;
        margin-bottom: 0;
    }
    .tagline {
        font-size: 1.1rem;
        color: #666;
        margin-top: 0;
    }
    .risk-critical {
        background-color: #FF0000;
        color: white;
        padding: 15px 25px;
        border-radius: 8px;
        font-size: 1.3rem;
        font-weight: 700;
        text-align: center;
    }
    .risk-high {
        background-color: #FF6600;
        color: white;
        padding: 15px 25px;
        border-radius: 8px;
        font-size: 1.3rem;
        font-weight: 700;
        text-align: center;
    }
    .risk-medium {
        background-color: #FFA500;
        color: white;
        padding: 15px 25px;
        border-radius: 8px;
        font-size: 1.3rem;
        font-weight: 700;
        text-align: center;
    }
    .risk-low {
        background-color: #28A745;
        color: white;
        padding: 15px 25px;
        border-radius: 8px;
        font-size: 1.3rem;
        font-weight: 700;
        text-align: center;
    }
    .secure-badge {
        background-color: #1a1a2e;
        color: #00FF00;
        padding: 10px 20px;
        border-radius: 8px;
        font-family: monospace;
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)


with st.spinner("Loading SHIELD models (first time only)..."):
    rag_engine = load_rag_engine()
    analyzer = load_analyzer()


st.markdown(f'<p class="main-header">{config.APP_ICON} {config.APP_TITLE}</p>', unsafe_allow_html=True)
st.markdown(f'<p class="tagline">{config.APP_TAGLINE}</p>', unsafe_allow_html=True)
st.markdown("---")

col_main, col_monitor = st.columns([3, 1])

with col_monitor:
    st.markdown("### Network Monitor")

    net_status = get_network_status()

    if net_status["status"] == "SECURE":
        st.markdown(
            '<div class="secure-badge">'
            '🟢 SECURE<br>'
            f'Cloud AI Connections: {net_status["cloud_ai_connections"]}<br>'
            f'Local AI Active: {net_status["local_ai_connections"]}<br>'
            'All processing: ON-DEVICE'
            '</div>',
            unsafe_allow_html=True,
        )
    else:
        st.error(f"⚠️ {net_status['summary']}")

    st.caption(f"Total connections: {net_status['total_established']}")
    st.caption(f"Model: {config.LLM_MODEL}")
    st.caption(f"Provider: {config.LLM_PROVIDER}")

with col_main:
    st.markdown("### Analyze a Suspicious Message")

    message = st.text_area(
        "Paste the suspicious SMS, WhatsApp message, or call transcript:",
        height=120,
        placeholder="Example: Dear SBI customer, your account will be blocked in 24hrs. Update KYC immediately: http://bit.ly/sbi-kyc-update",
    )

    col_sender, col_btn = st.columns([2, 1])
    with col_sender:
        sender_id = st.text_input(
            "Sender ID (optional):",
            placeholder="e.g., SBIBNK, SB1BNK",
        )
    with col_btn:
        st.markdown("<br>", unsafe_allow_html=True)
        analyze_btn = st.button("🔍 Analyze", type="primary", use_container_width=True)

    if analyze_btn and message.strip():
        with st.spinner("Analyzing message..."):
            start_time = time.time()

            result = analyzer.analyze(
                message.strip(),
                sender_id.strip() if sender_id.strip() else None,
            )

            elapsed = time.time() - start_time

        st.markdown("---")

        risk = result["combined_tool_risk"]
        if risk >= 80:
            risk_class = "risk-critical"
            risk_label = "CRITICAL RISK"
        elif risk >= 50:
            risk_class = "risk-high"
            risk_label = "HIGH RISK"
        elif risk >= 25:
            risk_class = "risk-medium"
            risk_label = "MEDIUM RISK"
        else:
            risk_class = "risk-low"
            risk_label = "LOW RISK"

        st.markdown(
            f'<div class="{risk_class}">'
            f'{risk_label} — Tool Score: {risk}/100'
            f'</div>',
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)

        col_url, col_sender_r, col_urgency = st.columns(3)

        url_data = result["tool_results"]["url_analysis"]
        sender_data = result["tool_results"]["sender_verification"]
        urgency_data = result["tool_results"]["urgency_analysis"]

        with col_url:
            st.metric("URL Risk", f"{url_data['overall_risk']}/100")
            if url_data["urls_found"] > 0:
                st.caption(url_data["summary"])

        with col_sender_r:
            st.metric("Sender Risk", f"{sender_data['risk_score']}/100")
            st.caption(sender_data["summary"][:80])

        with col_urgency:
            st.metric("Urgency Level", urgency_data["level"])
            if urgency_data["pin_otp_requested"]:
                st.error("PIN/OTP REQUESTED — ALWAYS FRAUD")

        st.markdown("### AI Analysis")
        st.markdown(result["llm_analysis"])

        with st.expander("Technical Details"):
            st.json({
                "model": result["model_used"],
                "cloud_connections": result["cloud_connections"],
                "rag_sources": result["rag_sources"],
                "analysis_time": f"{elapsed:.2f}s",
                "url_details": url_data,
                "sender_details": sender_data,
                "urgency_details": {
                    "level": urgency_data["level"],
                    "score": urgency_data["score"],
                    "pin_otp": urgency_data["pin_otp_requested"],
                    "tactics_count": len(urgency_data["tactics_found"]),
                },
            })

    elif analyze_btn:
        st.warning("Please enter a message to analyze.")


st.markdown("---")
st.markdown(
    f"<center><small>{config.APP_TITLE} — Powered by AMD GAIA + Lemonade Server | "
    f"All processing on-device | Zero cloud dependency</small></center>",
    unsafe_allow_html=True,
)
