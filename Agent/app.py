import streamlit as st
import time
import random
import string
import json
import re
import requests
import smtplib
import ssl
import hashlib
import hmac
import urllib.parse
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
from datetime import datetime, timezone
from openai import OpenAI

# Top-level secrets
DEEPSEEK_API_KEY   = st.secrets["DEEPSEEK_API_KEY"]
TENCENT_SECRET_ID  = st.secrets["TENCENT_SECRET_ID"]
TENCENT_SECRET_KEY = st.secrets["TENCENT_SECRET_KEY"]

# ==========================================
# 0. API Configuration
# ==========================================
client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com"
)

# ==========================================
# 0.0 Tencent Cloud Web Search API (WSA) Configuration
# ==========================================
WSA_SERVICE = "wsa"
WSA_HOST    = "wsa.tencentcloudapi.com"
WSA_ACTION  = "SearchPro"
WSA_VERSION = "2025-05-08"

# ==========================================
# Only these 5 official platforms are allowed
# ==========================================
ALLOWED_PLATFORMS = {
    "Taobao":   ["taobao.com", "m.tb.cn", "tb.cn"],
    "Tmall":    ["tmall.com"],
    "JD":       ["jd.com", "3.cn", "jd.hk"],
    "Pinduoduo":["pinduoduo.com", "yangkeduo.com"],
    "VIP.com":  ["vip.com"],
}

# ==========================================
# Global language enforcement block
# ==========================================
LANGUAGE_ENFORCEMENT = (
    "*** LANGUAGE REQUIREMENT (ABSOLUTE, NON-NEGOTIABLE) ***\n"
    "You MUST respond entirely in English. Every single word of your output — titles, "
    "reasons, dimensions, explanations, category names, attributes, and any other field — "
    "must be in English. Do NOT output any Chinese characters. Do NOT mix languages. "
    "If the user writes in Chinese, translate their intent and reply in English. "
    "Product titles copied from Chinese e-commerce sites must also be transliterated or "
    "translated into English (keep brand names and model numbers as-is when appropriate).\n"
    "*** END LANGUAGE REQUIREMENT ***\n"
)


def _detect_platform(url: str):
    if not url:
        return None
    url_l = url.lower()
    for name, domains in ALLOWED_PLATFORMS.items():
        for d in domains:
            if d in url_l:
                return name
    return None


def _is_allowed_url(url: str) -> bool:
    return _detect_platform(url) is not None


# ---------- Product detail page detection ----------
_PRODUCT_DETAIL_PATTERNS = [
    re.compile(r"item\.jd\.com/\d+\.html", re.I),
    re.compile(r"item\.m\.jd\.com/product/\d+\.html", re.I),
    re.compile(r"npcitem\.jd\.hk/\d+\.html", re.I),
    re.compile(r"detail\.tmall\.com/item\.htm\?.*id=\d+", re.I),
    re.compile(r"detail\.tmall\.hk/item\.htm\?.*id=\d+", re.I),
    re.compile(r"item\.taobao\.com/item\.htm\?.*id=\d+", re.I),
    re.compile(r"detail\.tb\.cn/item\.htm\?.*id=\d+", re.I),
    re.compile(r"mobile\.yangkeduo\.com/goods\.html\?.*goods_id=\d+", re.I),
    re.compile(r"yangkeduo\.com/goods\.html\?.*goods_id=\d+", re.I),
    re.compile(r"detail\.vip\.com/\d+\.html", re.I),
    re.compile(r"m\.vip\.com/detail/\d+", re.I),
]


def _is_product_detail_url(url: str) -> bool:
    if not url:
        return False
    if not _is_allowed_url(url):
        return False
    for pat in _PRODUCT_DETAIL_PATTERNS:
        if pat.search(url):
            return True
    return False


# ==========================================
# 0.1 Email sending
# ==========================================
SMTP_PRESETS = {
    "gmail.com":      ("smtp.gmail.com",        465, True),
    "googlemail.com": ("smtp.gmail.com",        465, True),
    "outlook.com":    ("smtp-mail.outlook.com", 587, False),
    "hotmail.com":    ("smtp-mail.outlook.com", 587, False),
    "live.com":       ("smtp-mail.outlook.com", 587, False),
    "msn.com":        ("smtp-mail.outlook.com", 587, False),
    "office365.com":  ("smtp.office365.com",    587, False),
    "yahoo.com":      ("smtp.mail.yahoo.com",   465, True),
    "ymail.com":      ("smtp.mail.yahoo.com",   465, True),
    "icloud.com":     ("smtp.mail.me.com",      587, False),
    "me.com":         ("smtp.mail.me.com",      587, False),
    "mac.com":        ("smtp.mail.me.com",      587, False),
    "aol.com":        ("smtp.aol.com",          465, True),
    "zoho.com":       ("smtp.zoho.com",         465, True),
    "protonmail.com": ("smtp.protonmail.ch",    587, False),
    "qq.com":         ("smtp.qq.com",           465, True),
    "vip.qq.com":     ("smtp.vip.qq.com",       465, True),
    "foxmail.com":    ("smtp.qq.com",           465, True),
    "163.com":        ("smtp.163.com",          465, True),
    "126.com":        ("smtp.126.com",          465, True),
    "yeah.net":       ("smtp.yeah.net",         465, True),
    "sina.com":       ("smtp.sina.com",         465, True),
    "sina.cn":        ("smtp.sina.com",         465, True),
    "sohu.com":       ("smtp.sohu.com",         465, True),
    "aliyun.com":     ("smtp.aliyun.com",       465, True),
    "139.com":        ("smtp.139.com",          465, True),
    "189.cn":         ("smtp.189.cn",           465, True),
    "21cn.com":       ("smtp.21cn.com",         465, True),
    "tom.com":        ("smtp.tom.com",          465, True),
    "exmail.qq.com":   ("smtp.exmail.qq.com",    465, True),
    "qiye.aliyun.com": ("smtp.qiye.aliyun.com",  465, True),
}


def resolve_smtp_config(sender_email: str, override: dict | None = None):
    if override and override.get("host"):
        return (
            override["host"],
            int(override.get("port", 465)),
            bool(override.get("use_ssl", True)),
        )
    domain = sender_email.split("@")[-1].lower().strip()
    if domain in SMTP_PRESETS:
        return SMTP_PRESETS[domain]
    for key, cfg in SMTP_PRESETS.items():
        if domain.endswith("." + key) or domain == key:
            return cfg
    return None


def send_email_code(
    to_email: str,
    code: str,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    use_ssl: bool = True,
    sender_name: str = "AI Shopping Agent",
    subject: str = "[AI Shopping Agent] Registration Verification Code",
    body_html: str = None,
):
    if body_html is None:
        body_html = f"""
        <div style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color:#1488CC;">AI Shopping Agent</h2>
            <p>You are registering an account. Your verification code is:</p>
            <h1 style="color:#FF4B4B; letter-spacing: 5px;">{code}</h1>
            <p>The code is valid for <b>5 minutes</b>. Please do not share it with anyone.</p>
            <hr>
            <p style="color:#888; font-size:12px;">
                If you did not initiate this action, please ignore this email.<br>
                This email was sent automatically. Please do not reply.
            </p>
        </div>
        """

    msg = MIMEText(body_html, "html", "utf-8")
    msg["From"] = formataddr((str(Header(sender_name, "utf-8")), smtp_user))
    msg["To"] = formataddr(("", to_email))
    msg["Subject"] = Header(subject, "utf-8")

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20, context=ctx) as server:
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_user, [to_email], msg.as_string())
        return True, ""
    except smtplib.SMTPAuthenticationError as e:
        return False, f"SMTP authentication failed. Please check the sender email and app password. ({e.smtp_code})"
    except smtplib.SMTPConnectError:
        return False, f"Cannot connect to {smtp_host}:{smtp_port}. Please check your network or port."
    except Exception as e:
        return False, f"Send failed: {type(e).__name__} - {e}"


def send_payment_code_email(to_email: str, code: str, order: dict):
    body = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color:#1488CC;">AI Shopping Agent · Payment Confirmation</h2>
        <p>You are paying for the following order. Please use the one-time password below to verify:</p>
        <table style="border-collapse:collapse; margin: 10px 0;">
            <tr><td style="padding:4px 8px;"><b>Order ID</b></td><td style="padding:4px 8px;">{order.get('order_id','')}</td></tr>
            <tr><td style="padding:4px 8px;"><b>Product</b></td><td style="padding:4px 8px;">{order.get('title','')}</td></tr>
            <tr><td style="padding:4px 8px;"><b>Amount</b></td><td style="padding:4px 8px; color:#FF4B4B;"><b>${order.get('final_price', 0)}</b></td></tr>
        </table>
        <p>Your one-time payment password:</p>
        <h1 style="color:#FF4B4B; letter-spacing: 4px; font-family: monospace;">{code}</h1>
        <p>The password is valid for <b>10 minutes</b> and can be used only once. Please do not share it with anyone.</p>
        <hr>
        <p style="color:#888; font-size:12px;">
            If you did not initiate this action, please ignore this email.<br>
            This email was sent automatically. Please do not reply.
        </p>
    </div>
    """
    return send_email_code(
        to_email=to_email,
        code=code,
        smtp_host=st.session_state.smtp_host,
        smtp_port=st.session_state.smtp_port,
        smtp_user=st.session_state.smtp_user,
        smtp_pass=st.session_state.smtp_pass,
        use_ssl=st.session_state.smtp_use_ssl,
        subject="[AI Shopping Agent] One-Time Payment Password",
        body_html=body,
    )


# ==========================================
# ★ Receipt email after successful payment (Merchant → Buyer)
# ==========================================
def send_receipt_email(to_email: str, order: dict, paid_at: str) -> tuple:
    platform = order.get("platform", "") or "the platform"
    title = order.get("title", "")
    price = order.get("final_price", 0)
    try:
        price_str = f"${float(price):.2f}"
    except Exception:
        price_str = f"${price}"

    body_html = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px; line-height:1.8;">
        <p style="font-size:15px;">
            <b>[{platform}]</b> Dear user, we received on <b>{paid_at}</b> your payment of
            <b style="color:#FF4B4B;">{price_str}</b> for purchasing <b>"{title}"</b> on our platform.
            This is your receipt. Please do not reply.
        </p>
        <hr>
        <p style="color:#888; font-size:12px;">
            This email was sent automatically by [{platform}]. Please do not reply.
        </p>
    </div>
    """

    return send_email_code(
        to_email=to_email,
        code="",
        smtp_host=st.session_state.smtp_host,
        smtp_port=st.session_state.smtp_port,
        smtp_user=st.session_state.smtp_user,
        smtp_pass=st.session_state.smtp_pass,
        use_ssl=st.session_state.smtp_use_ssl,
        sender_name=f"{platform} Merchant",
        subject=f"[{platform}] Your Payment Receipt",
        body_html=body_html,
    )


# ==========================================
# 1. Page configuration and CSS
# ==========================================
st.set_page_config(
    page_title="AI Shopping Agent with Auto Payment",
    page_icon="🛍",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .order-card {
        background-color: #1E212A;
        border: 1px solid #313543;
        border-radius: 10px;
        padding: 15px;
        margin-bottom: 10px;
    }
    .stButton>button { border-radius: 8px; }
    .wallet-card {
        background: linear-gradient(135deg, #2B32B2 0%, #1488CC 100%);
        color: white; padding: 20px; border-radius: 12px; margin-bottom: 20px;
    }
    .custom-badge {
        background-color: #2e7d32; color: white; padding: 3px 8px;
        border-radius: 12px; font-size: 12px; font-weight: bold;
    }
    .nav-card {
        background-color: #1E212A; border: 1px solid #313543;
        border-radius: 12px; padding: 20px; text-align: center;
        transition: transform 0.2s;
    }
    .nav-card:hover { border-color: #4CAF50; }
    .src-link { font-size: 13px; color: #4FC3F7; word-break: break-all; }
    .addr-tip {
        color: #FFA726; font-size: 13px; font-style: italic; margin-top: 4px;
    }
    .no-more-tip {
        background-color: #3E2723;
        border-left: 4px solid #FF9800;
        padding: 12px 16px;
        border-radius: 6px;
        color: #FFE0B2;
        margin: 10px 0;
    }
    .limit-tip {
        background-color: #4A148C;
        border-left: 4px solid #E91E63;
        padding: 12px 16px;
        border-radius: 6px;
        color: #F8BBD0;
        margin: 10px 0;
        font-weight: bold;
    }
    .chat-meta { color: #888; font-size: 12px; }
    .intent-tag {
        background-color: #1B5E20; color: white;
        padding: 3px 10px; border-radius: 10px;
        font-size: 12px; margin-right: 6px; display: inline-block;
    }
    .platform-tag {
        background-color: #B71C1C; color: white;
        padding: 2px 8px; border-radius: 8px;
        font-size: 12px; margin-left: 6px;
    }
</style>
""", unsafe_allow_html=True)


# ==========================================
# 2. Session State initialization
# ==========================================
if "users_db" not in st.session_state:
    st.session_state.users_db = {
        "test@example.com": {"email": "test@example.com", "password": "password123"}
    }

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_info" not in st.session_state:
    st.session_state.user_info = None
if "nav_location" not in st.session_state:
    st.session_state.nav_location = "chat"
if "max_limit" not in st.session_state:
    st.session_state.max_limit = 500
if "single_limit" not in st.session_state:
    st.session_state.single_limit = 10000.00
if "daily_limit" not in st.session_state:
    st.session_state.daily_limit = 50000.00
if "wallet_balance" not in st.session_state:
    st.session_state.wallet_balance = 350.00

if "bank_cards" not in st.session_state:
    st.session_state.bank_cards = []

if "address_list" not in st.session_state:
    st.session_state.address_list = []

if "chat_sessions" not in st.session_state:
    st.session_state.chat_sessions = [
        {
            "session_id": "CS-001",
            "title": "First Shopping Consultation",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "messages": [
                {"role": "assistant",
                 "content": "👋 Hi! I'm your **AI Shopping Agent across the whole web**.\n\nTell me what you'd like to buy (e.g., *\"Help me buy a 20,000 mAh fast-charging power bank\"*), and I'll compare prices, recommend items, and place the order for you!\n\n💡 You can also describe your needs precisely, e.g., *\"I want a black camera around $1000\"*. I'll shortlist matching products for you.\n\n🛒 Supported platforms: **Taobao / Tmall / JD / Pinduoduo / VIP.com**."}
            ]
        }
    ]
if "current_session_index" not in st.session_state:
    st.session_state.current_session_index = 0
if "pending_order" not in st.session_state:
    st.session_state.pending_order = None
if "orders_history" not in st.session_state:
    st.session_state.orders_history = []
if "simulated_code" not in st.session_state:
    st.session_state.simulated_code = None
if "code_sent_at" not in st.session_state:
    st.session_state.code_sent_at = None
if "buy_stage" not in st.session_state:
    st.session_state.buy_stage = "none"
if "recommend_step" not in st.session_state:
    st.session_state.recommend_step = 1
if "target_product_category" not in st.session_state:
    st.session_state.target_product_category = ""
if "candidate_options" not in st.session_state:
    st.session_state.candidate_options = []
if "search_cache" not in st.session_state:
    st.session_state.search_cache = {}

if "selected_address_for_order" not in st.session_state:
    st.session_state.selected_address_for_order = None
if "payment_code" not in st.session_state:
    st.session_state.payment_code = None
if "payment_code_sent_at" not in st.session_state:
    st.session_state.payment_code_sent_at = None
if "payment_code_order_id" not in st.session_state:
    st.session_state.payment_code_order_id = None

if "stage3_price_range" not in st.session_state:
    st.session_state.stage3_price_range = None

if "stage4_no_match" not in st.session_state:
    st.session_state.stage4_no_match = False

if "limit_exceeded" not in st.session_state:
    st.session_state.limit_exceeded = False
if "limit_exceeded_order" not in st.session_state:
    st.session_state.limit_exceeded_order = None

if "editing_address_id" not in st.session_state:
    st.session_state.editing_address_id = None
if "editing_card_id" not in st.session_state:
    st.session_state.editing_card_id = None

if "current_attributes" not in st.session_state:
    st.session_state.current_attributes = []
if "current_price_range" not in st.session_state:
    st.session_state.current_price_range = (None, None)
if "current_detail_req" not in st.session_state:
    st.session_state.current_detail_req = ""

# Placeholders — will be filled by _load_smtp_from_secrets()
if "smtp_user" not in st.session_state:
    st.session_state.smtp_user = ""
if "smtp_host" not in st.session_state:
    st.session_state.smtp_host = ""
if "smtp_port" not in st.session_state:
    st.session_state.smtp_port = 465
if "smtp_use_ssl" not in st.session_state:
    st.session_state.smtp_use_ssl = True
if "smtp_pass" not in st.session_state:
    st.session_state.smtp_pass = ""


# ==========================================
# 2.1 Auto-load SMTP config from st.secrets
# ==========================================
def _load_smtp_from_secrets():
    try:
        secrets = st.secrets
    except Exception:
        return

    smtp_user = secrets.get("SMTP_USER", "")
    smtp_pass = secrets.get("SMTP_PASS", "")
    if not smtp_user or not smtp_pass:
        return

    host = secrets.get("SMTP_HOST", "")
    port = secrets.get("SMTP_PORT", None)
    use_ssl = secrets.get("SMTP_USE_SSL", None)

    if not host or port is None or use_ssl is None:
        auto = resolve_smtp_config(smtp_user)
        if auto:
            a_host, a_port, a_ssl = auto
            host = host or a_host
            port = a_port if port is None else int(port)
            use_ssl = a_ssl if use_ssl is None else bool(use_ssl)
        else:
            host = host or ""
            port = 465 if port is None else int(port)
            use_ssl = True if use_ssl is None else bool(use_ssl)

    st.session_state.smtp_user    = smtp_user.strip()
    st.session_state.smtp_pass    = smtp_pass
    st.session_state.smtp_host    = host.strip()
    st.session_state.smtp_port    = int(port)
    st.session_state.smtp_use_ssl = bool(use_ssl)


_load_smtp_from_secrets()


# ==========================================
# 3. Helper functions
# ==========================================
def generate_12digit_code():
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(12))


def validate_password(pwd: str):
    if not pwd or len(pwd) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Za-z]", pwd):
        return False, "Password must contain at least one letter."
    if not re.search(r"\d", pwd):
        return False, "Password must contain at least one digit."
    return True, ""


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sign_tencent_cloud(secret_id: str, secret_key: str, payload: dict):
    if not secret_id or not secret_key:
        raise ValueError("Tencent Cloud SecretId / SecretKey is not configured!")
    try:
        secret_id.encode("ascii")
        secret_key.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(
            f"Tencent Cloud key contains non-ASCII characters. Please check whether it is still a placeholder.\n"
            f"SecretId = {secret_id!r}"
        )

    timestamp = int(time.time())
    date = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")

    method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    canonical_headers = (
        "content-type:application/json; charset=utf-8\n"
        f"host:{WSA_HOST}\n"
    )
    signed_headers = "content-type;host"

    payload_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    payload_bytes = payload_str.encode("utf-8")
    hashed_payload = hashlib.sha256(payload_bytes).hexdigest()

    canonical_request = "\n".join([
        method, canonical_uri, canonical_querystring,
        canonical_headers, signed_headers, hashed_payload
    ])

    algorithm = "TC3-HMAC-SHA256"
    credential_scope = f"{date}/{WSA_SERVICE}/tc3_request"
    hashed_canonical = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = "\n".join([
        algorithm, str(timestamp), credential_scope, hashed_canonical
    ])

    secret_date    = _hmac_sha256(("TC3" + secret_key).encode("utf-8"), date)
    secret_service = _hmac_sha256(secret_date, WSA_SERVICE)
    secret_signing = _hmac_sha256(secret_service, "tc3_request")
    signature = hmac.new(
        secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization = (
        f"{algorithm} "
        f"Credential={secret_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    headers = {
        "Authorization": str(authorization),
        "Content-Type": "application/json; charset=utf-8",
        "Host": str(WSA_HOST),
        "X-TC-Action": str(WSA_ACTION),
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": str(WSA_VERSION),
    }
    return headers, payload_bytes


def _search_web_raw(query: str, search_source: str = "standard") -> list:
    cache_key = f"raw::{query}||{search_source}"
    if cache_key in st.session_state.search_cache:
        return st.session_state.search_cache[cache_key]

    payload = {"Query": query, "Mode": 0, "Cnt": 50}

    results = []
    try:
        headers, body_bytes = _sign_tencent_cloud(
            TENCENT_SECRET_ID, TENCENT_SECRET_KEY, payload
        )
        resp = requests.post(
            f"https://{WSA_HOST}/",
            headers=headers,
            data=body_bytes,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        response_body = data.get("Response", {})
        if "Error" in response_body:
            err = response_body["Error"]
            print(f"[WSA Error] {err.get('Code')}: {err.get('Message')}")
            return []

        pages_raw = response_body.get("Pages", []) or []
        for page_str in pages_raw:
            try:
                page = json.loads(page_str) if isinstance(page_str, str) else page_str
                url = page.get("url", "") or page.get("Url", "")
                if not url:
                    continue
                platform = _detect_platform(url)
                if platform is None:
                    continue
                title = page.get("title", "") or page.get("Title", "") or "Untitled"
                site  = page.get("site", "") or page.get("Site", "") or platform
                date_ = page.get("date", "") or page.get("Date", "")
                passage = (
                    page.get("passage", "")
                    or page.get("content", "")
                    or page.get("Passage", "")
                )
                results.append({
                    "title":   title,
                    "url":     url,
                    "site":    site,
                    "date":    date_,
                    "passage": passage,
                    "platform": platform,
                    "is_detail": _is_product_detail_url(url),
                })
            except Exception as e:
                print(f"[WSA parse error] {e}")
                continue

        results.sort(key=lambda r: (not r["is_detail"],))

    except Exception as e:
        print(f"[WSA call failed] {type(e).__name__}: {e}")

    st.session_state.search_cache[cache_key] = results
    return results


def search_web(query: str, search_source: str = "standard") -> str:
    results = _search_web_raw(query, search_source)
    if not results:
        return "[Search service temporarily unavailable. Will rely on model knowledge.]"

    summaries = []
    for i, r in enumerate(results, 1):
        block = (
            f"[{i}] [{r['title']}] ({r['site']} {r['date']}) Platform: {r.get('platform','')}"
            f"{' [Product detail page]' if r.get('is_detail') else ''}\n"
            f"{r['passage']}\n"
            f"URL: {r['url']}"
        )
        summaries.append(block)
    return "\n\n".join(summaries)


def _attach_real_urls(data, raw_results: list, item_category: str = ""):
    """
    Attach a real product detail URL to every recommended item.

    STRICT MODE: If no detail URL can be attached to an item, we raise a ValueError
    so the caller can decide to show a friendly "no match" message instead of
    fabricating links.
    """
    used_urls = set()

    detail_candidates = [r for r in raw_results if r.get("is_detail")]

    def _pick_detail_by_title(title: str):
        title = (title or "").strip()
        if not title:
            return None
        # Exact / substring match first
        for r in detail_candidates:
            rt = r.get("title", "")
            if rt and (title in rt or rt in title):
                return r
        # Fuzzy match fallback
        best = None
        best_score = 0
        for r in detail_candidates:
            rt = r.get("title", "")
            if not rt:
                continue
            common = set(title) & set(rt)
            score = len(common)
            if score > best_score:
                best_score = score
                best = r
        if best is not None and best_score >= max(3, len(title) // 3):
            return best
        return None

    def _pick_any_unused_detail():
        for r in detail_candidates:
            if r.get("url") not in used_urls:
                return r
        return None

    def _fill(item):
        ref = item.get("search_ref", 0)
        try:
            ref = int(ref)
        except Exception:
            ref = 0

        picked = None
        if 1 <= ref <= len(raw_results):
            cand = raw_results[ref - 1]
            if cand.get("is_detail"):
                picked = cand

        if picked is None:
            picked = _pick_detail_by_title(item.get("title", ""))

        if picked is None:
            picked = _pick_any_unused_detail()

        if picked is None:
            raise ValueError(
                f"No real product detail URL found for '{item.get('title', '')}' "
                f"in category '{item_category}'."
            )

        item["source_url"]  = picked.get("url", "")
        item["source_site"] = picked.get("site", "") or picked.get("platform", "")
        item["platform"]    = picked.get("platform", "") or item.get("platform", "")
        used_urls.add(picked.get("url", ""))

    if isinstance(data, dict):
        _fill(data)
    elif isinstance(data, list):
        for it in data:
            _fill(it)
    return data


def estimate_price_range(item_category: str) -> tuple:
    raw_results = _search_web_raw(f"{item_category} price market price", "standard")

    prices = []
    if raw_results:
        text_blob = " ".join(
            (r.get("passage", "") or "") + " " + (r.get("title", "") or "")
            for r in raw_results
        )
        for m in re.findall(
            r"(?:¥|\$|price[:\s]*)?\s*(\d{1,3}(?:,\d{3})*(?:\.\d+)?)",
            text_blob,
            flags=re.I
        ):
            try:
                v = float(m.replace(",", ""))
                if 1 <= v <= 100000:
                    prices.append(v)
            except Exception:
                continue

    if prices:
        lo = max(0, int(min(prices) * 0.6))
        hi = int(max(prices) * 1.5) + 10
        lo = (lo // 10) * 10
        hi = ((hi + 9) // 10) * 10
        if hi - lo < 100:
            hi = lo + 500
        return lo, hi

    try:
        resp = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system",
                 "content": LANGUAGE_ENFORCEMENT +
                            f"The user wants to buy [{item_category}]. Output only one line of JSON: "
                            f'{{"min": lowest reasonable price, "max": highest reasonable price}} in CNY. Output only JSON.'},
                {"role": "user", "content": f"Please give a reasonable price range for [{item_category}]."}
            ],
            stream=False
        )
        content = resp.choices[0].message.content.strip()
        content = re.sub(r"^```json|```$", "", content).strip()
        obj = json.loads(content)
        lo = max(0, int(obj.get("min", 0)))
        hi = max(lo + 500, int(obj.get("max", 10000)))
        lo = (lo // 10) * 10
        hi = ((hi + 9) // 10) * 10
        return lo, hi
    except Exception:
        return 0, 10000


def parse_user_intent(user_input: str, current_category: str = "") -> dict:
    prompt = f"""{LANGUAGE_ENFORCEMENT}
You are a shopping intent parser for e-commerce. Extract the following from the user's input and return pure JSON:
{{
  "category": "product category (short, in ENGLISH, e.g., camera, power bank, laptop)",
  "min_price": number or null,
  "max_price": number or null,
  "attributes": ["color/brand/capacity and other specific attributes, in ENGLISH"],
  "changed": true/false
}}

Rules:
- If the user says "around 1000", min_price=800, max_price=1200 (±20%).
- If the user says "under 1000", min_price=null, max_price=1000.
- If the user says "at least 2000", min_price=2000, max_price=null.
- If the user says "between 1000 and 2000", min_price=1000, max_price=2000.
- If no price is mentioned, both min_price and max_price are null.
- attributes are what the user explicitly requires (e.g., "black", "Huawei", "20000mAh", "fast charging").
- changed indicates whether the category the user just mentioned is different from the current category.
- Current category: [{current_category or "(none)"}]
- If the user is just confirming/rejecting/continuing (e.g., "satisfied", "another batch"), set category to an empty string.
- ALL string values in the output MUST be in English.

User input: "{user_input}"

Output JSON only, no markdown."""

    try:
        resp = client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            stream=False
        )
        content = resp.choices[0].message.content.strip()
        content = re.sub(r"^```json|```$", "", content).strip()
        obj = json.loads(content)
        obj.setdefault("category", "")
        obj.setdefault("min_price", None)
        obj.setdefault("max_price", None)
        obj.setdefault("attributes", [])
        obj.setdefault("changed", False)
        if not isinstance(obj.get("attributes"), list):
            obj["attributes"] = []
        return obj
    except Exception as e:
        print(f"[Intent parsing failed] {e}")
        return {
            "category": user_input,
            "min_price": None,
            "max_price": None,
            "attributes": [],
            "changed": bool(current_category and user_input.strip() != current_category),
        }


_TITLE_RULES = """[Product title rules — extremely important]
- "title" must be the **full, specific name** of the product, translated into ENGLISH, copied from the product page on the e-commerce site, including brand, model, capacity, color, selling points, etc.
- Correct examples:
  "Xiaomi Built-in Cable Power Bank 10000 Pocket Edition Compact Portable Mobile Power Bank Two-way Fast Charging for Android & Apple Durable Light Brown"
  "Woodpecker Women's Autumn Winter Octagonal Hat Middle-aged Mom Fashion Versatile Warm Beret"
  "Apple iPhone 16 Pro 256GB Natural Titanium 5G Dual SIM Dual Standby"
- Wrong examples (strictly prohibited):
  "Xiaomi power bank"  "Power bank recommendation"  "High cost-performance power bank"  "[Custom Selection 1] Camera Special Edition"
- Do NOT use any placeholders or invented titles.
- Do NOT output any Chinese characters in the title.
"""

_URL_RULES = """[Link rules — extremely important]
- You **only reference search results through search_ref**. Never invent any URL.
- The program will pick a "product detail page URL" from the web search results (e.g., https://item.jd.com/10076490523190.html).
- If the search results contain **no** detail page for the product, the program will mark it as having no link. Do not force a search page.
- Every recommended product MUST have a real product detail page URL from one of these platforms only: Taobao, Tmall, JD, Pinduoduo, VIP.com.
"""


def call_deepseek_recommend_engine(step: int, item_category: str,
                                   user_history: list,
                                   extra_constraints: dict = None):
    extra_constraints = extra_constraints or {}
    search_context = ""
    raw_results = []

    attrs = extra_constraints.get("attributes", []) or []
    min_price_c = extra_constraints.get("min_price", None)
    max_price_c = extra_constraints.get("max_price", None)
    attr_q = " ".join(attrs) if attrs else ""

    price_q = ""
    if min_price_c is not None and max_price_c is not None:
        price_q = f"{int(min_price_c)}-{int(max_price_c)} CNY"
    elif min_price_c is not None:
        price_q = f"above {int(min_price_c)} CNY"
    elif max_price_c is not None:
        price_q = f"under {int(max_price_c)} CNY"

    platform_q = "Taobao Tmall JD Pinduoduo VIP.com"

    if step in [1, 2, 3, 4]:
        if step == 1:
            search_query = f"{item_category} {attr_q} latest price user reviews recommendation {platform_q}"
        elif step == 2:
            search_query = f"{item_category} {attr_q} price reviews sales {platform_q}"
        elif step == 3:
            p_min = extra_constraints.get("min_price", 0) or 0
            p_max = extra_constraints.get("max_price", 10000) or 10000
            search_query = f"{item_category} {attr_q} {p_min}-{p_max} CNY {platform_q}"
        else:
            user_detail = extra_constraints.get("detail_req", "")
            search_query = f"{item_category} {attr_q} {price_q} {user_detail} {platform_q}"

        raw_results = _search_web_raw(search_query, search_source="standard")
        if raw_results:
            summaries = []
            for i, r in enumerate(raw_results, 1):
                flag = " [Product detail page]" if r.get("is_detail") else ""
                block = (
                    f"[{i}] [{r['title']}] ({r['site']} {r['date']}) Platform: {r.get('platform','')}{flag}\n"
                    f"{r['passage']}\n"
                    f"URL: {r['url']}"
                )
                summaries.append(block)
            search_context = "\n\n".join(summaries)
        else:
            search_context = "[Search service temporarily unavailable. Will rely on model knowledge.]"

    base_instructions = (
        LANGUAGE_ENFORCEMENT +
        f"The user wants to buy the core product category: [{item_category}]. "
        f"You MUST STRICTLY recommend products within this category. Never switch to a different item type!\n"
        f"[Platform restriction] Only recommend products from Taobao, Tmall, JD, Pinduoduo, VIP.com. "
        f"Do not recommend any other platform (Amazon, Suning, Douyin, Xiaohongshu, etc. are all forbidden).\n"
        + _TITLE_RULES
        + _URL_RULES
    )

    constraint_lines = []
    if attrs:
        constraint_lines.append(f"Attributes the user explicitly requires: {', '.join(attrs)} (all recommendations must satisfy them).")
    if min_price_c is not None or max_price_c is not None:
        if min_price_c is not None and max_price_c is not None:
            constraint_lines.append(f"User price range: {int(min_price_c)} - {int(max_price_c)} CNY (all recommendations must fall in this range).")
        elif min_price_c is not None:
            constraint_lines.append(f"User requires price >= {int(min_price_c)} CNY.")
        else:
            constraint_lines.append(f"User requires price <= {int(max_price_c)} CNY.")
    if constraint_lines:
        base_instructions += "\n" + "\n".join(constraint_lines)

    if search_context and "[Search service temporarily unavailable" not in search_context:
        base_instructions += f"""

Below is the latest product information from the web search (**only Taobao / Tmall / JD / Pinduoduo / VIP.com**):
--- Web search results begin ---
{search_context}
--- Web search results end ---

Especially important:
- Do NOT invent any URL!
- Only fill in the "search_ref" field of the returned JSON with the index of the search result you referenced.
- The program will automatically attach the real e-commerce URL based on search_ref.
- The "platform" field must be one of [Taobao / Tmall / JD / Pinduoduo / VIP.com].
- If no search result is usable, set search_ref to 0.
- For "title", copy the product title from the search result directly (translate to English if needed). Do not rewrite or abbreviate.
- Every recommended item MUST correspond to one of the real product detail page URLs in the search results. Items without a matching detail URL will be rejected."""

    if step == 1:
        system_prompt = f"""{base_instructions}
Compare prices across the web and recommend 1 top overall choice.
You must output JSON in the format:
{{
  "title": "full specific product title (in English) on the e-commerce platform",
  "platform": "one of Taobao/Tmall/JD/Pinduoduo/VIP.com",
  "original_price": 200.0,
  "coupon": 20.0,
  "final_price": 180.0,
  "search_ref": 1,
  "reason": "reason for being the top overall choice (in English)"
}}
Return pure JSON only, no markdown."""
    elif step == 2:
        system_prompt = f"""{base_instructions}
For this category, recommend 3 options with different advantages from [Lowest Price], [Best Reviews], [Best Sales].
Output as a JSON array (3 objects):
[
  {{
    "dimension": "Best price choice",
    "title": "full specific product title (in English) on the e-commerce platform",
    "platform": "one of Taobao/Tmall/JD/Pinduoduo/VIP.com",
    "original_price": 150.0,
    "coupon": 10.0,
    "final_price": 140.0,
    "search_ref": 1,
    "reason": "Great value, lowest price across the web (in English)"
  }},
  {{
    "dimension": "Best reviews",
    "title": "full specific product title (in English) on the e-commerce platform",
    "platform": "one of Taobao/Tmall/JD/Pinduoduo/VIP.com",
    "original_price": 250.0,
    "coupon": 20.0,
    "final_price": 230.0,
    "search_ref": 2,
    "reason": "99.8% positive rate, excellent reputation (in English)"
  }},
  {{
    "dimension": "Best seller",
    "title": "full specific product title (in English) on the e-commerce platform",
    "platform": "one of Taobao/Tmall/JD/Pinduoduo/VIP.com",
    "original_price": 200.0,
    "coupon": 15.0,
    "final_price": 185.0,
    "search_ref": 3,
    "reason": "Best seller across the web, 100k+ monthly sales (in English)"
  }}
]
Return pure JSON only, no markdown."""
    elif step == 3:
        p_min = extra_constraints.get("min_price", 0)
        p_max = extra_constraints.get("max_price", 10000)
        system_prompt = f"""{base_instructions}
User filter: price range between {p_min} and {p_max} CNY.
Recommend 1 product that best fits the above price constraint.
You must output JSON in the format:
{{
  "title": "full specific product title (in English) on the e-commerce platform",
  "platform": "one of Taobao/Tmall/JD/Pinduoduo/VIP.com",
  "original_price": 190.0,
  "coupon": 10.0,
  "final_price": 180.0,
  "search_ref": 1,
  "reason": "accurately matches the budget range (in English)"
}}
Return pure JSON only, no markdown."""
    elif step == 4:
        user_detail = extra_constraints.get("detail_req", "")
        system_prompt = f"""{base_instructions}
The user's additional detailed request: "{user_detail}".
Based on this category and previous requirements, choose up to 5 specific products that meet the conditions for the user to pick.
**All recommendations must strictly satisfy the above attribute and price constraints (if any).**
**"title" must be the real, complete title of each product on the e-commerce platform, in English.**
Output as a JSON array (up to 5 objects):
[
  {{
    "option_id": 1,
    "title": "full specific product title (in English) on the e-commerce platform",
    "platform": "one of Taobao/Tmall/JD/Pinduoduo/VIP.com",
    "original_price": 200.0,
    "coupon": 20.0,
    "final_price": 180.0,
    "search_ref": 1,
    "reason": "explanation of why it is recommended (in English)"
  }}
]
Return pure JSON only, no markdown.
If NO product can satisfy the constraints and have a real product detail URL, return an empty array []."""

    try:
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Please combine the conversation history and generate the product options for stage {step}. Reply entirely in English."}
            ],
            stream=False
        )
        content = response.choices[0].message.content.strip()
        if content.startswith("```json"):
            content = content[7:-3].strip()
        elif content.startswith("```"):
            content = content[3:-3].strip()
        data = json.loads(content)

        # STRICT MODE: attach real URLs, raise if any item cannot get one.
        try:
            data = _attach_real_urls(data, raw_results, item_category=item_category)
        except ValueError as ve:
            print(f"[Attach URL failed] {ve}")
            # Propagate as empty result — the UI will show a "no match" message.
            if isinstance(data, dict):
                return {}
            return []

        if isinstance(data, dict):
            data["order_id"] = f"AGENT-ORD-{random.randint(100000, 999999)}"
        elif isinstance(data, list):
            for item in data:
                item["order_id"] = f"AGENT-ORD-{random.randint(100000, 999999)}"
        return data
    except Exception as e:
        print(f"[Recommendation engine failed] step={step}, {type(e).__name__}: {e}")
        # In strict mode, we do not fabricate products without real URLs.
        # Return an empty result to signal "no match".
        if step in [1, 3]:
            return {}
        elif step == 2:
            return []
        elif step == 4:
            return []


def _today_order_total() -> float:
    today_str = datetime.now().strftime("%Y-%m-%d")
    total = 0.0
    for o in st.session_state.orders_history:
        ts = o.get("paid_at", "")
        if ts.startswith(today_str):
            try:
                total += float(o.get("final_price", 0))
            except Exception:
                pass
    return total


def check_order_limits(order: dict) -> tuple:
    try:
        price = float(order.get("final_price", 0))
    except Exception:
        price = 0.0

    single_limit = float(st.session_state.single_limit)
    daily_limit = float(st.session_state.daily_limit)
    today_used = _today_order_total()
    today_after = today_used + price

    if price > single_limit:
        return True, (
            f"Sorry, the product you selected (${price:.2f}) exceeds your **single-transaction payment limit** (${single_limit:.2f}). "
            f"Please update the limit in your profile or choose a product within the limit."
        )
    if today_after > daily_limit:
        return True, (
            f"Sorry, the product you selected (${price:.2f}) plus today's spending (${today_used:.2f}) "
            f"would exceed your **daily cumulative payment limit** (${daily_limit:.2f}). "
            f"Please update the limit in your profile or choose a product within the limit."
        )
    return False, ""


# ==========================================
# 4. Sign up / Log in
# ==========================================
def render_welcome_page():
    st.markdown("<h1 style='text-align: center;'>🛍️ Welcome to the AI Shopping Agent</h1>",
                unsafe_allow_html=True)
    st.markdown(
        "<p style='text-align: center; color: #888;'>Powered by DeepSeek · Real-time web price comparison · 4-stage refined recommendations · Auto coupons · Instant payment</p>",
        unsafe_allow_html=True
    )
    st.divider()

    col_left, col_main, col_right = st.columns([1, 2, 1])

    with col_main:
        auth_mode = st.radio("Choose an action",
                             ["Sign Up", "Log In"],
                             horizontal=True)

        if auth_mode == "Sign Up":
            st.subheader("📝 Sign Up")

            email = st.text_input("Email", placeholder="example@domain.com")

            code_col1, code_col2 = st.columns([2, 1])
            with code_col1:
                verify_code = st.text_input("Verification code", placeholder="Enter the 6-digit code", max_chars=6)
            with code_col2:
                st.write("")
                if st.button("Send code", use_container_width=True):
                    if not email or "@" not in email:
                        st.error("❌ Please enter a valid email address first!")
                    elif not st.session_state.get("smtp_user"):
                        st.error("❌ The administrator has not configured a sender email. Cannot send email.")
                    else:
                        code = str(random.randint(100000, 999999))
                        with st.spinner("Sending verification code email..."):
                            ok, err = send_email_code(
                                to_email=email.strip().lower(),
                                code=code,
                                smtp_host=st.session_state.smtp_host,
                                smtp_port=st.session_state.smtp_port,
                                smtp_user=st.session_state.smtp_user,
                                smtp_pass=st.session_state.smtp_pass,
                                use_ssl=st.session_state.smtp_use_ssl,
                            )
                        if ok:
                            st.session_state.simulated_code = code
                            st.session_state.code_sent_at = time.time()
                            st.success(f"📩 Verification code sent to {email}. Valid for 5 minutes.")
                        else:
                            st.error(f"❌ Failed to send email: {err}")

            password = st.text_input("Set login password", type="password",
                                     placeholder="At least 8 characters, must include letters and digits")
            confirm_password = st.text_input("Confirm login password", type="password",
                                             placeholder="Re-enter password")

            st.markdown("---")
            agree_terms = st.checkbox(
                "I have read and agree to the [AI Shopping Agent Terms of Service](#) and [Privacy Policy](#)"
            )

            if st.button("🚀 Sign Up", type="primary", use_container_width=True):
                clean_email = email.strip().lower()
                pwd_ok, pwd_err = validate_password(password)

                if not agree_terms:
                    st.error("❌ You must agree to the legal agreements before signing up!")
                elif not clean_email:
                    st.error("❌ Please enter your email!")
                elif clean_email in st.session_state.users_db:
                    st.error("❌ This email is already registered. Please use Log In instead!")
                elif not st.session_state.simulated_code:
                    st.error("❌ Please click Send code first!")
                elif (st.session_state.code_sent_at is None
                      or time.time() - st.session_state.code_sent_at > 300):
                    st.error("❌ Verification code expired (>5 minutes). Please resend!")
                elif not verify_code or verify_code != st.session_state.simulated_code:
                    st.error("❌ Incorrect verification code!")
                elif not pwd_ok:
                    st.error(f"❌ {pwd_err}")
                elif password != confirm_password:
                    st.error("❌ Passwords do not match!")
                else:
                    user_data = {
                        "email": clean_email,
                        "password": password,
                        "login_type": "email"
                    }
                    st.session_state.users_db[clean_email] = user_data
                    st.session_state.simulated_code = None
                    st.session_state.code_sent_at = None

                    st.success("🎉 Sign-up successful! Logging you in automatically...")
                    st.session_state.authenticated = True
                    st.session_state.user_info = user_data
                    time.sleep(1.2)
                    st.rerun()

        else:
            st.subheader("🔑 Log In")
            st.caption("Quick test account: `test@example.com` / password: `password123`")

            login_email = st.text_input("Email",
                                        placeholder="Enter your registered email").strip().lower()
            login_password = st.text_input("Password", type="password", placeholder="Enter password")

            if st.button("🔓 Log In", type="primary", use_container_width=True):
                if not login_email or not login_password:
                    st.error("❌ Please enter your email and password!")
                elif login_email not in st.session_state.users_db:
                    st.error("❌ This email is not registered. Please Sign Up first!")
                else:
                    user_data = st.session_state.users_db[login_email].copy()
                    if user_data["password"] != login_password:
                        st.error("❌ Incorrect password. Please try again!")
                    else:
                        user_data["login_type"] = "email"
                        st.success("✅ Login verified! Redirecting...")
                        st.session_state.authenticated = True
                        st.session_state.user_info = user_data
                        time.sleep(1)
                        st.rerun()


# ==========================================
# 5. “My” center
# ==========================================
def render_profile_navigation_home():
    st.title("👤 My Profile")
    st.caption("Choose a section to manage")
    st.divider()

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("""
        <div class="nav-card">
            <h3>💳 Payment Settings</h3>
            <p style="color:#aaa;">Manage bound bank accounts and transaction limits</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Go to Payment Settings ➔", key="btn_go_pay_settings", use_container_width=True):
            st.session_state.nav_location = "pay_settings"
            st.rerun()

        st.write("")
        st.markdown("""
        <div class="nav-card">
            <h3>📍 My Addresses</h3>
            <p style="color:#aaa;">Manage shipping addresses for your orders</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Go to Address Book ➔", key="btn_go_address", use_container_width=True):
            st.session_state.nav_location = "address"
            st.rerun()

    with c2:
        st.markdown("""
        <div class="nav-card">
            <h3>👛 My Wallet</h3>
            <p style="color:#aaa;">Top-up balance and passwordless auto-debit management</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Go to My Wallet ➔", key="btn_go_wallet", use_container_width=True):
            st.session_state.nav_location = "wallet"
            st.rerun()

        st.write("")
        st.markdown("""
        <div class="nav-card">
            <h3>📜 My History</h3>
            <p style="color:#aaa;">View past chats and completed orders</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Go to My History ➔", key="btn_go_records", use_container_width=True):
            st.session_state.nav_location = "records"
            st.rerun()


def _card_display_name(card: dict) -> str:
    tail = card.get("tail", "")
    ctype = card.get("type", "")
    if tail:
        return f"{card['bank']} (ending {tail}) · {ctype}"
    return f"{card['bank']} · {ctype}"


def render_bank_cards_section():
    st.subheader("💳 Bound Bank Accounts / Cards")

    if not st.session_state.bank_cards:
        st.info("📭 You haven't linked any bank account yet. Please add your first card below.")

    for card in list(st.session_state.bank_cards):
        editing = (st.session_state.editing_card_id == card["id"])

        with st.container():
            c1, c2, c3 = st.columns([6, 1, 1])
            with c1:
                st.write(f"🏦 **{card['bank']}** (ending {card.get('tail','')}) · {card['type']}")
            with c2:
                if st.button("✏️ Edit", key=f"edit_card_{card['id']}",
                             use_container_width=True):
                    st.session_state.editing_card_id = card["id"]
                    st.rerun()
            with c3:
                if st.button("🗑️ Delete", key=f"del_card_{card['id']}",
                             use_container_width=True):
                    st.session_state.bank_cards = [
                        x for x in st.session_state.bank_cards if x["id"] != card["id"]
                    ]
                    if st.session_state.editing_card_id == card["id"]:
                        st.session_state.editing_card_id = None
                    st.success("Bank card deleted.")
                    time.sleep(0.5)
                    st.rerun()

            if editing:
                st.markdown("**✏️ Edit this bank card**")
                with st.form(key=f"edit_card_form_{card['id']}"):
                    new_bank = st.text_input("Bank name", value=card["bank"],
                                             placeholder="e.g., Bank of China")
                    new_type = st.selectbox(
                        "Card type", ["Debit Card", "Credit Card"],
                        index=0 if card["type"] == "Debit Card" else 1
                    )
                    new_tail = st.text_input(
                        "Last 4 digits of card number",
                        value=card.get("tail", ""),
                        max_chars=4,
                        placeholder="e.g., 1234",
                    )
                    sub_c1, sub_c2 = st.columns(2)
                    with sub_c1:
                        save = st.form_submit_button("💾 Save", type="primary",
                                                     use_container_width=True)
                    with sub_c2:
                        cancel = st.form_submit_button("✖️ Cancel",
                                                       use_container_width=True)
                    if save:
                        if not new_bank.strip():
                            st.error("Bank name cannot be empty.")
                        elif not new_tail.strip() or not new_tail.strip().isdigit() or len(new_tail.strip()) != 4:
                            st.error("Last 4 digits must be exactly 4 numeric digits.")
                        else:
                            for x in st.session_state.bank_cards:
                                if x["id"] == card["id"]:
                                    x["bank"] = new_bank.strip()
                                    x["type"] = new_type
                                    x["tail"] = new_tail.strip()
                            st.session_state.editing_card_id = None
                            st.success("✅ Updated.")
                            time.sleep(0.6)
                            st.rerun()
                    if cancel:
                        st.session_state.editing_card_id = None
                        st.rerun()

            st.divider()

    with st.expander("➕ Add a new bank card", expanded=not st.session_state.bank_cards):
        with st.form("add_card_form"):
            nb = st.text_input("Bank name", placeholder="e.g., Bank of China")
            nt = st.selectbox("Card type", ["Debit Card", "Credit Card"])
            ntail = st.text_input("Last 4 digits of card number", max_chars=4, placeholder="e.g., 1234")
            submit_add = st.form_submit_button("➕ Add", type="primary",
                                               use_container_width=True)
            if submit_add:
                if not nb.strip():
                    st.error("Bank name cannot be empty.")
                elif not ntail.strip() or not ntail.strip().isdigit() or len(ntail.strip()) != 4:
                    st.error("Last 4 digits must be exactly 4 numeric digits.")
                else:
                    new_id = max([c["id"] for c in st.session_state.bank_cards], default=0) + 1
                    st.session_state.bank_cards.append({
                        "id": new_id,
                        "bank": nb.strip(),
                        "type": nt,
                        "tail": ntail.strip(),
                    })
                    st.success("✅ Added.")
                    time.sleep(0.6)
                    st.rerun()

    st.info("💡 Bank accounts are used for **large order direct debit** and for **topping up your wallet**.")


def render_addresses_section():
    st.subheader("📦 Shipping Address Book")

    if not st.session_state.address_list:
        st.info("📭 You haven't added any shipping address yet. Please add your first one below.")

    for addr in list(st.session_state.address_list):
        editing = (st.session_state.editing_address_id == addr["id"])

        with st.container():
            col_a, col_b, col_c, col_d = st.columns([4, 1, 1, 1])
            with col_a:
                default_tag = " :red[[Default]]" if addr["is_default"] else ""
                st.write(f"👤 **{addr['name']}** ({addr['phone']}){default_tag}")
                st.write(f"🏠 {addr['address']}")
            with col_b:
                if not addr["is_default"]:
                    if st.button("Set default", key=f"def_{addr['id']}",
                                 use_container_width=True):
                        for a in st.session_state.address_list:
                            a["is_default"] = (a["id"] == addr["id"])
                        st.rerun()
            with col_c:
                if st.button("✏️ Edit", key=f"edit_addr_{addr['id']}",
                             use_container_width=True):
                    st.session_state.editing_address_id = addr["id"]
                    st.rerun()
            with col_d:
                if st.button("🗑️ Delete", key=f"del_addr_{addr['id']}",
                             use_container_width=True):
                    st.session_state.address_list = [
                        a for a in st.session_state.address_list if a["id"] != addr["id"]
                    ]
                    if st.session_state.editing_address_id == addr["id"]:
                        st.session_state.editing_address_id = None
                    st.success("Address deleted.")
                    time.sleep(0.5)
                    st.rerun()

            if editing:
                st.markdown("**✏️ Edit this address**")
                with st.form(key=f"edit_addr_form_{addr['id']}"):
                    n_name = st.text_input("Recipient name", value=addr["name"])
                    n_phone = st.text_input("Phone number", value=addr["phone"])
                    n_addr = st.text_area("Detailed address", value=addr["address"])
                    n_def = st.checkbox("Set as default address", value=addr["is_default"])
                    sc1, sc2 = st.columns(2)
                    with sc1:
                        save = st.form_submit_button("💾 Save", type="primary",
                                                     use_container_width=True)
                    with sc2:
                        cancel = st.form_submit_button("✖️ Cancel",
                                                       use_container_width=True)
                    if save:
                        if not n_name.strip() or not n_phone.strip() or not n_addr.strip():
                            st.error("Name, phone and address cannot be empty.")
                        else:
                            for a in st.session_state.address_list:
                                if a["id"] == addr["id"]:
                                    a["name"] = n_name.strip()
                                    a["phone"] = n_phone.strip()
                                    a["address"] = n_addr.strip()
                                    a["is_default"] = bool(n_def)
                            if n_def:
                                for a in st.session_state.address_list:
                                    if a["id"] != addr["id"]:
                                        a["is_default"] = False
                            st.session_state.editing_address_id = None
                            st.success("✅ Updated.")
                            time.sleep(0.6)
                            st.rerun()
                    if cancel:
                        st.session_state.editing_address_id = None
                        st.rerun()

            st.divider()

    with st.expander("➕ Add a new shipping address", expanded=not st.session_state.address_list):
        with st.form("add_addr_form"):
            n_name = st.text_input("Recipient name")
            n_phone = st.text_input("Phone number")
            n_addr = st.text_area("Detailed address")
            n_def = st.checkbox("Set as default address", value=not st.session_state.address_list)
            sub = st.form_submit_button("➕ Add", type="primary",
                                        use_container_width=True)
            if sub:
                if not n_name.strip() or not n_phone.strip() or not n_addr.strip():
                    st.error("Name, phone and address cannot be empty.")
                else:
                    new_id = max([a["id"] for a in st.session_state.address_list],
                                 default=0) + 1
                    if n_def or not st.session_state.address_list:
                        for a in st.session_state.address_list:
                            a["is_default"] = False
                        n_def = True
                    st.session_state.address_list.append({
                        "id": new_id,
                        "name": n_name.strip(),
                        "phone": n_phone.strip(),
                        "address": n_addr.strip(),
                        "is_default": bool(n_def),
                    })
                    st.success("✅ Added.")
                    time.sleep(0.6)
                    st.rerun()


def render_profile_sub_page():
    current_loc = st.session_state.nav_location

    nav_cols = st.columns([1, 5])
    with nav_cols[0]:
        if st.button("⬅️ Back to My Profile"):
            st.session_state.nav_location = "profile_home"
            st.session_state.editing_address_id = None
            st.session_state.editing_card_id = None
            st.rerun()

    st.divider()

    if current_loc == "pay_settings":
        st.title("💳 Payment Settings")
        st.caption("Manage bank accounts and purchase transaction limits here.")

        tab_bank, tab_limits = st.tabs(["🏦 Bank Accounts", "⚙ Transaction Limits"])

        with tab_bank:
            render_bank_cards_section()

        with tab_limits:
            st.subheader("⚙ Adjust transaction limits")
            lim_c1, lim_c2 = st.columns(2)
            with lim_c1:
                new_single = st.number_input(
                    "Single transaction limit ($)", min_value=100.0, max_value=10000.0,
                    value=float(st.session_state.single_limit), step=500.0
                )
            with lim_c2:
                new_daily = st.number_input(
                    "Daily cumulative payment limit ($)", min_value=1000.0, max_value=50000.0,
                    value=float(st.session_state.daily_limit), step=1000.0
                )

            st.divider()
            verify_pwd = st.text_input("Enter your login password to confirm changes", type="password")

            if st.button("💾 Save Limits", type="primary"):
                current_user_pwd = (
                    st.session_state.user_info.get("password")
                    if st.session_state.user_info else None
                )
                if not verify_pwd or verify_pwd != current_user_pwd:
                    st.error("❌ Login password verification failed. Cannot modify!")
                elif new_single > new_daily:
                    st.error("❌ Single-transaction limit cannot be higher than the daily limit!")
                else:
                    st.session_state.single_limit = new_single
                    st.session_state.daily_limit = new_daily
                    st.success("✅ Updated!")
                    time.sleep(1)
                    st.rerun()

    elif current_loc == "wallet":
        st.markdown(f"""
        <div class="wallet-card">
            <h3>👛 Shopping E-Wallet</h3>
            <h1 style="margin: 10px 0;">${st.session_state.wallet_balance:,.2f}</h1>
        </div>
        """, unsafe_allow_html=True)

        st.subheader("💵 Wallet top-up")
        if not st.session_state.bank_cards:
            st.info("📭 You haven't linked any bank account yet. Please go to [Payment Settings → Bank Accounts] to add a card before topping up.")
        else:
            recharge_col1, recharge_col2 = st.columns([2, 1])
            with recharge_col1:
                select_bank = st.selectbox(
                    "Select a bank card for payment",
                    [_card_display_name(card) for card in st.session_state.bank_cards],
                )
                recharge_amount = st.number_input(
                    "Top-up amount ($)", min_value=10, max_value=10000, value=200, step=50
                )
            with recharge_col2:
                st.write("")
                st.write("")
                if st.button("🚀 Top up now", type="primary", use_container_width=True):
                    st.session_state.wallet_balance += recharge_amount
                    st.success(f"🎉 Topped up ${recharge_amount:.2f} from [{select_bank}] to your wallet!")
                    time.sleep(1)
                    st.rerun()

    elif current_loc == "address":
        render_addresses_section()

    elif current_loc == "records":
        rec_tab1, rec_tab2 = st.tabs(["💬 Chat History", "🛍 Purchase History"])
        with rec_tab1:
            if st.button("➕ Start a new conversation", type="primary"):
                new_idx = len(st.session_state.chat_sessions) + 1
                st.session_state.chat_sessions.append({
                    "session_id": f"CS-{new_idx:03d}",
                    "title": "New Shopping Chat",
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "messages": [
                        {"role": "assistant",
                         "content": "👋 Hi! I'm your **AI Shopping Agent across the whole web**.\n\nTell me what you'd like to buy, and I'll compare prices and place the order!"}
                    ]
                })
                st.session_state.current_session_index = len(st.session_state.chat_sessions) - 1
                st.session_state.nav_location = "chat"
                st.session_state.buy_stage = "none"
                st.session_state.recommend_step = 1
                st.session_state.target_product_category = ""
                st.session_state.pending_order = None
                st.session_state.candidate_options = []
                st.session_state.stage3_price_range = None
                st.session_state.stage4_no_match = False
                st.session_state.limit_exceeded = False
                st.session_state.limit_exceeded_order = None
                st.session_state.current_attributes = []
                st.session_state.current_price_range = (None, None)
                st.session_state.current_detail_req = ""
                st.rerun()

            st.markdown("##### 💬 Past conversations")
            for s_idx, session in enumerate(st.session_state.chat_sessions):
                title = session.get("title", "Untitled")
                created_at = session.get("created_at", "")
                head_c1, head_c2 = st.columns([5, 2])
                with head_c1:
                    st.markdown(f"**{s_idx+1}. {title}**")
                with head_c2:
                    st.markdown(
                        f'<div class="chat-meta" style="text-align:right;">🕒 {created_at}</div>',
                        unsafe_allow_html=True
                    )
                with st.expander(f"Show contents ({session['session_id']})", expanded=False):
                    for msg in session["messages"]:
                        st.write(f"**{msg['role'].upper()}**: {msg['content']}")
                st.divider()

        with rec_tab2:
            if not st.session_state.orders_history:
                st.info("No paid orders yet.")
            else:
                for ord_item in st.session_state.orders_history:
                    st.markdown(f"""
                    <div class="order-card">
                        <h4>{ord_item['title']}</h4>
                        <p>🏷️ <b>Platform</b>: {ord_item['platform']} | 🆔 <b>Order ID</b>: <code>{ord_item['order_id']}</code></p>
                        <p>💰 <b>Paid</b>: <span style="color:#FF4B4B; font-weight:bold;">${ord_item['final_price']}</span></p>
                        <p>📦 <b>Ship to</b>: {ord_item.get('shipping_address', 'Default address')}</p>
                        <p>💳 <b>Payment method</b>: {ord_item.get('payment_method', 'Unknown')}</p>
                        <p>🕒 <b>Paid at</b>: {ord_item.get('paid_at', 'Unknown')}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    if ord_item.get("source_url"):
                        st.markdown(f"🔗 [View original product page]({ord_item['source_url']})")


# ==========================================
# 6. Main chat interface
# ==========================================
def render_order_card(order: dict, key_prefix: str = ""):
    st.subheader(order.get("title", "Untitled product"))
    st.write(f"🏷️ **Recommended platform**: {order.get('platform', 'Unknown')}")
    st.write(f"🆔 **Order ID**: `{order.get('order_id', '')}`")
    if order.get("reason"):
        st.write(f"💡 **Reason**: {order['reason']}")
    st.markdown(f"### Price after coupon: :red[${order.get('final_price', 0)}]")

    src = order.get("source_url", "")
    site = order.get("source_site", "")
    platform = order.get("platform", "")

    if src and _is_product_detail_url(src):
        st.markdown(f"🔗 **Source site**: {site or platform or 'Official platform'}")
        st.markdown(f"👉 [Open product detail page]({src})")
        st.text_input(
            "📋 Copy link (click the icon on the right or select all to copy)",
            value=src,
            key=f"copy_{key_prefix}_{order.get('order_id', random.random())}",
        )
    else:
        st.warning("⚠️ No real product detail URL could be attached to this item. It has been hidden.")


def render_address_selection():
    st.divider()
    st.subheader("📍 Choose a shipping address")

    if not st.session_state.address_list:
        st.info("📭 You don't have any shipping address yet. Please fill in a new one:")
        new_name = st.text_input("Recipient name", key="only_new_addr_name")
        new_phone = st.text_input("Recipient phone number", key="only_new_addr_phone")
        new_addr = st.text_area(
            "Detailed address",
            key="only_new_addr_detail",
            placeholder="e.g., Room 302, Building 5, XX Community, 100 Century Avenue, Pudong New Area, Shanghai",
        )
        if st.button("➡️ Save address and proceed to payment", type="primary",
                     use_container_width=True, key="only_new_addr_confirm"):
            if not new_name.strip() or not new_phone.strip() or not new_addr.strip():
                st.error("❌ Please fill in name, phone and detailed address completely!")
            else:
                addr_obj = {
                    "id": 1,
                    "name": new_name.strip(),
                    "phone": new_phone.strip(),
                    "address": new_addr.strip(),
                    "is_default": True,
                }
                st.session_state.address_list.append(addr_obj)
                st.session_state.selected_address_for_order = addr_obj
                st.session_state.buy_stage = "payment"
                st.session_state.payment_code = None
                st.session_state.payment_code_sent_at = None
                st.rerun()
        return

    addr_options = []
    for a in st.session_state.address_list:
        tag = " [Default]" if a["is_default"] else ""
        addr_options.append(f"{a['name']} - {a['phone']} - {a['address']}{tag}")
    addr_options.append("➕ Enter a new address for this order")

    default_idx = next(
        (i for i, a in enumerate(st.session_state.address_list) if a["is_default"]), 0
    )

    selected_idx = st.radio(
        "Select a shipping address",
        range(len(addr_options)),
        format_func=lambda i: addr_options[i],
        index=default_idx,
        key="addr_radio",
    )

    st.markdown('<div class="addr-tip">Don\'t see your address? Tell me a new one.</div>',
                unsafe_allow_html=True)

    is_new_address = (selected_idx == len(st.session_state.address_list))

    if is_new_address:
        new_name = st.text_input("Recipient name", key="new_addr_name")
        new_phone = st.text_input("Recipient phone number", key="new_addr_phone")
        new_addr = st.text_area("Detailed address", key="new_addr_detail",
                                placeholder="e.g., Room 302, Building 5, XX Community, 100 Century Avenue, Pudong New Area, Shanghai")

        if st.button("➡️ Save and use this new address, proceed to payment", type="primary",
                     use_container_width=True, key="new_addr_confirm"):
            if not new_name.strip() or not new_phone.strip() or not new_addr.strip():
                st.error("❌ Please fill in name, phone and detailed address completely!")
            else:
                new_id = max([a["id"] for a in st.session_state.address_list], default=0) + 1
                addr_obj = {
                    "id": new_id,
                    "name": new_name.strip(),
                    "phone": new_phone.strip(),
                    "address": new_addr.strip(),
                    "is_default": False,
                }
                st.session_state.address_list.append(addr_obj)
                st.session_state.selected_address_for_order = addr_obj
                st.session_state.buy_stage = "payment"
                st.session_state.payment_code = None
                st.session_state.payment_code_sent_at = None
                st.rerun()
    else:
        chosen = st.session_state.address_list[selected_idx]
        st.caption(f"Selected: {chosen['name']} · {chosen['phone']} · {chosen['address']}")

        if st.button("➡️ Confirm address, proceed to payment", type="primary",
                     use_container_width=True, key="addr_confirm"):
            st.session_state.selected_address_for_order = chosen
            st.session_state.buy_stage = "payment"
            st.session_state.payment_code = None
            st.session_state.payment_code_sent_at = None
            st.rerun()


def _render_inline_add_bank_form(form_key: str = "inline_add_bank"):
    st.markdown("**➕ Add a new bank card**")
    with st.form(key=form_key):
        nb = st.text_input("Bank name", placeholder="e.g., Bank of China")
        nt = st.selectbox("Card type", ["Debit Card", "Credit Card"])
        ntail = st.text_input("Last 4 digits of card number", max_chars=4, placeholder="e.g., 1234")
        sub = st.form_submit_button("➕ Add and use this card", type="primary",
                                    use_container_width=True)
        if sub:
            if not nb.strip():
                st.error("Bank name cannot be empty.")
                return None
            if not ntail.strip() or not ntail.strip().isdigit() or len(ntail.strip()) != 4:
                st.error("Last 4 digits must be exactly 4 numeric digits.")
                return None
            new_id = max([c["id"] for c in st.session_state.bank_cards], default=0) + 1
            new_card = {
                "id": new_id,
                "bank": nb.strip(),
                "type": nt,
                "tail": ntail.strip(),
            }
            st.session_state.bank_cards.append(new_card)
            st.success("✅ Bank card added.")
            return new_card
    return None


def render_payment_section():
    order = st.session_state.pending_order
    final_price = float(order["final_price"])

    st.subheader("💳 Order Payment")
    render_order_card(order, key_prefix="pay")
    st.markdown(f"### Amount due: :red[${final_price:.2f}]")

    addr = st.session_state.selected_address_for_order
    if addr:
        st.info(f"📦 Shipping address: **{addr['name']}** · {addr['phone']} · {addr['address']}")

    wallet_balance = st.session_state.wallet_balance
    if wallet_balance >= final_price:
        default_method = "👛 Wallet balance (preferred)"
        st.success(f"✅ Your wallet balance (${wallet_balance:.2f}) is enough for this order. It will be **deducted from the wallet first**.")
    else:
        default_method = "🏦 Direct bank debit"
        st.warning(
            f"⚠️ Your wallet balance (${wallet_balance:.2f}) is insufficient for ${final_price:.2f}. "
            f"**Direct bank debit** will be used (requires login password re-authentication)."
        )

    pay_method = st.radio(
        "Choose payment method",
        ["👛 Wallet balance (preferred)", "🏦 Direct bank debit"],
        index=0 if "👛 Wallet balance (preferred)" == default_method else 1,
        horizontal=True,
        key="pay_method_radio",
    )

    if pay_method == "👛 Wallet balance (preferred)" and wallet_balance < final_price:
        st.error("❌ Wallet balance is not enough. Please choose direct bank debit.")
        return

    selected_card = None
    if pay_method == "🏦 Direct bank debit":
        if not st.session_state.bank_cards:
            st.info("📭 You haven't linked any bank account yet. Please add a card for this payment:")
            new_card = _render_inline_add_bank_form("pay_inline_add_bank")
            if new_card is not None:
                selected_card = _card_display_name(new_card)
                st.rerun()
            else:
                st.stop()
        else:
            options = [_card_display_name(c) for c in st.session_state.bank_cards]
            selected_card = st.selectbox(
                "Select the bank account to debit",
                options,
                key="pay_bank_select",
            )

    st.divider()
    st.markdown("### 🔐 One-time payment password verification")

    order_id = order["order_id"]
    if (
        st.session_state.payment_code is None
        or st.session_state.payment_code_order_id != order_id
    ):
        code = generate_12digit_code()
        st.session_state.payment_code = code
        st.session_state.payment_code_sent_at = time.time()
        st.session_state.payment_code_order_id = order_id

        user_email = st.session_state.user_info.get("email") if st.session_state.user_info else ""
        if user_email and st.session_state.get("smtp_user"):
            with st.spinner("Sending the one-time payment password to your email..."):
                ok, err = send_payment_code_email(user_email, code, order)
            if ok:
                st.success(f"📩 One-time payment password sent to {user_email}. Valid for 10 minutes.")
            else:
                st.error(f"❌ Failed to send email: {err}")
        else:
            st.warning("⚠️ Sender email not configured or user email not available. Cannot send.")

    user_pay_code = st.text_input(
        "Enter the one-time payment password you received by email (12 alphanumeric characters)",
        type="password",
        max_chars=12,
        key="user_pay_code_input",
    )

    need_login_pwd_verify = (pay_method == "🏦 Direct bank debit")
    user_login_pwd = None
    if need_login_pwd_verify:
        if final_price > st.session_state.max_limit:
            st.warning(
                f"🔐 This bank card transaction of ${final_price:.2f} exceeds the password-free threshold "
                f"of ${st.session_state.max_limit:.2f}. You must enter your **login password** to re-authenticate."
            )
        else:
            st.info("🔐 Bank card payment requires your **login password** for re-authentication.")
        user_login_pwd = st.text_input(
            "Enter your login password to complete bank card authentication",
            type="password",
            key="bank_login_pwd",
        )

    if st.button("✅ Confirm payment", type="primary", use_container_width=True,
                 key="final_pay_confirm"):
        if not user_pay_code:
            st.error("❌ Please enter the one-time payment password you received by email!")
            st.stop()
        if user_pay_code != st.session_state.payment_code:
            st.error("❌ Incorrect one-time payment password!")
            st.stop()
        if (st.session_state.payment_code_sent_at is None
                or time.time() - st.session_state.payment_code_sent_at > 600):
            st.error("❌ The one-time payment password has expired (>10 minutes). Please resend!")
            st.stop()

        if need_login_pwd_verify:
            current_pwd = (
                st.session_state.user_info.get("password")
                if st.session_state.user_info else None
            )
            if not user_login_pwd:
                st.error("❌ Please enter your login password!")
                st.stop()
            if user_login_pwd != current_pwd:
                st.error("❌ Incorrect login password. Authentication failed!")
                st.stop()
            if not st.session_state.bank_cards:
                st.error("❌ Please add a bank card before paying!")
                st.stop()

        payment_method_text = ""
        if pay_method == "👛 Wallet balance (preferred)":
            st.session_state.wallet_balance -= final_price
            payment_method_text = "👛 Wallet balance"
        else:
            payment_method_text = f"🏦 {selected_card or _card_display_name(st.session_state.bank_cards[0])}"

        addr = st.session_state.selected_address_for_order
        paid_at_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        st.session_state.orders_history.append({
            "order_id": order["order_id"],
            "title": order["title"],
            "platform": order["platform"],
            "final_price": final_price,
            "shipping_address": f"{addr['name']} · {addr['phone']} · {addr['address']}" if addr else "Default address",
            "payment_method": payment_method_text,
            "source_url": order.get("source_url", ""),
            "paid_at": paid_at_str,
        })

        user_email = st.session_state.user_info.get("email") if st.session_state.user_info else ""
        if user_email and st.session_state.get("smtp_user"):
            with st.spinner("Payment succeeded. The merchant is sending the receipt email..."):
                ok, err = send_receipt_email(user_email, order, paid_at_str)
            if ok:
                st.success(f"📧 Receipt email sent to {user_email}")
            else:
                st.warning(f"⚠️ Failed to send receipt email: {err}")
        else:
            st.info("ℹ️ Sender email not configured. Skipping receipt email.")

        end_conversation(reason=f"🎉 Payment successful! Method: {payment_method_text}, amount: ${final_price:.2f}")


def end_conversation(reason: str = ""):
    current_session = st.session_state.chat_sessions[st.session_state.current_session_index]
    current_session["messages"].append({
        "role": "assistant",
        "content": (reason + "\n\n" if reason else "") +
                   "This shopping session has ended. A new chat window has been started for you."
    })

    new_idx = len(st.session_state.chat_sessions) + 1
    st.session_state.chat_sessions.append({
        "session_id": f"CS-{new_idx:03d}",
        "title": "New Shopping Chat",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "messages": [
            {"role": "assistant",
             "content": "👋 A new conversation has started! Tell me what you'd like to buy, and I'll compare prices, recommend products and complete the purchase for you."}
        ]
    })
    st.session_state.current_session_index = len(st.session_state.chat_sessions) - 1

    st.session_state.pending_order = None
    st.session_state.buy_stage = "none"
    st.session_state.recommend_step = 1
    st.session_state.target_product_category = ""
    st.session_state.candidate_options = []
    st.session_state.stage3_price_range = None
    st.session_state.stage4_no_match = False
    st.session_state.limit_exceeded = False
    st.session_state.limit_exceeded_order = None
    st.session_state.selected_address_for_order = None
    st.session_state.payment_code = None
    st.session_state.payment_code_sent_at = None
    st.session_state.payment_code_order_id = None
    st.session_state.current_attributes = []
    st.session_state.current_price_range = (None, None)
    st.session_state.current_detail_req = ""

    time.sleep(1)
    st.rerun()


def reset_current_conversation(new_product: str = None):
    st.session_state.pending_order = None
    st.session_state.buy_stage = "none"
    st.session_state.recommend_step = 1
    st.session_state.candidate_options = []
    st.session_state.stage3_price_range = None
    st.session_state.stage4_no_match = False
    st.session_state.limit_exceeded = False
    st.session_state.limit_exceeded_order = None
    st.session_state.selected_address_for_order = None
    st.session_state.payment_code = None
    st.session_state.payment_code_sent_at = None
    st.session_state.payment_code_order_id = None
    st.session_state.current_attributes = []
    st.session_state.current_price_range = (None, None)
    st.session_state.current_detail_req = ""

    if new_product:
        st.session_state.target_product_category = new_product


def _update_current_session_title(product_category: str):
    if not product_category:
        return
    current_session = st.session_state.chat_sessions[st.session_state.current_session_index]
    if current_session.get("title") in ("First Shopping Consultation", "New Shopping Chat", "", None):
        title = product_category.strip()
        if len(title) > 12:
            title = title[:12] + "..."
        current_session["title"] = title


def _generate_constrained_options(item_category, detail_req, attributes, min_price, max_price, history):
    return call_deepseek_recommend_engine(
        step=4,
        item_category=item_category,
        user_history=history,
        extra_constraints={
            "detail_req": detail_req,
            "attributes": attributes,
            "min_price": min_price,
            "max_price": max_price,
        }
    )


def render_chat_agent():
    st.title("🤖 Auto-Payment AI Shopping Agent")
    st.caption("Powered by DeepSeek · Tencent Cloud real-time web price comparison · Lock the required category · Smart attributes & price detection · Taobao / Tmall / JD / Pinduoduo / VIP.com only")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("My wallet balance", f"${st.session_state.wallet_balance:.2f}")
    with col2:
        st.metric("Completed purchases", f"{len(st.session_state.orders_history)} order(s)")

    st.divider()

    current_session = st.session_state.chat_sessions[st.session_state.current_session_index]
    for message in current_session["messages"]:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if st.session_state.buy_stage in ("confirm_product", "select_address", "payment"):
        tags = []
        if st.session_state.target_product_category:
            tags.append(f"🎯 Category: {st.session_state.target_product_category}")
        for a in st.session_state.current_attributes:
            tags.append(f"🎨 {a}")
        pmin, pmax = st.session_state.current_price_range
        if pmin is not None or pmax is not None:
            if pmin is not None and pmax is not None:
                tags.append(f"💰 ${pmin}~${pmax}")
            elif pmin is not None:
                tags.append(f"💰 ≥${pmin}")
            else:
                tags.append(f"💰 ≤${pmax}")
        tags.append("🛒 Platform: Taobao/Tmall/JD/Pinduoduo/VIP.com")
        if tags:
            st.markdown(
                "".join(f'<span class="intent-tag">{t}</span>' for t in tags),
                unsafe_allow_html=True
            )
            st.write("")

    if st.session_state.limit_exceeded and st.session_state.limit_exceeded_order:
        st.markdown(
            '<div class="limit-tip">'
            'Sorry, the product you selected exceeds your configured payment limit. '
            'Please update the limit in your profile or choose a product within the limit.'
            '</div>',
            unsafe_allow_html=True
        )
        order = st.session_state.limit_exceeded_order
        render_order_card(order, key_prefix="limit")

        lc1, lc2 = st.columns(2)
        with lc1:
            if st.button("⚙️ Go to profile to update the limit", type="primary",
                         use_container_width=True, key="limit_go_settings"):
                end_conversation(reason="The session has ended. Please update the limit in your profile.")
                st.session_state.nav_location = "pay_settings"
                st.rerun()
        with lc2:
            if st.button("🔁 Choose another product within the limit", use_container_width=True,
                         key="limit_reselect"):
                st.session_state.limit_exceeded = False
                st.session_state.limit_exceeded_order = None
                st.session_state.pending_order = None
                st.session_state.buy_stage = "confirm_product"
                st.session_state.recommend_step = 1
                st.session_state.candidate_options = []

                with st.spinner("Comparing prices online again..."):
                    result = call_deepseek_recommend_engine(
                        step=1,
                        item_category=st.session_state.target_product_category,
                        user_history=current_session["messages"]
                    )
                    st.session_state.pending_order = result if result else None
                    if not result:
                        st.session_state.stage4_no_match = True
                        st.session_state.buy_stage = "confirm_product"
                        st.session_state.recommend_step = 4
                st.rerun()

    elif st.session_state.buy_stage == "confirm_product" and st.session_state.recommend_step == 1:
        order = st.session_state.pending_order
        if not order:
            st.warning("😔 No product with a real product detail URL could be found in this category. Please try another category or broaden your requirements.")
            st.markdown(
                '<div class="no-more-tip">'
                "Sorry, we could not find a matching product with a real product page on "
                "Taobao / Tmall / JD / Pinduoduo / VIP.com. Please try a different keyword."
                '</div>',
                unsafe_allow_html=True
            )
            if st.button("🆕 Start a new search", use_container_width=True, key="s1_none_restart"):
                reset_current_conversation()
                st.rerun()
        else:
            st.warning("Here is the top overall match for you:")
            render_order_card(order, key_prefix="s1")

            btn_c1, btn_c2, _ = st.columns([1, 1, 2])
            with btn_c1:
                if st.button("✅ Satisfied (choose this product)", type="primary", use_container_width=True,
                             key="s1_ok"):
                    exceeded, msg = check_order_limits(order)
                    if exceeded:
                        st.session_state.limit_exceeded = True
                        st.session_state.limit_exceeded_order = order
                        st.session_state.pending_order = None
                        current_session["messages"].append({
                            "role": "assistant", "content": msg
                        })
                        st.rerun()
                    else:
                        st.session_state.buy_stage = "select_address"
                        st.session_state.selected_address_for_order = None
                        current_session["messages"].append({"role": "user", "content": "Satisfied. Let's go with this one."})
                        st.rerun()
            with btn_c2:
                if st.button("❌ Not satisfied (show another batch)", use_container_width=True, key="s1_no"):
                    st.session_state.recommend_step = 2
                    st.session_state.candidate_options = []
                    with st.spinner("Searching best options by [price], [reviews] and [sales]..."):
                        c_options = call_deepseek_recommend_engine(
                            step=2,
                            item_category=st.session_state.target_product_category,
                            user_history=current_session["messages"],
                            extra_constraints={
                                "attributes": st.session_state.current_attributes,
                                "min_price": st.session_state.current_price_range[0],
                                "max_price": st.session_state.current_price_range[1],
                            }
                        )
                        st.session_state.candidate_options = c_options
                    st.rerun()

    elif st.session_state.buy_stage == "confirm_product" and st.session_state.recommend_step == 2:
        options = st.session_state.candidate_options
        if not options:
            st.markdown(
                '<div class="no-more-tip">'
                "Sorry, we could not find matching products with real product detail pages "
                "on Taobao / Tmall / JD / Pinduoduo / VIP.com."
                '</div>',
                unsafe_allow_html=True
            )
            if st.button("🆕 Start a new search", use_container_width=True, key="s2_none_restart"):
                reset_current_conversation()
                st.rerun()
        else:
            st.info("Below are three options picked from three different dimensions")
            for idx, opt in enumerate(options):
                with st.container():
                    st.markdown(f"### 🔹 {opt.get('dimension', f'Option {idx+1}')}")
                    render_order_card(opt, key_prefix=f"s2_{idx}")
                    if st.button(f"Choose this option ({idx+1})", key=f"pick_s2_{idx}",
                                 type="primary", use_container_width=True):
                        exceeded, msg = check_order_limits(opt)
                        if exceeded:
                            st.session_state.limit_exceeded = True
                            st.session_state.limit_exceeded_order = opt
                            current_session["messages"].append({
                                "role": "assistant", "content": msg
                            })
                            st.rerun()
                        else:
                            st.session_state.pending_order = opt
                            st.session_state.buy_stage = "select_address"
                            st.session_state.selected_address_for_order = None
                            current_session["messages"].append({
                                "role": "user", "content": f"I choose option: {opt['title']}"
                            })
                            st.rerun()
                    st.divider()

            if st.button("🔍 None of them. Filter by budget instead", key="s2_go3"):
                st.session_state.recommend_step = 3
                st.session_state.candidate_options = []
                with st.spinner("Estimating a reasonable price range for this product based on online market prices..."):
                    lo, hi = estimate_price_range(st.session_state.target_product_category)
                st.session_state.stage3_price_range = (lo, hi)
                st.rerun()

    elif st.session_state.buy_stage == "confirm_product" and st.session_state.recommend_step == 3:
        st.info("Please set your budget range. The Agent will match precisely:")

        if st.session_state.stage3_price_range is None:
            with st.spinner("Estimating a reasonable price range for this product based on online market prices..."):
                lo, hi = estimate_price_range(st.session_state.target_product_category)
            st.session_state.stage3_price_range = (lo, hi)

        lo, hi = st.session_state.stage3_price_range
        st.caption(f"💡 Based on online market prices, the reasonable price for [{st.session_state.target_product_category}] is about ${lo} ~ ${hi}")

        price_range = st.slider(
            "Budget range ($)",
            min_value=int(lo),
            max_value=int(hi),
            value=(int(lo), int(hi)),
            step=10,
            format="$%d"
        )

        if st.button("🎯 Start precise matching", type="primary", use_container_width=True,
                     key="s3_match"):
            with st.spinner("Filtering by your budget..."):
                result = call_deepseek_recommend_engine(
                    step=3,
                    item_category=st.session_state.target_product_category,
                    user_history=current_session["messages"],
                    extra_constraints={
                        "min_price": price_range[0],
                        "max_price": price_range[1],
                        "attributes": st.session_state.current_attributes,
                    }
                )
                st.session_state.pending_order = result if result else None
                st.session_state.current_price_range = (price_range[0], price_range[1])
                if not result:
                    st.session_state.stage4_no_match = True
                    st.session_state.recommend_step = 4

        if st.session_state.pending_order and st.session_state.recommend_step == 3:
            order = st.session_state.pending_order
            st.success("✅ **Precise matching complete**")
            render_order_card(order, key_prefix="s3")

            if st.button("✅ Choose this product", type="primary", use_container_width=True,
                         key="s3_ok"):
                exceeded, msg = check_order_limits(order)
                if exceeded:
                    st.session_state.limit_exceeded = True
                    st.session_state.limit_exceeded_order = order
                    st.session_state.pending_order = None
                    current_session["messages"].append({
                        "role": "assistant", "content": msg
                    })
                    st.rerun()
                else:
                    st.session_state.buy_stage = "select_address"
                    st.session_state.selected_address_for_order = None
                    st.rerun()

            if st.button("🔍 Still not satisfied. Add more detailed requirements", key="s3_go4"):
                st.session_state.recommend_step = 4
                st.session_state.candidate_options = []
                st.session_state.pending_order = None
                st.session_state.stage4_no_match = False
                st.rerun()

    elif st.session_state.buy_stage == "confirm_product" and st.session_state.recommend_step == 4:
        if st.session_state.stage4_no_match:
            st.markdown(
                '<div class="no-more-tip">'
                "😔 Sorry, for more specific products please browse the e-commerce platforms directly."
                '</div>',
                unsafe_allow_html=True
            )
            st.markdown("Please choose what to do next:")
            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("🔚 End this conversation", type="primary", use_container_width=True,
                             key="s4_end"):
                    end_conversation(reason="Thank you for using the service!")
            with c2:
                if st.button("🔙 Back to previously recommended products", use_container_width=True,
                             key="s4_back"):
                    st.session_state.stage4_no_match = False
                    st.session_state.recommend_step = 2
                    with st.spinner("Reloading previously recommended products..."):
                        c_options = call_deepseek_recommend_engine(
                            step=2,
                            item_category=st.session_state.target_product_category,
                            user_history=current_session["messages"],
                            extra_constraints={
                                "attributes": st.session_state.current_attributes,
                                "min_price": st.session_state.current_price_range[0],
                                "max_price": st.session_state.current_price_range[1],
                            }
                        )
                        st.session_state.candidate_options = c_options
                    st.rerun()
            with c3:
                if st.button("🆕 Shop for something else", use_container_width=True,
                             key="s4_new"):
                    reset_current_conversation()
                    current_session["messages"].append({
                        "role": "assistant",
                        "content": "Sure! Tell me what you want to buy this time and I'll compare prices online."
                    })
                    st.rerun()
        else:
            st.info("Please add more detailed requirements. The Agent will select up to 5 products for you:")
            detail_req = st.text_area(
                "Detailed requirements",
                value=st.session_state.current_detail_req,
                placeholder="e.g., black color, fast charging, brand warranty, invoice needed, capacity >= 20000mAh..."
            )

            col_a, col_b = st.columns([1, 1])
            with col_a:
                if st.button("🔎 Generate curated products", type="primary",
                             use_container_width=True, key="s4_gen"):
                    if not detail_req.strip():
                        st.error("Please fill in your detailed requirements!")
                    else:
                        st.session_state.current_detail_req = detail_req
                        with st.spinner("Curating products that best match your requirements..."):
                            options = _generate_constrained_options(
                                item_category=st.session_state.target_product_category,
                                detail_req=detail_req,
                                attributes=st.session_state.current_attributes,
                                min_price=st.session_state.current_price_range[0],
                                max_price=st.session_state.current_price_range[1],
                                history=current_session["messages"],
                            )
                            st.session_state.candidate_options = options
                            if not options:
                                st.session_state.stage4_no_match = True
                                st.session_state.candidate_options = []
            with col_b:
                if st.button("🙅 Still not satisfied. Let me think", use_container_width=True,
                             key="s4_reject"):
                    st.session_state.stage4_no_match = True
                    st.session_state.candidate_options = []
                    st.rerun()

            if st.session_state.candidate_options:
                for idx, opt in enumerate(st.session_state.candidate_options):
                    opt_uid = opt.get("option_id", idx)
                    with st.container():
                        render_order_card(opt, key_prefix=f"s4_{opt_uid}")
                        if st.button("Choose this one", key=f"pick_s4_{opt_uid}",
                                     type="primary", use_container_width=True):
                            exceeded, msg = check_order_limits(opt)
                            if exceeded:
                                st.session_state.limit_exceeded = True
                                st.session_state.limit_exceeded_order = opt
                                current_session["messages"].append({
                                    "role": "assistant", "content": msg
                                })
                                st.rerun()
                            else:
                                st.session_state.pending_order = opt
                                st.session_state.buy_stage = "select_address"
                                st.session_state.selected_address_for_order = None
                                st.rerun()
                        st.divider()

    elif st.session_state.buy_stage == "select_address":
        st.success("🎉 **Product selected! Please confirm the shipping address:**")
        order = st.session_state.pending_order
        render_order_card(order, key_prefix="addr")
        render_address_selection()

    elif st.session_state.buy_stage == "payment":
        render_payment_section()

    user_input = st.chat_input("Tell me what you'd like to buy, e.g., Help me buy a 20000mAh fast-charging power bank / a black camera around $1000")

    if user_input:
        current_session["messages"].append({"role": "user", "content": user_input})

        with st.spinner("Understanding your request..."):
            intent = parse_user_intent(
                user_input, st.session_state.target_product_category
            )

        new_category = (intent.get("category") or "").strip()
        min_price = intent.get("min_price")
        max_price = intent.get("max_price")
        attributes = intent.get("attributes") or []
        has_price_constraint = (min_price is not None) or (max_price is not None)
        has_any_constraint = has_price_constraint or bool(attributes)

        already_in_flow = st.session_state.buy_stage in (
            "confirm_product", "select_address", "payment"
        )

        if not new_category:
            new_category = user_input.strip()

        category_changed = False
        if already_in_flow:
            current_cat = st.session_state.target_product_category or ""
            if intent.get("changed"):
                category_changed = True
            elif new_category and new_category != current_cat and len(new_category) >= 2:
                category_changed = True
        else:
            category_changed = True

        if category_changed:
            reset_current_conversation(new_product=new_category)
            st.session_state.target_product_category = new_category
            st.session_state.current_attributes = attributes
            st.session_state.current_price_range = (min_price, max_price)
            st.session_state.current_detail_req = user_input
            _update_current_session_title(new_category)

            if has_any_constraint:
                with st.spinner("Curating products based on your specific requirements..."):
                    options = _generate_constrained_options(
                        item_category=new_category,
                        detail_req=user_input,
                        attributes=attributes,
                        min_price=min_price,
                        max_price=max_price,
                        history=current_session["messages"],
                    )
                    st.session_state.candidate_options = options
                    st.session_state.buy_stage = "confirm_product"
                    st.session_state.recommend_step = 4
                    st.session_state.stage4_no_match = not options
                current_session["messages"].append({
                    "role": "assistant",
                    "content": f"Great! Products curated based on your requirements ({user_input}) →"
                })
            else:
                with st.spinner("Comparing prices online for you..."):
                    result = call_deepseek_recommend_engine(
                        step=1,
                        item_category=new_category,
                        user_history=current_session["messages"]
                    )
                    st.session_state.pending_order = result if result else None
                    st.session_state.buy_stage = "confirm_product"
                    st.session_state.recommend_step = 1
                    if not result:
                        st.session_state.stage4_no_match = True
                current_session["messages"].append({
                    "role": "assistant",
                    "content": f"I've compared prices across the web for [{new_category}]. Please see the recommendation below →"
                })
            st.rerun()

        elif already_in_flow and has_any_constraint:
            merged_attrs = list(set(st.session_state.current_attributes + attributes))
            cur_min, cur_max = st.session_state.current_price_range
            merged_min = min_price if min_price is not None else cur_min
            merged_max = max_price if max_price is not None else cur_max

            st.session_state.current_attributes = merged_attrs
            st.session_state.current_price_range = (merged_min, merged_max)
            st.session_state.current_detail_req = user_input

            with st.spinner("Re-curating products based on your additional conditions..."):
                options = _generate_constrained_options(
                    item_category=st.session_state.target_product_category,
                    detail_req=user_input,
                    attributes=merged_attrs,
                    min_price=merged_min,
                    max_price=merged_max,
                    history=current_session["messages"],
                )
                st.session_state.candidate_options = options
                st.session_state.buy_stage = "confirm_product"
                st.session_state.recommend_step = 4
                st.session_state.stage4_no_match = not options
                st.session_state.pending_order = None
            current_session["messages"].append({
                "role": "assistant",
                "content": "Re-curated products based on your additional conditions →"
            })
            st.rerun()

        else:
            st.rerun()


# ==========================================
# 7. Main entry
# ==========================================
def main():
    if not st.session_state.authenticated:
        render_welcome_page()
        return

    with st.sidebar:
        st.markdown("## 🧭 Navigation")
        if st.button("🤖 AI Shopping", use_container_width=True):
            st.session_state.nav_location = "chat"
            st.rerun()
        if st.button("👤 My Profile", use_container_width=True):
            st.session_state.nav_location = "profile_home"
            st.rerun()
        st.divider()
        if st.button("🚪 Log Out", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.user_info = None
            st.session_state.nav_location = "chat"
            st.rerun()

    loc = st.session_state.nav_location
    if loc == "chat":
        render_chat_agent()
    elif loc == "profile_home":
        render_profile_navigation_home()
    elif loc in ["pay_settings", "wallet", "address", "records"]:
        render_profile_sub_page()
    else:
        render_chat_agent()


if __name__ == "__main__":
    main()