from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from fastapi.middleware.cors import CORSMiddleware
import bcrypt
import uvicorn
import re
import pickle
import os
import json
import secrets
import hashlib
import numpy as np
import tldextract
import joblib
from datetime import datetime, timedelta
import requests
from dotenv import load_dotenv
from database import (
    client,                  # ← imported so startup ping works
    users_collection,
    url_scans_collection,
    reports_collection,
    risk_keywords_collection,
    login_logs_collection,
)

# ── Gmail SMTP ──
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

load_dotenv()
FAST2SMS_API_KEY = os.getenv("FAST2SMS_API_KEY")

# ── Gmail credentials from .env ──
GMAIL_SENDER   = os.getenv("GMAIL_USER")
GMAIL_PASSWORD = os.getenv("GMAIL_PASSWORD")

app = FastAPI(title="TrustShield API", description="AI Powered Scam Detection Platform")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ══════════════════════════════════════════
#   Startup – verify MongoDB is reachable
# ══════════════════════════════════════════

# @app.on_event("startup")
# async def startup_db_check():
#     try:
#         await client.admin.command("ping")
#         print("✅ MongoDB connection verified on startup.")
#         # ── Print collection counts so you know data exists ──
#         u = await users_collection.count_documents({})
#         s = await url_scans_collection.count_documents({})
#         r = await reports_collection.count_documents({})
#         print(f"   📊 users={u}  url_scans={s}  reports={r}")
#     except Exception as e:
#         print(f"❌ MongoDB connection FAILED on startup: {e}")
#         print("   ► Check MONGO_URI in your .env file.")
#         print("   ► If using MongoDB Atlas, ensure your IP is whitelisted.")
@app.on_event("startup")
async def startup_db_check():
    try:
        await client.admin.command("ping")
        print("✅ MongoDB connection verified on startup.")

        # ── Seed default admin if not exists ──
        existing_admin = await users_collection.find_one({"role": "admin"})
        if not existing_admin:
            hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
            await users_collection.insert_one({
                "username": "admin",
                "password": hashed,
                "role": "admin",
                "email": "",
                "phone": "",
                "created_at": datetime.utcnow().isoformat()
            })
            print("✅ Default admin created — username: admin, password: admin123")
        else:
            print("ℹ️ Admin already exists, skipping seed.")
    except Exception as e:
        print(f"❌ MongoDB FAILED: {e}")

# ══════════════════════════════════════════
#           Pydantic Models
# ══════════════════════════════════════════

class ScamMessage(BaseModel):
    text: str
    username: Optional[str] = None

class ScamResult(BaseModel):
    is_scam: bool
    probability: float
    risk_level: str
    reason: str
    flagged_keywords: List[dict]

class URLCheck(BaseModel):
    url: str
    username: Optional[str] = None

class URLResult(BaseModel):
    is_safe: bool
    risk_level: str
    details: List[str]
    ml_confidence: Optional[float] = None
    ml_model_used: Optional[str] = None

class KeywordEntry(BaseModel):
    word: str
    risk_level: str
    category: str
    added_by: Optional[str] = None

class UserAuth(BaseModel):
    username: str
    password: str
    phone: Optional[str] = None
    email: Optional[str] = None

class OTPRequest(BaseModel):
    phone: str

class OTPVerify(BaseModel):
    phone: str
    otp: str

class PasswordReset(BaseModel):
    phone: str
    otp: str
    new_password: str

class ReportEntry(BaseModel):
    report_type: str
    content: str
    link: Optional[str] = None
    notes: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    user_email: Optional[str] = None

class RoleUpdate(BaseModel):
    role: str

# ── Cybercrime report model ──
class CybercrimeReport(BaseModel):
    report_type:  str
    content:      Optional[str] = None
    link:         Optional[str] = None
    admin_notes:  Optional[str] = None
    reported_by:  Optional[str] = None
    submitted_at: Optional[str] = None

# ── In-memory OTP store ──
OTP_STORE: Dict[str, Dict[str, Any]] = {}
RATE_LIMIT_STORE: Dict[str, datetime] = {}

# ══════════════════════════════════════════
#   Load Scam Text ML Model
# ══════════════════════════════════════════

MODEL_PATH      = os.path.join(BASE_DIR, 'model', 'scam_model.pkl')
VECTORIZER_PATH = os.path.join(BASE_DIR, 'model', 'vectorizer.pkl')

model      = None
vectorizer = None

try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    with open(VECTORIZER_PATH, 'rb') as f:
        vectorizer = pickle.load(f)
    print("✅ Scam text AI model loaded successfully.")
except FileNotFoundError as e:
    print(f"❌ Scam model file missing: {e}")
except Exception as e:
    print(f"❌ Scam model load failed: {e}")

# ══════════════════════════════════════════
#   Load Phishing URL ML Models
# ══════════════════════════════════════════

def _load_phishing_models():
    phishing_models_dir = os.path.join(BASE_DIR, 'phishing_models')
    if not os.path.isdir(phishing_models_dir):
        print(f"❌ Phishing models folder not found: {phishing_models_dir}")
        return None, None, None

    subfolders = sorted([
        f for f in os.listdir(phishing_models_dir)
        if os.path.isdir(os.path.join(phishing_models_dir, f))
    ])
    if not subfolders:
        print("❌ No model versions found in phishing_models/")
        return None, None, None

    latest    = subfolders[-1]
    model_dir = os.path.join(phishing_models_dir, latest)
    print(f"📂 Loading phishing models from: {model_dir}")

    try:
        xgb    = joblib.load(os.path.join(model_dir, 'xgboost.pkl'))
        scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
        with open(os.path.join(model_dir, 'feature_columns.json')) as f:
            feature_cols = json.load(f)
        print(f"✅ Phishing URL ML models loaded ({latest})")
        return xgb, scaler, feature_cols
    except Exception as e:
        print(f"❌ Failed to load phishing models: {e}")
        return None, None, None


phishing_xgb, phishing_scaler, phishing_feature_cols = _load_phishing_models()

# ══════════════════════════════════════════
#   Phishing URL Feature Extraction
# ══════════════════════════════════════════

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "banking",
    "confirm", "password", "signin", "webscr", "ebayisapi", "paypal",
    "submit", "free", "bonus", "click", "winner", "prize",
]
IP_PATTERN = re.compile(r"(\d{1,3}\.){3}\d{1,3}|0x[\da-f]{8}|\d{8,10}")


def extract_url_features(url: str) -> dict:
    url_clean  = url.strip().lower().rstrip("/")
    extracted  = tldextract.extract(url_clean)
    subdomain  = extracted.subdomain
    num_subdomains = len(subdomain.split(".")) if subdomain else 0
    digits  = sum(c.isdigit() for c in url_clean)
    letters = sum(c.isalpha() for c in url_clean)

    return {
        "url_length":         len(url_clean),
        "num_dots":           url_clean.count("."),
        "has_ip":             int(bool(IP_PATTERN.search(url_clean))),
        "has_at":             int("@" in url_clean),
        "uses_https":         int(url_clean.startswith("https://")),
        "susp_keywords_url":  sum(kw in url_clean for kw in SUSPICIOUS_KEYWORDS),
        "digit_letter_ratio": round(digits / letters, 4) if letters > 0 else 0.0,
        "num_subdomains":     num_subdomains,
        "special_char_count": sum(c in set("-_?=&#%~!+") for c in url_clean),
        "hyphen_in_domain":   int("-" in extracted.domain),
        "domain_age_days":    0,
        "is_recent_domain":   0,
        "registrar_freq":     0,
        "has_a_record":       0,
        "has_mx_record":      0,
        "count_ns":           0,
    }


def ml_analyze_url(url: str):
    if phishing_xgb is None or phishing_scaler is None:
        return None, None
    try:
        features = extract_url_features(url)
        X        = np.array([[features[col] for col in phishing_feature_cols]])
        X_scaled = phishing_scaler.transform(X)
        proba    = phishing_xgb.predict_proba(X_scaled)[0][1]
        return proba > 0.5, float(proba)
    except Exception as e:
        print(f"[ML URL WARNING] {e}")
        return None, None

# ══════════════════════════════════════════
#   SMS Helper
# ══════════════════════════════════════════

def send_sms(phone: str, message: str) -> bool:
    if not FAST2SMS_API_KEY:
        print(f"[MOCK SMS] To {phone}: {message}")
        return True
    try:
        response = requests.post(
            "https://www.fast2sms.com/dev/bulkV2",
            headers={
                "authorization": FAST2SMS_API_KEY,
                "Content-Type":  "application/json"
            },
            json={
                "route":    "q",
                "message":  message,
                "language": "english",
                "flash":    0,
                "numbers":  phone
            }
        )
        result = response.json()
        print(f"[FAST2SMS] Sent to {phone}: {result}")
        return result.get("return", False)
    except Exception as e:
        print(f"[FAST2SMS ERROR] {e}")
        return False

# ══════════════════════════════════════════
#   Gmail Email Helper
# ══════════════════════════════════════════

def send_report_acknowledgement_email(
    to_email: str,
    username: str,
    report_type: str,
    report_content: str,
    submitted_at: str,
    scan_verdict: str,
    scan_risk: str,
    scan_confidence: float,
    scan_reason: str,
) -> bool:

    if not GMAIL_SENDER or not GMAIL_PASSWORD:
        print(f"[MOCK EMAIL] Would send acknowledgement to {to_email}")
        return True

    subject = f"[TrustShield] Report Scanned — {scan_verdict} | {report_type}"

    try:
        dt = datetime.fromisoformat(submitted_at)
        formatted_date = dt.strftime("%d %B %Y, %I:%M %p")
    except Exception:
        formatted_date = submitted_at

    preview        = report_content[:300] + ("..." if len(report_content) > 300 else "")
    confidence_pct = round(scan_confidence * 100, 1)

    if scan_verdict == "PHISHING DETECTED":
        verdict_color  = "#ef4444"
        verdict_bg     = "#1a0d0d"
        verdict_border = "#ef444433"
        verdict_icon   = "🔴"
    elif scan_verdict == "SUSPICIOUS":
        verdict_color  = "#f59e0b"
        verdict_bg     = "#1a150d"
        verdict_border = "#f59e0b33"
        verdict_icon   = "⚠️"
    else:
        verdict_color  = "#22c55e"
        verdict_bg     = "#0d1a0d"
        verdict_border = "#22c55e33"
        verdict_icon   = "✅"

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <style>
    body {{ margin:0; padding:0; background:#0d0d0f; font-family:Arial,sans-serif; }}
    .wrapper {{ max-width:620px; margin:0 auto; background:#0d0d0f; padding:32px 16px; }}
    .header {{ background:linear-gradient(135deg,#0d0d0f 0%,#1a1a2e 100%); border:1px solid #22d3ee44; border-top:4px solid #22d3ee; border-radius:12px 12px 0 0; padding:32px; text-align:center; }}
    .header h1 {{ margin:0; font-size:26px; color:#22d3ee; letter-spacing:2px; }}
    .header p  {{ margin:6px 0 0; color:#6b7280; font-size:12px; letter-spacing:1px; text-transform:uppercase; }}
    .body {{ background:#111117; border:1px solid #1f2937; border-top:none; padding:32px; }}
    .case-box {{ background:#1a1a2e; border:1px solid #22d3ee33; border-left:4px solid #22d3ee; border-radius:8px; padding:16px 20px; margin-bottom:24px; }}
    .case-box .label {{ font-size:10px; color:#6b7280; letter-spacing:2px; text-transform:uppercase; margin-bottom:4px; }}
    .case-box .value {{ font-size:14px; color:#e5e7eb; font-weight:bold; }}
    .info-row {{ display:flex; margin-bottom:10px; }}
    .info-label {{ width:140px; color:#6b7280; font-size:13px; flex-shrink:0; }}
    .info-value {{ color:#e5e7eb; font-size:13px; }}
    .content-preview {{ background:#0d0d0f; border:1px solid #1f2937; border-radius:8px; padding:14px 16px; color:#9ca3af; font-size:13px; line-height:1.6; margin-bottom:24px; font-family:monospace; }}
    .warning-box {{ background:#1a0d0d; border:1px solid #ef444433; border-left:4px solid #ef4444; border-radius:8px; padding:16px 20px; margin-bottom:24px; }}
    .warning-box h3 {{ margin:0 0 10px; color:#ef4444; font-size:13px; letter-spacing:1px; text-transform:uppercase; }}
    .warning-box ul {{ margin:0; padding-left:18px; color:#d1d5db; font-size:13px; line-height:1.9; }}
    .divider {{ border:none; border-top:1px solid #1f2937; margin:24px 0; }}
    .footer {{ background:#0d0d0f; border:1px solid #1f2937; border-top:none; border-radius:0 0 12px 12px; padding:20px 32px; text-align:center; }}
    .footer p {{ color:#4b5563; font-size:11px; margin:4px 0; }}
    .footer .brand {{ color:#22d3ee; font-weight:bold; font-size:13px; }}
  </style>
</head>
<body>
<div class="wrapper">
  <div class="header">
    <h1>🛡️ TRUSTSHIELD</h1>
    <p>Cybercrime Threat Intelligence Unit</p>
  </div>
  <div class="body">
    <p style="color:#e5e7eb;font-size:16px;margin-bottom:20px;">Dear <strong style="color:#22d3ee">{username}</strong>,</p>
    <p style="color:#d1d5db;font-size:14px;line-height:1.7;margin-bottom:24px;">
      Your report has been <strong style="color:#22c55e">received and instantly scanned</strong> by our AI engine. Here is your result:
    </p>
    <div style="background:{verdict_bg};border:2px solid {verdict_border};border-left:5px solid {verdict_color};border-radius:10px;padding:20px 24px;margin-bottom:24px;">
      <div style="font-size:10px;color:#6b7280;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;">AI Scan Result</div>
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">
        <span style="font-size:2rem;">{verdict_icon}</span>
        <div>
          <div style="font-size:1.3rem;font-weight:900;color:{verdict_color};letter-spacing:1px;">{scan_verdict}</div>
          <div style="font-size:13px;color:#9ca3af;margin-top:4px;">
            Risk Level: <strong style="color:{verdict_color};">{scan_risk}</strong>
            &nbsp;·&nbsp;
            Confidence: <strong style="color:#e5e7eb;">{confidence_pct}%</strong>
          </div>
        </div>
      </div>
      <div style="background:#1f2937;border-radius:6px;height:10px;margin-bottom:14px;">
        <div style="width:{confidence_pct}%;height:10px;border-radius:6px;background:{verdict_color};"></div>
      </div>
      <div style="background:#0d0d0f;border-radius:8px;padding:10px 14px;font-size:13px;color:#9ca3af;line-height:1.6;">
        <strong style="color:#e5e7eb;">AI Reason: </strong>{scan_reason}
      </div>
    </div>
    <div class="case-box">
      <div class="label">Case Reference</div>
      <div class="value">TS-{submitted_at[:10].replace('-', '')}-{username.upper()[:4]}</div>
    </div>
    <div style="margin-bottom:20px;">
      <div style="font-size:10px;color:#6b7280;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;">Report Details</div>
      <div class="info-row"><span class="info-label">Report Type</span><span class="info-value">{report_type}</span></div>
      <div class="info-row"><span class="info-label">Submitted By</span><span class="info-value">{username}</span></div>
      <div class="info-row"><span class="info-label">Date &amp; Time</span><span class="info-value">{formatted_date}</span></div>
    </div>
    <div style="font-size:10px;color:#6b7280;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">Reported Content (Preview)</div>
    <div class="content-preview">{preview}</div>
    <hr class="divider" />
    <div class="warning-box">
      <h3>⚠️ Important Cybercrime Advisory</h3>
      <ul>
        <li>Do <strong>not</strong> click any links in the suspicious message.</li>
        <li>Do <strong>not</strong> share OTPs, passwords, or banking details with anyone.</li>
        <li>If you have already interacted with the threat, <strong>change your passwords immediately</strong>.</li>
        <li>Report financial fraud to your bank and the <strong>National Cyber Crime Portal</strong> at <strong>cybercrime.gov.in</strong>.</li>
        <li>You may also call the <strong>Cyber Crime Helpline: 1930</strong> (India) for immediate assistance.</li>
        <li>Preserve all evidence — do not delete suspicious messages or emails.</li>
      </ul>
    </div>
    <hr class="divider" />
    <p style="color:#9ca3af;font-size:13px;line-height:1.7;">Thank you for helping protect thousands of users from cyber threats.</p>
    <p style="color:#9ca3af;font-size:13px;margin-top:16px;">
      Stay safe,<br/>
      <strong style="color:#22d3ee">TrustShield Security Team</strong><br/>
      <span style="color:#4b5563;font-size:12px;">Cybercrime Threat Intelligence Unit</span>
    </p>
  </div>
  <div class="footer">
    <p class="brand">🛡️ TrustShield AI</p>
    <p>Protecting Citizens from Cyber Scams</p>
    <p style="margin-top:8px;">This is an automated message. Please do not reply to this email.</p>
    <p>© 2026 TrustShield. All rights reserved.</p>
  </div>
</div>
</body>
</html>
"""

    plain_body = f"""
Dear {username},

AI SCAN RESULT: {verdict_icon} {scan_verdict}
Risk Level    : {scan_risk}
Confidence    : {confidence_pct}%
Reason        : {scan_reason}

CASE REFERENCE : TS-{submitted_at[:10].replace('-', '')}-{username.upper()[:4]}
Report Type    : {report_type}
Submitted      : {formatted_date}

CYBERCRIME ADVISORY:
- Do NOT click any links in the suspicious message.
- Do NOT share OTPs, passwords, or banking details with anyone.
- If you interacted with the threat, change your passwords immediately.
- Report financial fraud: cybercrime.gov.in | Helpline: 1930 (India)
- Preserve all evidence — do not delete suspicious messages.

Stay safe,
TrustShield Security Team
© 2026 TrustShield. All rights reserved.
"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"TrustShield Security <{GMAIL_SENDER}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body,  "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_SENDER, GMAIL_PASSWORD)
            server.sendmail(GMAIL_SENDER, to_email, msg.as_string())
        print(f"📧 Acknowledgement email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send to {to_email}: {e}")
        return False

# ══════════════════════════════════════════
#         MongoDB Helper Functions
# ══════════════════════════════════════════

async def get_user_by_username(username: str):
    return await users_collection.find_one({"username": username}, {"_id": 0})

async def get_user_by_phone(phone: str):
    return await users_collection.find_one({"phone": phone}, {"_id": 0})

async def save_user(user: dict):
    try:
        result = await users_collection.insert_one(user)
        print(f"✅ User saved — inserted_id: {result.inserted_id}")
    except Exception as e:
        print(f"❌ FAILED to save user: {e}")
        raise HTTPException(status_code=500, detail=f"Database error while saving user: {str(e)}")

async def update_user_password(phone: str, hashed_password: str):
    try:
        result = await users_collection.update_one(
            {"phone": phone},
            {"$set": {"password": hashed_password}}
        )
        print(f"✅ Password updated — matched: {result.matched_count}, modified: {result.modified_count}")
    except Exception as e:
        print(f"❌ FAILED to update password: {e}")
        raise HTTPException(status_code=500, detail=f"Database error while updating password: {str(e)}")

async def get_risk_keywords():
    try:
        return await risk_keywords_collection.find({}, {"_id": 0}).to_list(None)
    except Exception as e:
        print(f"❌ FAILED to fetch keywords: {e}")
        return []

async def save_keyword(keyword: dict):
    try:
        result = await risk_keywords_collection.insert_one(keyword)
        print(f"✅ Keyword saved — inserted_id: {result.inserted_id}")
    except Exception as e:
        print(f"❌ FAILED to save keyword: {e}")
        raise HTTPException(status_code=500, detail=f"Database error while saving keyword: {str(e)}")

async def save_report(report: dict):
    try:
        result = await reports_collection.insert_one(report)
        print(f"✅ Report saved — inserted_id: {result.inserted_id}")
    except Exception as e:
        print(f"❌ FAILED to save report: {e}")
        raise HTTPException(status_code=500, detail=f"Database error while saving report: {str(e)}")

async def save_url_scan(scan: dict):
    try:
        result = await url_scans_collection.insert_one(scan)
        print(f"✅ URL/Text scan saved — inserted_id: {result.inserted_id} | type: {scan.get('type')} | user: {scan.get('username')}")
    except Exception as e:
        print(f"❌ FAILED to save url_scan: {e}")
        raise HTTPException(status_code=500, detail=f"Database error while saving scan: {str(e)}")

# ══════════════════════════════════════════
#              Core Analysis
# ══════════════════════════════════════════

async def analyze_text(text: str):
    keywords      = await get_risk_keywords()
    flagged       = []
    total_score   = 0
    message_lower = text.lower()

    for item in keywords:
        word = item['word'].lower()
        if word in message_lower:
            weight = (
                0.5 if item['risk_level'] == "High"
                else 0.3 if item['risk_level'] == "Medium"
                else 0.1
            )
            total_score += weight
            flagged.append({
                "word":       item['word'],
                "risk_level": item['risk_level'],
                "category":   item['category']
            })

    ai_prob = 0.0
    if model and vectorizer:
        try:
            X = vectorizer.transform([text])
            try:
                ai_prob = float(model.predict_proba(X)[0][1])
            except AttributeError:
                ai_prob = float(model.predict(X)[0])
        except Exception as e:
            print(f"[ML WARNING] Prediction failed: {e}")
            ai_prob = 0.0

    final_prob = min((ai_prob * 0.6) + (min(total_score, 1.0) * 0.4), 1.0)

    is_scam    = final_prob > 0.35
    risk_level = (
        "High"   if final_prob > 0.65
        else "Medium" if final_prob > 0.35
        else "Low"
    )

    reason = (
        f"Flagged due to {len(flagged)} risky keyword(s): "
        + ", ".join([f['word'] for f in flagged])
        if flagged
        else "No specific risky keywords found. Analysis based on AI pattern recognition."
    )
    return is_scam, final_prob, risk_level, reason, flagged


def analyze_url(url: str):
    url_lower     = url.lower()
    details       = []
    ml_confidence = None
    ml_model_used = None

    is_phishing_ml, confidence = ml_analyze_url(url)

    if is_phishing_ml is not None:
        ml_confidence = round(confidence * 100, 2)
        ml_model_used = "XGBoost"
        is_safe       = not is_phishing_ml
        risk_level    = (
            "High"   if confidence > 0.75
            else "Medium" if confidence > 0.5
            else "Low"
        )
        details.append(
            f"ML Model ({ml_model_used}): {ml_confidence}% confidence "
            f"— {'Phishing detected' if is_phishing_ml else 'Looks legitimate'}"
        )
    else:
        details.append("ML models unavailable — using rule-based analysis.")
        is_safe    = True
        risk_level = "Low"

        BLACKLISTED = [
            "scam-link.net", "win-free-prize.com", "bank-verify-kyc.in",
            "tinyurl.com/free-money", "free-money.com", "phishing-site.com",
        ]
        for domain in BLACKLISTED:
            if domain in url_lower:
                is_safe = False
                details.append(f"Matches blacklisted domain: {domain}")

        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
            is_safe    = False
            risk_level = "High"

        if not is_safe:
            risk_level = "High"

    if any(s in url_lower for s in ["bit.ly", "tinyurl.com", "is.gd", "t.co", "goo.gl"]):
        details.append("⚠️ Uses a URL shortener — commonly used to hide phishing links.")
    if not url_lower.startswith("https://"):
        details.append("⚠️ Does not use HTTPS — connection is not secure.")
    if "@" in url:
        details.append("⚠️ Contains '@' symbol — browsers ignore everything before it.")
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
        details.append("⚠️ Uses a raw IP address instead of a domain name.")

    if not details:
        details.append("✅ URL appears safe based on ML and structural analysis.")

    features = {
        "length":        len(url),
        "num_dots":      url.count("."),
        "symbols":       sum(c in "?=&#%" for c in url),
        "https":         url_lower.startswith("https://"),
        "ml_confidence": ml_confidence,
    }

    return is_safe, risk_level, details, features, ml_confidence, ml_model_used

# ══════════════════════════════════════════
#                  ROUTES
# ══════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "status":                "online",
        "scam_model_loaded":     model is not None,
        "phishing_model_loaded": phishing_xgb is not None,
        "message":               "TrustShield API is running"
    }

# ── Text Detection ──
@app.post("/detect/text", response_model=ScamResult)
async def detect_scam_text(message: ScamMessage):
    print(f"📩 /detect/text called — username: {message.username} | text: {message.text[:60]}")

    is_scam, prob, risk, reason, flagged = await analyze_text(message.text)

    scan_doc = {
        "type":             "text",
        "user_id":          message.username,
        "username":         message.username,
        "input_text":       message.text,
        "is_scam":          is_scam,
        "probability":      round(prob, 4),
        "risk_level":       risk,
        "reason":           reason,
        "flagged_keywords": flagged,
        "scan_time":        datetime.now().isoformat()
    }
    print(f"   💾 Saving text scan to DB: is_scam={is_scam}, risk={risk}")
    await save_url_scan(scan_doc)

    return {
        "is_scam":          is_scam,
        "probability":      prob,
        "risk_level":       risk,
        "reason":           reason,
        "flagged_keywords": flagged
    }

# ── URL Detection ──
@app.post("/detect/url", response_model=URLResult)
async def detect_scam_url(check: URLCheck):
    print(f"🔗 /detect/url called — username: {check.username} | url: {check.url}")

    is_safe, risk_level, final_details, features, ml_confidence, ml_model_used = analyze_url(check.url)

    scan_doc = {
        "type":          "url",
        "user_id":       check.username,
        "username":      check.username,
        "url_text":      check.url,
        "is_scam":       not is_safe,
        "risk_level":    risk_level,
        "detail":        final_details,
        "features":      features,
        "ml_confidence": ml_confidence,
        "ml_model_used": ml_model_used,
        "scan_time":     datetime.now().isoformat()
    }
    print(f"   💾 Saving URL scan to DB: is_safe={is_safe}, risk={risk_level}")
    await save_url_scan(scan_doc)

    return {
        "is_safe":       is_safe,
        "risk_level":    risk_level,
        "details":       final_details,
        "ml_confidence": ml_confidence,
        "ml_model_used": ml_model_used,
    }

# ── Register ──
@app.post("/auth/register")
async def register(auth: UserAuth):
    existing = await get_user_by_username(auth.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = bcrypt.hashpw(
        auth.password.encode('utf-8'), bcrypt.gensalt()
    ).decode('utf-8')

    new_user = {
        "username":   auth.username,
        "password":   hashed_password,
        "role":       "user",
        "email":      auth.email,
        "created_at": datetime.now().isoformat()
    }
    if auth.phone:
        new_user["phone"] = auth.phone

    await save_user(new_user)
    return {"message": "User registered successfully"}

# ── Login ──
@app.post("/auth/login")
async def login(auth: UserAuth, request: Request):
    user = await get_user_by_username(auth.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not bcrypt.checkpw(auth.password.encode('utf-8'), user['password'].encode('utf-8')):
        try:
            await login_logs_collection.insert_one({
                "username":  auth.username,
                "role":      None,
                "status":    "failed",
                "ip":        request.client.host,
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            print(f"❌ FAILED to save login log: {e}")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    try:
        await login_logs_collection.insert_one({
            "username":  auth.username,
            "role":      user.get("role", "user"),
            "status":    "success",
            "ip":        request.client.host,
            "timestamp": datetime.now().isoformat()
        })
        print(f"✅ Login log saved for {auth.username}")
    except Exception as e:
        print(f"❌ FAILED to save login log: {e}")

    return {
        "message":  "Login successful",
        "username": auth.username,
        "role":     user.get("role", "user"),
        "email":    user.get("email", None),
    }

def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode()).hexdigest()

# ── Forgot Password ──
@app.post("/auth/forgot-password/phone")
async def forgot_password_phone(req: OTPRequest):
    phone = re.sub(r'[\s\-]', '', req.phone)
    if not re.match(r"^(?:\+?91)?\s?[6789]\d{9}$", phone):
        raise HTTPException(status_code=400, detail="Invalid phone format")

    phone = phone[-10:]
    now   = datetime.now()

    if phone in RATE_LIMIT_STORE:
        cooldown_end = RATE_LIMIT_STORE[phone]
        if now < cooldown_end:
            wait_time = int((cooldown_end - now).total_seconds())
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {wait_time} seconds before requesting another OTP"
            )

    user = await get_user_by_phone(phone)
    RATE_LIMIT_STORE[phone] = now + timedelta(seconds=30)

    if user:
        otp = "".join(str(secrets.randbelow(10)) for _ in range(6))
        OTP_STORE[phone] = {
            "hash":     hash_otp(otp),
            "expiry":   now + timedelta(minutes=5),
            "attempts": 0,
            "verified": False
        }
        send_sms(phone, f"Your TrustShield OTP is {otp} (valid for 5 minutes)")

    return {"message": "If the number is registered, an OTP has been sent."}

# ── Verify OTP ──
@app.post("/auth/verify-otp")
async def verify_otp(req: OTPVerify):
    phone = re.sub(r'[\s\-]', '', req.phone)[-10:]
    otp   = req.otp.strip()

    if phone not in OTP_STORE:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    session = OTP_STORE[phone]

    if datetime.now() > session["expiry"]:
        OTP_STORE.pop(phone, None)
        raise HTTPException(status_code=400, detail="OTP has expired")

    if session["attempts"] >= 5:
        OTP_STORE.pop(phone, None)
        raise HTTPException(status_code=400, detail="Too many failed attempts. Request a new OTP.")

    if session["hash"] != hash_otp(otp):
        session["attempts"] += 1
        raise HTTPException(status_code=400, detail="Invalid OTP")

    session["verified"] = True
    return {"message": "OTP verified successfully"}

# ── Reset Password ──
@app.post("/auth/reset-password")
async def reset_password(req: PasswordReset):
    phone = re.sub(r'[\s\-]', '', req.phone)[-10:]

    if phone not in OTP_STORE or not OTP_STORE[phone].get("verified"):
        raise HTTPException(status_code=400, detail="Phone number not verified")

    if OTP_STORE[phone]["hash"] != hash_otp(req.otp.strip()):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user = await get_user_by_phone(phone)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    hashed_password = bcrypt.hashpw(
        req.new_password.encode('utf-8'), bcrypt.gensalt()
    ).decode('utf-8')

    await update_user_password(phone, hashed_password)
    OTP_STORE.pop(phone, None)
    return {"message": "Password reset successfully"}

# ── Add Keyword ──
@app.post("/add_keyword")
async def add_keyword(entry: KeywordEntry):
    keywords = await get_risk_keywords()
    if any(k['word'].lower() == entry.word.lower() for k in keywords):
        raise HTTPException(status_code=400, detail="Keyword already exists in the database")

    added_at = datetime.now().isoformat()
    await save_keyword({
        "word":       entry.word,
        "risk_level": entry.risk_level,
        "category":   entry.category,
        "added_by":   entry.added_by or "unknown",
        "added_at":   added_at,
        "created_at": added_at,
    })

    return {
        "message": "Keyword successfully added to the detection database.",
        "keyword": {
            "word":       entry.word,
            "risk_level": entry.risk_level,
            "category":   entry.category,
            "added_by":   entry.added_by or "unknown",
            "added_at":   added_at
        }
    }

# ── Submit Report ──
@app.post("/report")
async def submit_report(report: ReportEntry):
    submitted_at = datetime.now().isoformat()

    url_report_types = {"Phishing URL", "Suspicious Link"}
    is_url_report    = report.report_type in url_report_types and report.link

    if is_url_report:
        is_safe, risk_level, details, _, ml_confidence, _ = analyze_url(report.link)
        is_scam     = not is_safe
        confidence  = (ml_confidence / 100) if ml_confidence else (0.85 if is_scam else 0.1)
        scan_reason = "; ".join(details[:2])
    else:
        is_scam, confidence, risk_level, scan_reason, _ = await analyze_text(report.content)

    if is_scam and risk_level in ("High", "Medium"):
        scan_verdict = "PHISHING DETECTED"
    elif is_scam:
        scan_verdict = "SUSPICIOUS"
    else:
        scan_verdict = "SAFE"

    email_to_save = report.email or report.user_email

    await save_report({
        "report_type":      report.report_type,
        "message_content":  report.content,
        "suspicious_link":  report.link,
        "additional_notes": report.notes,
        "reported_by":      report.username,
        "username":         report.username,
        "email":            email_to_save,
        "scan_verdict":     scan_verdict,
        "scan_risk":        risk_level,
        "scan_confidence":  round(confidence * 100, 1),
        "status":           "pending",
        "submitted_at":     submitted_at
    })

    email_sent   = False
    email_to_use = email_to_save

    if not email_to_use and report.username:
        db_user = await get_user_by_username(report.username)
        if db_user and db_user.get("email"):
            email_to_use = db_user["email"]

    if email_to_use:
        email_sent = send_report_acknowledgement_email(
            to_email        = email_to_use,
            username        = report.username or "User",
            report_type     = report.report_type,
            report_content  = report.content,
            submitted_at    = submitted_at,
            scan_verdict    = scan_verdict,
            scan_risk       = risk_level,
            scan_confidence = confidence,
            scan_reason     = scan_reason,
        )

    return {
        "message":    "Report submitted successfully. Thank you for helping improve TrustShield.",
        "email_sent": email_sent,
        "report": {
            "report_type":      report.report_type,
            "message_content":  report.content,
            "suspicious_link":  report.link,
            "additional_notes": report.notes,
            "scan_verdict":     scan_verdict,
            "scan_risk":        risk_level,
            "status":           "pending",
            "submitted_at":     submitted_at
        }
    }

# ── Get all keywords ──
@app.get("/keywords")
async def get_keywords():
    keywords = await get_risk_keywords()
    return {"keywords": keywords}

# ── Get all reports (public) ──
@app.get("/reports")
async def get_reports():
    try:
        reports = await reports_collection.find({}, {"_id": 0}).to_list(None)
        return {"reports": reports}
    except Exception as e:
        print(f"❌ FAILED to fetch reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ══════════════════════════════════════════
#           ADMIN ENDPOINTS
# ══════════════════════════════════════════

@app.get("/admin/users")
async def get_all_users():
    users = await users_collection.find(
        {}, {"_id": 0, "password": 0}
    ).to_list(None)
    return {"users": users}

@app.put("/admin/users/{username}/role")
async def update_user_role(username: str, body: RoleUpdate):
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'user'")
    result = await users_collection.update_one(
        {"username": username},
        {"$set": {"role": body.role}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"{username} is now {body.role}"}

@app.delete("/admin/users/{username}")
async def delete_user(username: str):
    result = await users_collection.delete_one({"username": username})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"User '{username}' deleted successfully."}

@app.get("/admin/scans")
async def get_all_scans():
    try:
        scans = await url_scans_collection.find({}, {"_id": 0}).to_list(None)
        return {"scans": scans}
    except Exception as e:
        print(f"❌ FAILED to fetch scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/reports")
async def get_all_reports_admin():
    try:
        reports = await reports_collection.find({}, {"_id": 0}).to_list(None)
        return {"reports": reports}
    except Exception as e:
        print(f"❌ FAILED to fetch reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/admin/reports/{submitted_at}/status")
async def update_report_status(submitted_at: str, status: str):
    if status not in ("pending", "reviewed", "rejected"):
        raise HTTPException(status_code=400, detail="status must be 'pending', 'reviewed' or 'rejected'")

    result = await reports_collection.update_one(
        {"submitted_at": submitted_at},
        {"$set": {"status": status, "reviewed_at": datetime.now().isoformat()}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Report not found")

    report = await reports_collection.find_one({"submitted_at": submitted_at}, {"_id": 0})
    sms_sent = False; notified_user = None

    if report and report.get("username"):
        user          = await get_user_by_username(report["username"])
        notified_user = report["username"]
        report_type   = report.get("report_type", "Threat Report")

        if user and user.get("phone"):
            phone = str(user["phone"]).strip()
            if status == "reviewed":
                sms_message = f"Hi {report['username']}, your TrustShield report ({report_type}) has been reviewed by our team. Thank you for helping keep the community safe! - TrustShield"
            elif status == "rejected":
                sms_message = f"Hi {report['username']}, your TrustShield report ({report_type}) was reviewed but could not be confirmed as a threat. Thank you for reporting! - TrustShield"
            else:
                sms_message = None
            if sms_message:
                sms_sent = send_sms(phone, sms_message)

    return {
        "message":       f"Report marked as {status}",
        "status":        status,
        "sms_sent":      sms_sent,
        "notified_user": notified_user
    }

@app.delete("/admin/keywords/{word}")
async def delete_keyword(word: str):
    result = await risk_keywords_collection.delete_one({"word": word})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Keyword not found")
    return {"message": f"Keyword '{word}' deleted successfully."}

@app.get("/admin/stats")
async def get_admin_stats():
    try:
        return {
            "total_users":       await users_collection.count_documents({}),
            "total_scans":       await url_scans_collection.count_documents({}),
            "total_reports":     await reports_collection.count_documents({}),
            "total_keywords":    await risk_keywords_collection.count_documents({}),
            "phishing_detected": await url_scans_collection.count_documents({"is_scam": True}),
            "pending_reports":   await reports_collection.count_documents({"status": "pending"}),
        }
    except Exception as e:
        print(f"❌ FAILED to fetch stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/models")
async def get_admin_models():
    return {
        "models": [
            {
                "name":         "XGBoost Classifier",
                "type":         "url",
                "accuracy":     96.5,
                "status":       "loaded" if phishing_xgb is not None else "not loaded",
                "trained_data": "merged_dataset.xlsx — 20,000 URLs (10k legit + 10k phishing)",
                "algorithm":    "XGBoost (Gradient Boosted Decision Trees)",
                "features":     len(phishing_feature_cols) if phishing_feature_cols else 16,
                "notes":        "Primary URL classifier. Outputs probability 0–1; >0.5 = phishing."
            },
            {
                "name":         "NLP Scam Detector",
                "type":         "text",
                "accuracy":     None,
                "status":       "loaded" if model is not None else "not loaded",
                "trained_data": "Custom scam SMS/email corpus + risk_keywords.json",
                "algorithm":    "TF-IDF Vectorizer + ML Classifier",
                "notes":        "Hybrid: 60% ML model + 40% keyword-based risk scoring for text/SMS/email."
            }
        ]
    }

@app.get("/admin/detections")
async def get_admin_detections():
    try:
        detections = await url_scans_collection.find(
            {"is_scam": True}, {"_id": 0}
        ).sort("scan_time", -1).to_list(None)
        return {"detections": detections}
    except Exception as e:
        print(f"❌ FAILED to fetch detections: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/login_logs")
async def get_login_logs():
    try:
        logs = await login_logs_collection.find(
            {}, {"_id": 0}
        ).sort("timestamp", -1).to_list(None)
        return {"login_logs": logs}
    except Exception as e:
        print(f"❌ FAILED to fetch login logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/setup")
async def create_admin(auth: UserAuth):
    existing = await get_user_by_username(auth.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = bcrypt.hashpw(
        auth.password.encode('utf-8'), bcrypt.gensalt()
    ).decode('utf-8')

    await save_user({
        "username":   auth.username,
        "password":   hashed_password,
        "role":       "admin",
        "created_at": datetime.now().isoformat()
    })
    return {"message": f"Admin user '{auth.username}' created successfully."}

# ── Report to Cybercrime Cell ──
@app.post("/admin/report_cybercrime")
async def report_to_cybercrime(report: CybercrimeReport):
    filed_at = datetime.now().isoformat()

    if report.submitted_at:
        try:
            result = await reports_collection.update_one(
                {"submitted_at": report.submitted_at},
                {"$set": {
                    "cybercrime_filed":    True,
                    "cybercrime_filed_at": filed_at,
                    "admin_notes":         report.admin_notes,
                    "status":              "reviewed"
                }}
            )
            print(f"✅ Cybercrime report DB updated — matched: {result.matched_count}")
        except Exception as e:
            print(f"❌ FAILED to update cybercrime report: {e}")

    reference = f"CC-{filed_at[:10].replace('-', '')}-{(report.reported_by or 'ADMIN').upper()[:4]}"

    print(f"🚨 CYBERCRIME REPORT FILED")
    print(f"   Reference : {reference}")
    print(f"   Type      : {report.report_type}")
    print(f"   Link      : {report.link or 'N/A'}")
    print(f"   Content   : {(report.content or '')[:80]}")
    print(f"   Admin Note: {report.admin_notes}")
    print(f"   Filed At  : {filed_at}")

    return {
        "status":    "submitted",
        "message":   "Report successfully forwarded to cybercrime cell.",
        "reference": reference,
        "filed_at":  filed_at,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)