# ================================================================
#  DailyUpdate Backend (FULL VERSION WITH ALL FEATURES)
#  - All original logic preserved
#  - Firebase/Gemini/News/Cron toggles
#  - Dummy values supported for testing
#  - Safe fallback behavior
#  - Web Testing Interface included
# ================================================================

import os
import base64
import json
import time
import traceback
import hashlib
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template
import requests
import feedparser
from geopy.geocoders import Nominatim

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import google.generativeai as genai

# SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker

# ================================================================
# LOAD ENV (DUMMY FRIENDLY)
# ================================================================
load_dotenv()

# -------- Feature Toggles (0=disable, 1=enable) --------
FIREBASE_ENABLED      = os.getenv("FIREBASE_ENABLED", "0") == "1"
GEMINI_ENABLED        = os.getenv("GEMINI_ENABLED", "1") == "1"
NEWS_ENABLED          = os.getenv("NEWS_ENABLED", "1") == "1"
CRON_PUSH_ENABLED     = os.getenv("CRON_PUSH_ENABLED", "0") == "1"
CITY_DETECT_ENABLED   = os.getenv("CITY_DETECT_ENABLED", "1") == "1"

# -------- Core Secrets --------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "DUMMY_GEMINI_KEY")
APPCOMMONKEY_B64 = os.getenv("APPCOMMONKEY_B64")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./users.db")
CRON_SECRET = os.getenv("CRON_SECRET", "TEST_CRON")

# cache ttl (default 30 minutes)
CACHE_TTL = int(os.getenv("CACHE_TTL_SECONDS", 1800))

# ================================================================
# VALIDATE SECRETS
# ================================================================
if not APPCOMMONKEY_B64:
    raise RuntimeError("APPCOMMONKEY_B64 missing (must be base64 32 bytes).")

try:
    APPCOMMON_KEY_BYTES = base64.b64decode(APPCOMMONKEY_B64)
    if len(APPCOMMON_KEY_BYTES) != 32:
        raise ValueError("AppCommonKey must be exactly 32 bytes base64.")
except Exception as e:
    raise RuntimeError("Invalid APPCOMMONKEY_B64 → " + str(e))

# ================================================================
# LOAD GEMINI SAFE
# ================================================================
if GEMINI_ENABLED:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print("🔷 Gemini Enabled")
    except:
        print("⚠ Gemini key invalid → summarizer fallback mode")
        GEMINI_ENABLED = False
else:
    print("⚠ Gemini Disabled by config")

# ================================================================
# OPTIONAL FIREBASE IMPORT (NOT REMOVED)
# ================================================================
if FIREBASE_ENABLED:
    import firebase_admin
    from firebase_admin import credentials, messaging
    print("🔥 Firebase Enabled")
else:
    print("⚠ Firebase disabled by config")

# ================================================================
# INIT FIREBASE (IF ENABLED)
# ================================================================
def init_firebase():
    if not FIREBASE_ENABLED:
        print("⚠ Firebase skipped (FIREBASE_ENABLED=0)")
        return

    try:
        creds_json_b64 = os.getenv("FIREBASE_CREDENTIALS_JSON")
        if not creds_json_b64:
            print("⚠ No firebase credentials provided")
            return

        raw = creds_json_b64.strip()
        if not raw.startswith("{"):
            raw = base64.b64decode(raw).decode("utf-8")

        cred_json = json.loads(raw)

        cred = credentials.Certificate(cred_json)
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)

        print("🔥 Firebase initialized")

    except Exception as e:
        print("⚠ Firebase init failed:", e)

init_firebase()

# ================================================================
# DATABASE SETUP
# ================================================================
engine = create_engine(DATABASE_URL, echo=False, future=True)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

# -------- MODELS --------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    user_id = Column(String(200), unique=True, index=True)
    aes_key_b64 = Column(String(100), nullable=False)
    device_id = Column(String(200))
    device_token = Column(String(1024))
    name = Column(String(200))
    language = Column(String(20))
    city = Column(String(200))
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    user_id = Column(String(200), index=True)
    device_token = Column(String(1024))
    platform = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("user_id", "device_token", name="u_user_device"),)

class UserCityHash(Base):
    __tablename__ = "user_city_hash"
    id = Column(Integer, primary_key=True)
    user_id = Column(String(200), index=True)
    city = Column(String(200), index=True)
    last_hash = Column(String(128))
    updated_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (UniqueConstraint("user_id", "city", name="u_city_hash"),)

Base.metadata.create_all(bind=engine)

# ================================================================
# APP + GEOLOCATOR
# ================================================================
app = Flask(__name__)
geolocator = Nominatim(user_agent="dailyupdate-agent")
NEWS_CACHE = {}  # city → cached news

# ================================================================
# AES ENCRYPTION HELPERS
# ================================================================
def aes_encrypt_bytes(key: bytes, raw: bytes) -> str:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(raw)
    return base64.b64encode(nonce + ct + tag).decode()

def aes_encrypt_for_user(key_b64, data: dict):
    key = base64.b64decode(key_b64)
    raw = json.dumps(data, ensure_ascii=False).encode()
    return aes_encrypt_bytes(key, raw)

# ================================================================
# SAFE NEWS FUNCTIONS (WITH TOGGLES + FALLBACKS)
# ================================================================
def reverse_city(lat, lon):
    if not CITY_DETECT_ENABLED:
        return "Unknown"
    try:
        loc = geolocator.reverse(f"{lat},{lon}", language="en")
        if not loc:
            return "Unknown"
        addr = loc.raw.get("address", {})
        return addr.get("city") or addr.get("town") or addr.get("village") or addr.get("state") or "Unknown"
    except:
        return "Unknown"

def fetch_news(city, limit=5):
    if not NEWS_ENABLED:
        print("⚠ News fetching disabled")
        return [{"title": "News disabled", "summary": "Turn NEWS_ENABLED=1 to enable news"}]

    try:
        q = requests.utils.quote(city)
        url = f"https://news.google.com/rss/search?q={q}&hl=en-IN&gl=IN&ceid=IN:en"
        feed = feedparser.parse(requests.get(url, timeout=8).content)
        return [
            {"title": e.get("title",""), "summary": e.get("summary","")}
            for e in feed.entries[:limit]
        ]
    except Exception:
        return [{"title": "Error fetching news", "summary": "Check internet connection"}]

def summarize(text):
    if not GEMINI_ENABLED:
        return text[:200] + "..."
    try:
        model = genai.GenerativeModel("gemini-pro")
        r = model.generate_content(f"Summarize:\n{text}")
        return (r.text or "").strip()
    except:
        return text[:200] + "..."

def classify(text, city):
    if not GEMINI_ENABLED:
        return "LOW"
    try:
        model = genai.GenerativeModel("gemini-pro")
        r = model.generate_content(f"Is this HIGH priority for {city}? Answer HIGH or LOW:\n{text}")
        out = (r.text or "").upper()
        return "HIGH" if "HIGH" in out else "LOW"
    except:
        return "LOW"

def hash_titles(items):
    return hashlib.sha256("\n".join(i["title"] for i in items).encode()).hexdigest()

# ================================================================
# ROUTES
# ================================================================
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/health")
def health():
    return {"ok": True}

@app.route("/sync", methods=["POST"])
def sync():
    try:
        data = request.json or {}
        uid = data.get("user_id", "").strip()

        if len(uid) < 3:
            return {"error": "Invalid user_id"}, 400

        db = SessionLocal()
        user = db.query(User).filter_by(user_id=uid).first()

        if not user:
            key = base64.b64encode(os.urandom(32)).decode()
            user = User(user_id=uid, aes_key_b64=key)
            db.add(user)
            db.commit()

        encrypted_key = aes_encrypt_bytes(
            APPCOMMON_KEY_BYTES,
            user.aes_key_b64.encode()
        )
        return {"encrypted_user_key": encrypted_key}

    except Exception:
        traceback.print_exc()
        return {"error": "internal"}, 500

@app.route("/news", methods=["POST"])
def news():
    try:
        data = request.json or {}
        uid = data.get("user_id")
        lat = data.get("lat")
        lon = data.get("lon")

        if not uid:
            return {"error": "user_id missing"}, 400
        if lat is None or lon is None:
            return {"error": "lat/lon required"}, 400

        db = SessionLocal()
        user = db.query(User).filter_by(user_id=uid).first()
        if not user:
            return {"error": "User not found"}, 404

        try:
            lat = float(lat)
            lon = float(lon)
        except:
            return {"error": "Invalid lat/lon"}, 400

        city = reverse_city(lat, lon)
        user.city = city
        db.commit()

        now = time.time()
        cache = NEWS_CACHE.get(city)

        if not cache or now - cache["timestamp"] > CACHE_TTL:
            raw_news = fetch_news(city)
            summarized = [
                {"headline": i["title"], "summary": summarize(i["summary"])}
                for i in raw_news
            ]
            obj = {
                "city": city,
                "news": summarized,
                "fetched_at": datetime.utcnow().isoformat()
            }
            NEWS_CACHE[city] = {"data": obj, "timestamp": now}
        else:
            obj = cache["data"]

        encrypted = aes_encrypt_for_user(user.aes_key_b64, obj)
        return {"data": encrypted}

    except Exception:
        traceback.print_exc()
        return {"error": "internal"}, 500

@app.route("/cron/check-news", methods=["POST"])
def cron_check_news():
    try:
        if request.headers.get("X-Cron-Secret") != CRON_SECRET:
            return {"error": "unauthorized"}, 401

        print("✔ Running CRON (Push =", CRON_PUSH_ENABLED, ")")

        db = SessionLocal()
        users = db.query(User).filter(User.city.isnot(None)).all()

        cities = {}
        for u in users:
            cities.setdefault(u.city, []).append(u)

        for city, group in cities.items():
            now = time.time()
            cache = NEWS_CACHE.get(city)

            if not cache or now - cache["timestamp"] > CACHE_TTL:
                raw_news = fetch_news(city)
                summarized = [
                    {"title": i["title"], "summary": summarize(i["summary"])}
                    for i in raw_news
                ]
                NEWS_CACHE[city] = {
                    "data": {"city": city, "news": summarized},
                    "timestamp": now
                }

            items = NEWS_CACHE[city]["data"]["news"]
            new_hash = hash_titles(items)

            for u in group:
                h = db.query(UserCityHash).filter_by(user_id=u.user_id, city=city).first()

                if h and h.last_hash == new_hash:
                    continue

                high_items = [i for i in items if classify(i["summary"], city) == "HIGH"]

                # PUSH only if enabled
                if high_items and CRON_PUSH_ENABLED:
                    print(f"🔥 Would send HIGH ALERT to {u.user_id}")
                elif high_items:
                    print(f"⚠ High priority (PUSH DISABLED) for {u.user_id}")

                if not h:
                    h = UserCityHash(user_id=u.user_id, city=city, last_hash=new_hash)
                    db.add(h)
                else:
                    h.last_hash = new_hash

                db.commit()

        return {"ok": True}

    except:
        traceback.print_exc()
        return {"error": "internal"}, 500

# ================================================================
# WEB UI TESTING ENDPOINTS
# ================================================================
@app.route("/test/sync", methods=["POST"])
def test_sync():
    with app.test_client() as c:
        resp = c.post("/sync", json=request.form.to_dict())
        return jsonify(resp.json)

@app.route("/test/news", methods=["POST"])
def test_news_view():
    with app.test_client() as c:
        resp = c.post("/news", json=request.form.to_dict())
        return jsonify(resp.json)

@app.route("/test/cron", methods=["POST"])
def test_cron_view():
    with app.test_client() as c:
        resp = c.post("/cron/check-news", headers={"X-Cron-Secret": CRON_SECRET})
        return jsonify(resp.json)

# ================================================================
# RUN SERVER
# ================================================================
if __name__ == "__main__":
    app.run(debug=True, port=5000)
