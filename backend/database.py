from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB  = os.getenv("MONGO_DB", "trustshield")

# ── Debug: print loaded config ──
print(f"🔍 MONGO_URI loaded: {MONGO_URI}")
print(f"🔍 MONGO_DB  loaded: {MONGO_DB}")

client = AsyncIOMotorClient(MONGO_URI)
db     = client[MONGO_DB]

# ── Collections ──
users_collection         = db["users"]
url_scans_collection     = db["url_scans"]
reports_collection       = db["reports"]
risk_keywords_collection = db["risk_keywords"]
login_logs_collection    = db["login_logs"]

print("✅ MongoDB client initialised (connection will be verified on startup).")