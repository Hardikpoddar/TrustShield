import asyncio
import json
import os
from database import users_collection, risk_keywords_collection

async def seed_database():
    print("🌱 Starting database seeding...")

    # 1. Seed Users
    users_file = os.path.join(os.path.dirname(__file__), "users.json")
    if os.path.exists(users_file):
        with open(users_file, "r", encoding="utf-8") as f:
            users_data = json.load(f)
        
        users_added = 0
        for user in users_data:
            # Check if user already exists
            exists = await users_collection.find_one({"username": user["username"]})
            if not exists:
                # Replace password hash placeholder with a standard bcrypt hash for 'admin' if needed
                if user["username"] == "admin" and "YOUR_GENERATED_HASH_HERE" in user["password"]:
                    import bcrypt
                    hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")
                    user["password"] = hashed
                    print("🔑 Configured admin user password as 'admin123'")
                
                await users_collection.insert_one(user)
                users_added += 1
        
        print(f"👥 Users seed: Added {users_added} new users.")
    else:
        print("⚠️ users.json not found.")

    # 2. Seed Risk Keywords
    keywords_file = os.path.join(os.path.dirname(__file__), "risk_keywords.json")
    if os.path.exists(keywords_file):
        with open(keywords_file, "r", encoding="utf-8") as f:
            keywords_data = json.load(f)
        
        keywords_added = 0
        existing_keywords = await risk_keywords_collection.distinct("word")
        existing_set = set(k.lower() for k in existing_keywords)

        to_insert = []
        for kw in keywords_data:
            if kw["word"].lower() not in existing_set:
                to_insert.append(kw)
                existing_set.add(kw["word"].lower()) # Prevent duplicates in input list
        
        if to_insert:
            await risk_keywords_collection.insert_many(to_insert)
            keywords_added = len(to_insert)
        
        print(f"🔑 Keywords seed: Added {keywords_added} new risk keywords.")
    else:
        print("⚠️ risk_keywords.json not found.")

    print("✅ Seeding completed!")

if __name__ == "__main__":
    asyncio.run(seed_database())
