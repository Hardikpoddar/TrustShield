import asyncio
from database import users_collection

async def check():
    users = await users_collection.find(
        {"email": {"$exists": False}},
        {"_id": 0, "username": 1, "phone": 1}
    ).to_list(None)
    print(f"Users without email: {len(users)}")
    for u in users:
        name = u.get("username", "unknown")
        phone = u.get("phone", "none")
        print(f"  - {name} (phone: {phone})")

asyncio.run(check())
