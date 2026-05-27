import asyncio
from database import users_collection

async def fix():
    result = await users_collection.update_one(
        {"username": "Rosemarie"},
        {"$set": {"email": "sangmarosemerry6@gmail.com"}}
    )
    print("Updated:", result.modified_count, "document(s)")

asyncio.run(fix())
