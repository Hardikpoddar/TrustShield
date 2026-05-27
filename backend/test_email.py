import asyncio,aiosmtplib,os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
load_dotenv()
GMAIL_USER=os.getenv("GMAIL_USER")
GMAIL_PASSWORD=os.getenv("GMAIL_PASSWORD")
print("USER:",GMAIL_USER)
print("PASS:",GMAIL_PASSWORD)
async def test():
    m=MIMEMultipart("alternative")
    m["From"]=GMAIL_USER
    m["To"]=GMAIL_USER
    m["Subject"]="Test"
    m.attach(MIMEText("<h1>Test</h1>","html"))
    try:
        await aiosmtplib.send(m,hostname="smtp.gmail.com",port=587,start_tls=True,username=GMAIL_USER,password=GMAIL_PASSWORD)
        print("SUCCESS: Email sent!")
    except Exception as e:
        print("FAILED:",e)
import asyncio
asyncio.run(test())
