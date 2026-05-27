# from fastapi import APIRouter
# import json

# router = APIRouter()

# # ---------- READ REPORTS ----------
# def load_reports():
#     try:
#         with open("reported_phishing.json", "r") as f:
#             return json.load(f)
#     except:
#         return []

# # ---------- SAVE REPORTS ----------
# def save_reports(data):
#     with open("reported_phishing.json", "w") as f:
#         json.dump(data, f, indent=4)

# # ---------- GET ALL REPORTS ----------
# @router.get("/admin/reports")
# def get_reports():
#     return load_reports()

# # ---------- DELETE REPORT ----------
# @router.delete("/admin/reports/{index}")
# def delete_report(index: int):
#     data = load_reports()

#     if index < len(data):
#         data.pop(index)
#         save_reports(data)
#         return {"message": "Report deleted"}

#     return {"message": "Invalid index"}


from fastapi import APIRouter
from database import reports_collection

router = APIRouter()

@router.get("/admin/reports")
async def get_reports():
    reports = await reports_collection.find({}, {"_id": 0}).to_list(None)
    return reports

@router.delete("/admin/reports/{report_id}")
async def delete_report(report_id: str):
    result = await reports_collection.delete_one({"id": report_id})
    if result.deleted_count:
        return {"message": "Report deleted"}
    return {"message": "Invalid ID"}