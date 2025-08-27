# test_bump_version.py
import json, time
from sheets.gsheets_client import open_sheet, bump_version
s = json.load(open("settings.json","r",encoding="utf-8-sig"))
sh = open_sheet(s["google_sheets"]["credentials_file"], s["google_sheets"]["sheet_id"])
bump_version(sh, updated_by="manual_test")
print("OK: versión incrementada en Configuracion")
