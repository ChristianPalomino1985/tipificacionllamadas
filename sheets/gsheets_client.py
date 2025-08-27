# sheets/gsheets_client.py
import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime
from typing import Dict, List
from .schema import RECORD_HEADERS, USERS_HEADERS, CATALOGO_HEADERS, CONFIG_KEYS

# ---- Conexión base ----
def get_client(creds_file: str) -> gspread.Client:
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ]
    credentials = Credentials.from_service_account_file(creds_file, scopes=scopes)
    return gspread.authorize(credentials)

def open_sheet(creds_file: str, sheet_id: str) -> gspread.Spreadsheet:
    client = get_client(creds_file)
    return client.open_by_key(sheet_id)

def get_ws(sh: gspread.Spreadsheet, title: str, rows=2000, cols=20) -> gspread.Worksheet:
    try:
        return sh.worksheet(title)
    except Exception:
        return sh.add_worksheet(title=title, rows=rows, cols=cols)

# ---- Utilidades comunes ----
def ensure_headers(ws: gspread.Worksheet, headers: List[str]) -> None:
    vals = ws.get_all_values()
    if not vals or vals[0][:len(headers)] != headers:
        end_col = chr(64 + len(headers))  # A=65
        ws.update(f"A1:{end_col}1", [headers])

def next_empty_row(ws: gspread.Worksheet) -> int:
    vals = ws.col_values(1)
    return len(vals) + 1 if vals else 2

def write_row(ws: gspread.Worksheet, row: List[str]) -> None:
    end_col = chr(64 + len(row))
    r = next_empty_row(ws)
    ws.update(f"A{r}:{end_col}{r}", [row], value_input_option="RAW")

# ---- Registros (Llamadas/Chats) ----
def append_record(sh: gspread.Spreadsheet, tab: str, record: Dict[str, str]) -> None:
    ws = get_ws(sh, tab, rows=5000, cols=len(RECORD_HEADERS))
    ensure_headers(ws, RECORD_HEADERS)
    row = [str(record.get(h, "")) for h in RECORD_HEADERS]
    write_row(ws, row)

# ---- Configuración (versionado) ----
def get_config_dict(sh: gspread.Spreadsheet):
    ws = get_ws(sh, "Configuracion", rows=10, cols=2)
    vals = ws.get_all_values()
    if not vals:
        ensure_headers(ws, ["key","value"])
        data = [["key","value"]] + [
            ["version", "1"],
            ["updated_by", "bootstrap"],
            ["updated_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ]
        ws.update("A1:B4", data)
        return {"version":"1"}
    got = {}
    for r in vals[1:]:
        if len(r) >= 2 and r[0]:
            got[r[0]] = r[1]
    if "version" not in got:
        got["version"] = "1"
    return got

def bump_version(sh: gspread.Spreadsheet, updated_by="admin"):
    ws = get_ws(sh, "Configuracion", rows=10, cols=2)
    ensure_headers(ws, ["key","value"])
    kv = {"version":"1","updated_by":updated_by,"updated_at":datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    vals = ws.get_all_values()
    for r in vals[1:]:
        if len(r) >= 2 and r[0]:
            kv[r[0]] = r[1] or kv.get(r[0], "")
    try:
        kv["version"] = str(int(kv.get("version","1")) + 1)
    except:
        kv["version"] = "1"
    data = [["key","value"]] + [[k, kv[k]] for k in ("version","updated_by","updated_at")]
    ws.clear()
    ws.update(f"A1:B{len(data)}", data)

# ---- Catálogo ----
def fetch_catalogo(sh: gspread.Spreadsheet) -> Dict[str, List[str]]:
    ws = get_ws(sh, "Catalogo", rows=500, cols=len(CATALOGO_HEADERS))
    ensure_headers(ws, CATALOGO_HEADERS)
    vals = ws.get_all_values()
    if len(vals) <= 1:
        return {"tipos": [], "areas": [], "motivos": []}
    headers = vals[0]
    cols = list(zip(*vals[1:])) if len(vals) > 1 else []
    def col(name):
        if name in headers:
            i = headers.index(name)
            return [x for x in (cols[i] if i < len(cols) else []) if x]
        return []
    return {"tipos": col("tipos"), "areas": col("areas"), "motivos": col("motivos")}

def save_catalogo(sh: gspread.Spreadsheet, catalogo: Dict[str, List[str]]):
    ws = get_ws(sh, "Catalogo", rows=500, cols=len(CATALOGO_HEADERS))
    ensure_headers(ws, CATALOGO_HEADERS)
    maxlen = max(len(catalogo.get("tipos",[])), len(catalogo.get("areas",[])), len(catalogo.get("motivos",[])), 1)
    data = [CATALOGO_HEADERS]
    for i in range(maxlen):
        data.append([
            catalogo.get("tipos",[])[i] if i < len(catalogo.get("tipos",[])) else "",
            catalogo.get("areas",[])[i] if i < len(catalogo.get("areas",[])) else "",
            catalogo.get("motivos",[])[i] if i < len(catalogo.get("motivos",[])) else ""
        ])
    ws.clear()
    end_col = chr(64 + len(CATALOGO_HEADERS))
    ws.update(f"A1:{end_col}{len(data)}", data, value_input_option="RAW")

# ---- Usuarios ----
def fetch_usuarios(sh: gspread.Spreadsheet) -> Dict:
    ws = get_ws(sh, "Usuarios", rows=1000, cols=len(USERS_HEADERS))
    ensure_headers(ws, USERS_HEADERS)
    vals = ws.get_all_values()
    out = {"users": []}
    if len(vals) <= 1:
        return out
    idx = {h:i for i,h in enumerate(vals[0])}
    for r in vals[1:]:
        if not r or not r[idx["username"]].strip():
            continue
        try:
            iterations = int(r[idx.get("iterations", -1)]) if idx.get("iterations") is not None else 200000
        except:
            iterations = 200000
        out["users"].append({
            "username": r[idx["username"]],
            "role": r.get(idx.get("role",1), "USER") if isinstance(idx.get("role",1), int) else "USER",
            "active": (r[idx.get("active",2)].upper() == "TRUE") if idx.get("active") is not None else True,
            "must_change_password": (r[idx.get("must_change_password",3)].upper() == "TRUE") if idx.get("must_change_password") is not None else False,
            "password": {
                "salt": r[idx.get("salt_base64",5)] if idx.get("salt_base64") is not None else "",
                "hash": r[idx.get("hash_base64",6)] if idx.get("hash_base64") is not None else "",
                "iterations": iterations
            }
        })
    return out

def save_usuarios(sh: gspread.Spreadsheet, record: Dict):
    ws = get_ws(sh, "Usuarios", rows=1000, cols=len(USERS_HEADERS))
    ensure_headers(ws, USERS_HEADERS)
    data = [USERS_HEADERS]
    for u in record.get("users", []):
        p = u.get("password", {}) or {}
        data.append([
            u.get("username",""),
            u.get("role","USER"),
            "TRUE" if u.get("active", True) else "FALSE",
            "TRUE" if u.get("must_change_password", False) else "FALSE",
            int(p.get("iterations", 200000)),
            p.get("salt",""),
            p.get("hash",""),
            u.get("note","")
        ])
    ws.clear()
    end_col = chr(64 + len(USERS_HEADERS))
    ws.update(f"A1:{end_col}{len(data)}", data, value_input_option="RAW")

