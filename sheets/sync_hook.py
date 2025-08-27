# sheets/sync_hook.py
import json
try:
    from PyQt5.QtCore import QTimer
except Exception:
    from PySide6.QtCore import QTimer

from .gsheets_client import open_sheet, get_config_dict, fetch_catalogo, fetch_usuarios, bump_version

def _load_settings():
    return json.load(open("settings.json","r",encoding="utf-8-sig"))

def _reload_from_cloud(win):
    # Carga catálogo y usuarios desde Sheets y refresca UI si existen esos atributos
    try:
        s = _load_settings()
        sh = open_sheet(s["google_sheets"]["credentials_file"], s["google_sheets"]["sheet_id"])
        if hasattr(win, "catalogo"):
            win.catalogo = fetch_catalogo(sh)
        if hasattr(win, "users_record"):
            win.users_record = fetch_usuarios(sh)
        if hasattr(win, "_refresh_combos_from_catalog"):
            try: win._refresh_combos_from_catalog()
            except Exception: pass
    except Exception as e:
        print("[Sync] Error reloading from cloud:", e)

def _wrap_admin_saves(win):
    # Si el Admin guarda catálogo o usuarios, subimos versión inmediatamente
    def _wrap(name, updated_by):
        if hasattr(win, name):
            orig = getattr(win, name)
            def _wrapped(*args, **kwargs):
                out = orig(*args, **kwargs)
                try:
                    s = _load_settings()
                    sh = open_sheet(s["google_sheets"]["credentials_file"], s["google_sheets"]["sheet_id"])
                    bump_version(sh, updated_by=updated_by)
                except Exception as e:
                    print(f"[Sync] bump_version failed after {name}:", e)
                return out
            setattr(win, name, _wrapped)
    _wrap("on_save_catalog", "admin_catalog")
    _wrap("save_users_record", "admin_users")

def attach_sync(win):
    s = _load_settings()
    if s.get("sync",{}).get("mode") != "sheets": 
        return
    # Hook para subir versión al guardar
    _wrap_admin_saves(win)
    # Timer de polling
    win._lastCloudVersion = None
    t = getattr(win, "_gsSyncTimer", None)
    if t is None:
        t = QTimer(win); win._gsSyncTimer = t
    interval = int(s.get("sync",{}).get("poll_secs", 30))
    interval = max(5, interval)
    def _tick():
        try:
            st = _load_settings()
            sh = open_sheet(st["google_sheets"]["credentials_file"], st["google_sheets"]["sheet_id"])
            cfg = get_config_dict(sh)
            v = cfg.get("version")
            if v and v != getattr(win, "_lastCloudVersion", None):
                win._lastCloudVersion = v
                _reload_from_cloud(win)
        except Exception as e:
            # silencioso: si no hay red, reintenta en el siguiente tick
            pass
    t.timeout.connect(_tick)
    t.start(interval * 1000)
    # primer chequeo inmediato
    _tick()
