# sheets/status_hook.py
import json
try:
    from PyQt5.QtWidgets import QLabel
    from PyQt5.QtCore import QTimer, Qt
except Exception:
    from PySide6.QtWidgets import QLabel
    from PySide6.QtCore import QTimer, Qt

from .gsheets_client import open_sheet, get_ws as _gs_get_ws

def _load_settings():
    return json.load(open("settings.json","r",encoding="utf-8-sig"))

def _is_connected():
    try:
        s = _load_settings()
        sh = open_sheet(s["google_sheets"]["credentials_file"], s["google_sheets"]["sheet_id"])
        _ = _gs_get_ws(sh, s["google_sheets"]["sheet_tab"])
        return True
    except Exception:
        return False

def _apply_status(win, ok: bool):
    # 1) Label de estado si existe
    lbl = getattr(win, "lblSheetsStatus", None)
    if lbl is not None:
        lbl.setText("Google Sheets: Conectado" if ok else "Google Sheets: Desconectado")
        lbl.setStyleSheet("color:#16a34a;font-weight:bold;" if ok else "color:#ef4444;font-weight:bold;")
    # 2) Luz ● arriba a la derecha
    light = getattr(win, "_gsLight", None)
    if light is None:
        light = QLabel("●", win)
        light.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        win._gsLight = light
        def _reposition():
            x = win.width() - 26
            light.move(max(x, 6), 6)
        win._gsLight_repos = _reposition

        # Resize handler limpio (sin warnings)
        _old = getattr(win, "resizeEvent", None)
        def _on_resize(ev):
            if callable(_old): 
                _old(ev)
            _reposition()
        win.resizeEvent = _on_resize

    win._gsLight.setStyleSheet("font-size:18px;color:#22c55e;" if ok else "font-size:18px;color:#ef4444;")
    if hasattr(win, "_gsLight_repos"): win._gsLight_repos()
    win._gsLight.show()

def attach_status(win, interval_ms: int = 15000):
    # aplica una vez y luego en intervalo
    ok = _is_connected()
    _apply_status(win, ok)
    t = getattr(win, "_gsStatusTimer", None)
    if t is None:
        t = QTimer(win); win._gsStatusTimer = t
    t.timeout.connect(lambda: _apply_status(win, _is_connected()))
    t.start(max(3000, interval_ms))
