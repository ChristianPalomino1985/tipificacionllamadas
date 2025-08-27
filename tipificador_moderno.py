import sys
import os
import json
import csv
import base64
import secrets
import hashlib
from datetime import datetime
from collections import Counter

import gspread
from google.oauth2.service_account import Credentials

from PyQt5.QtCore import Qt, QTimer, QEasingCurve, QPropertyAnimation
from PyQt5.QtGui import QIcon, QPixmap  # NUEVO: QIcon, QPixmap
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTextEdit, QDialog, QLineEdit, QFormLayout, QFrame, QSizePolicy,
    QMessageBox, QScrollArea, QSpacerItem, QDialogButtonBox, QTableWidget, QTableWidgetItem,
    QListWidget, QTabWidget, QCheckBox, QFileDialog
)
from PyQt5.QtNetwork import QLocalServer, QLocalSocket  # NUEVO

# =================== CONFIGURACIÓN ===================
APP_NAME = "Tipificador"
OBS_MAX = 1000
CATALOGO_JSON = "catalogo.json"
USERS_JSON = "users.json"
SETTINGS_JSON = "settings.json"
LOCAL_CSV = "registros_local.csv"

# NUEVO: rutas absolutas para assets (icono y logo)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_ICON_PATH = os.path.join(BASE_DIR, "assets", "icon.ico")
APP_LOGO_PATH = os.path.join(BASE_DIR, "assets", "logo.png")
SINGLE_INSTANCE_KEY = "Tipificador_Single_Instance_Key"  # NUEVO

# Roles
ROLE_ADMIN = "ADMIN"
ROLE_SUPERVISOR = "SUPERVISOR"
ROLE_USER = "USER"

def normalize_role(raw):
    if not raw:
        return ROLE_USER
    r = str(raw).strip().upper()
    if r == "ADMIN":
        return ROLE_ADMIN
    if r == "SUPERVISOR":
        return ROLE_SUPERVISOR
    return ROLE_USER

# Defaults
DEFAULT_SETTINGS = {
    "google_sheets": {
        "credentials_file": "",
        "sheet_id": "",
        "sheet_tab": "Llamadas"
    }
}

DEFAULT_CATALOGO = {
    "tipos": ["Entrante", "Saliente"],
    "areas": ["VENTAS", "SOPORTE", "TIENDAS CONCEPTO", "COBRANZAS", "TI", "OTROS"],
    "motivos": ["Consulta", "Queja", "Extornos", "Seguimiento", "Escalamiento"]
}

# =================== SETTINGS (Google Sheets) ===================
def load_settings() -> dict:
    if not os.path.isfile(SETTINGS_JSON):
        with open(SETTINGS_JSON, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SETTINGS, f, ensure_ascii=False, indent=2)
        return json.loads(json.dumps(DEFAULT_SETTINGS))
    try:
        with open(SETTINGS_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
        base = json.loads(json.dumps(DEFAULT_SETTINGS))
        base.update(data or {})
        if "google_sheets" in data:
            base["google_sheets"].update(data["google_sheets"])
        return base
    except Exception:
        return json.loads(json.dumps(DEFAULT_SETTINGS))

def save_settings(data: dict):
    with open(SETTINGS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# =================== GOOGLE SHEETS (REAL) ===================
_gs_client = None
_gs_worksheet = None
_gs_cached_cfg = None

def _gs_reset_cache():
    global _gs_client, _gs_worksheet, _gs_cached_cfg
    _gs_client = None
    _gs_worksheet = None
    _gs_cached_cfg = None

def _gs_get_client_and_ws():
    global _gs_client, _gs_worksheet, _gs_cached_cfg
    cfg = load_settings().get("google_sheets", {})
    creds_path = (cfg.get("credentials_file") or "").strip()
    sheet_id = (cfg.get("sheet_id") or "").strip()
    sheet_tab = (cfg.get("sheet_tab") or "Llamadas").strip()

    key = (creds_path, sheet_id, sheet_tab)
    if _gs_cached_cfg != key:
        _gs_reset_cache()
        _gs_cached_cfg = key

    if _gs_client and _gs_worksheet:
        return _gs_client, _gs_worksheet

    if not creds_path or not os.path.isfile(creds_path) or not sheet_id:
        raise RuntimeError("Google Sheets no está configurado. Ve a Admin > Google Sheets y completa los datos.")

    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ]
    creds = Credentials.from_service_account_file(creds_path, scopes=scopes)
    _gs_client = gspread.authorize(creds)
    sh = _gs_client.open_by_key(sheet_id)
    _gs_worksheet = sh.worksheet(sheet_tab)
    return _gs_client, _gs_worksheet

def gsheets_is_connected() -> bool:
    try:
        _, ws = _gs_get_client_and_ws()
        _ = ws.title
        return True
    except Exception:
        return False

def gsheets_append_row(row):
    _, ws = _gs_get_client_and_ws()
    ws.append_row(row, value_input_option="USER_ENTERED")

def gsheets_fetch_today_records():
    _, ws = _gs_get_client_and_ws()
    rows = ws.get_all_values()
    if not rows or len(rows) < 2:
        return []
    headers = rows[0]
    data = rows[1:]
    hoy = datetime.now().strftime("%d/%m/%Y")
    out = []
    idx = {h: i for i, h in enumerate(headers)}
    for r in data:
        if len(r) < len(headers):
            continue
        if r[idx.get("Fecha", 0)] == hoy:
            out.append([
                r[idx.get("Fecha", 0)],
                r[idx.get("Hora", 1)],
                r[idx.get("Usuario", 2)],
                r[idx.get("Rol", 3)],
                r[idx.get("Tipo", 4)],
                r[idx.get("Área", idx.get("Area", 5))],
                r[idx.get("Motivo", 6)],
                r[idx.get("Observaciones", 7)],
            ])
    return out

# =================== SEGURIDAD: PASSWORDS ===================
def password_hash(plain: str, iterations: int = 200_000) -> dict:
    if not isinstance(plain, str) or len(plain) < 4:
        raise ValueError("La contraseña debe tener al menos 4 caracteres.")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iterations)
    return {"salt": base64.b64encode(salt).decode("utf-8"),
            "hash": base64.b64encode(dk).decode("utf-8"),
            "iterations": iterations}

def password_verify(plain: str, stored: dict) -> bool:
    try:
        salt = base64.b64decode(stored["salt"])
        iterations = int(stored.get("iterations", 200_000))
        expected = base64.b64decode(stored["hash"])
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iterations)
        return secrets.compare_digest(dk, expected)
    except Exception:
        return False

# =================== ARCHIVO DE USUARIOS ===================
def ensure_users_file():
    if not os.path.isfile(USERS_JSON):
        data = {
            "users": [
                {
                    "username": "admin",
                    "role": "ADMIN",
                    "active": True,
                    "must_change_password": False,
                    "password": password_hash("1234")
                },
                {
                    "username": "user1",
                    "role": "USER",
                    "active": True,
                    "must_change_password": False,
                    "password": password_hash("0000")
                },
                {
                    "username": "user2",
                    "role": "SUPERVISOR",
                    "active": True,
                    "must_change_password": False,
                    "password": password_hash("1111")
                }
            ]
        }
        with open(USERS_JSON, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

def load_users():
    ensure_users_file()
    with open(USERS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(data):
    with open(USERS_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_user(record, username):
    for u in record.get("users", []):
        if u.get("username") == username:
            return u
    return None

def count_active_admins(record):
    return sum(1 for u in record.get("users", []) if normalize_role(u.get("role")) == ROLE_ADMIN and u.get("active") is True)

# =================== UTILES DE UI ===================
def card_frame():
    f = QFrame()
    f.setObjectName("Card")
    f.setFrameShape(QFrame.StyledPanel)
    return f

def label_icon_title(emoji, text):
    w = QWidget()
    h = QHBoxLayout(w)
    h.setContentsMargins(0,0,0,0)
    icon = QLabel(emoji)
    icon.setStyleSheet("font-size:16px;")
    lbl = QLabel(text)
    lbl.setStyleSheet("font-weight:700; font-size:16px; color:#111827;")
    h.addWidget(icon); h.addSpacing(6); h.addWidget(lbl); h.addStretch()
    return w

# =================== LOGIN DIALOG ===================
class LoginDialog(QDialog):
    def __init__(self, parent=None, force_change=False, username=None):
        super().__init__(parent)
        self.setWindowTitle("Iniciar sesión" if not force_change else "Cambiar contraseña")
        self.setModal(True)
        self.setMinimumWidth(340)
        self.force_change = force_change
        self.username_forced = username

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(6)

        self.userField = QLineEdit()
        self.pinField = QLineEdit()
        self.pinField.setEchoMode(QLineEdit.Password)

        if not force_change:
            self.userField.setPlaceholderText("Usuario")
            self.pinField.setPlaceholderText("Contraseña")
            form.addRow("Usuario:", self.userField)
            form.addRow("Contraseña:", self.pinField)
        else:
            self.userField.setText(username or "")
            self.userField.setEnabled(False)
            self.pinNew = QLineEdit(); self.pinNew.setEchoMode(QLineEdit.Password); self.pinNew.setPlaceholderText("Nueva contraseña")
            self.pinNew2 = QLineEdit(); self.pinNew2.setEchoMode(QLineEdit.Password); self.pinNew2.setPlaceholderText("Confirmar contraseña")
            form.addRow("Usuario:", self.userField)
            form.addRow("Nueva:", self.pinNew)
            form.addRow("Confirmar:", self.pinNew2)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(6)
        lay.addLayout(form)
        lay.addWidget(buttons)

    def get_credentials(self):
        if self.force_change:
            return self.userField.text().strip(), self.pinNew.text().strip(), self.pinNew2.text().strip()
        return self.userField.text().strip(), self.pinField.text().strip()

# =================== DIALOGO REGISTROS ===================
class TodayRecordsDialog(QDialog):
    def __init__(self, rows, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Registros de hoy")
        self.resize(820, 480)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(6)

        headers = ["Fecha", "Hora", "Usuario", "Rol", "Tipo", "Área", "Motivo", "Observaciones"]
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                table.setItem(r, c, QTableWidgetItem(str(val)))
        table.resizeColumnsToContents()
        lay.addWidget(table)

        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.button(QDialogButtonBox.Close).setText("Cerrar")
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

# =================== MAIN WINDOW ===================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.user = {"usuario": None, "rol": "USER"}
        self.users_record = load_users()
        self.catalogo = json.loads(json.dumps(DEFAULT_CATALOGO))
        self._animShortcuts = None
        self.counters = Counter({"Entrantes": 0, "Salientes": 0})

        self._build_ui()
        self._apply_styles()
        self._load_catalogo_json()
        self._post_build()

        QTimer.singleShot(0, self._force_login_on_start)

    # ---------- Construcción de UI ----------
    def _build_ui(self):
        self.setWindowTitle(f"{APP_NAME} - Usuario")
        self.setMinimumSize(940, 640)

        cw = QWidget()
        self.setCentralWidget(cw)
        root = QVBoxLayout(cw)
        root.setContentsMargins(12, 8, 12, 8)
        root.setSpacing(8)

        # Header
        headerW = QWidget(); headerL = QHBoxLayout(headerW)
        headerL.setContentsMargins(0,0,0,0); headerL.setSpacing(8)

        # NUEVO: Logo opcional a la izquierda
        self.logo_label = QLabel()
        self.logo_label.setVisible(False)
        if os.path.isfile(APP_LOGO_PATH):
            pm = QPixmap(APP_LOGO_PATH)
            if not pm.isNull():
                self.logo_label.setPixmap(pm.scaledToHeight(28, Qt.SmoothTransformation))
                self.logo_label.setVisible(True)
        headerL.addWidget(self.logo_label)

        self.lblSession = QLabel("(sin sesión) (USER)")
        self.lblSession.setStyleSheet("font-weight:700; color:#0E7490;")
        headerL.addWidget(self.lblSession); headerL.addStretch()

        self.lblSheets = QLabel("Google Sheets:")
        connected = gsheets_is_connected()
        self.lblSheetsStatus = QLabel(" Conectado" if connected else " Desconectado")
        self.lblSheetsStatus.setStyleSheet("color:#16a34a;" if connected else "color:#dc2626;")
        headerL.addWidget(self.lblSheets); headerL.addWidget(self.lblSheetsStatus)

        self.btnShort = QPushButton("⌨️"); self.btnShort.setToolTip("Atajos"); self.btnShort.setFixedSize(34, 32)
        self.btnShort.clicked.connect(self._toggle_shortcuts_panel); headerL.addWidget(self.btnShort)
        self.btnMenu = QPushButton("≡"); self.btnMenu.setToolTip("Login / Panel Admin"); self.btnMenu.setFixedSize(42, 32)
        self.btnMenu.clicked.connect(self._login_or_admin); headerL.addWidget(self.btnMenu)
        root.addWidget(headerW)

        # Fecha y Hora
        cardDate = card_frame()
        vl = QVBoxLayout(cardDate); vl.setContentsMargins(10, 8, 10, 8); vl.setSpacing(6)
        vl.addWidget(label_icon_title("📅", "Fecha y Hora"))
        self.lblDateTime = QLabel(""); self.lblDateTime.setStyleSheet("color:#16a34a; font-weight:700; font-size:13px;")
        vl.addWidget(self.lblDateTime)
        root.addWidget(cardDate)

        # Resumen del día
        cardSummary = card_frame()
        sl = QVBoxLayout(cardSummary); sl.setContentsMargins(10, 8, 10, 8); sl.setSpacing(8)
        sl.addWidget(label_icon_title("📊", "Resumen del día"))
        countersW = QWidget(); countersL = QHBoxLayout(countersW); countersL.setContentsMargins(0,0,0,0); countersL.setSpacing(8)
        self.badgeIn = QLabel("Entrantes: 0"); self.badgeOut = QLabel("Salientes: 0")
        for b, bg, fg in ((self.badgeIn, "#E0F2FE", "#0369A1"), (self.badgeOut, "#FEE2E2", "#991B1B")):
            b.setStyleSheet(f"background:{bg}; color:{fg}; border:1px solid rgba(0,0,0,0.06); border-radius:12px; padding:6px 10px; font-weight:700;")
        countersL.addWidget(self.badgeIn); countersL.addWidget(self.badgeOut); countersL.addStretch()
        sl.addWidget(countersW)
        self.lblSummary = QLabel("Entrantes: 0  Salientes: 0"); self.lblSummary.setVisible(False)
        root.addWidget(cardSummary)

        # Panel de atajos
        self.shortcutsPanel = QFrame(); self.shortcutsPanel.setObjectName("Card")
        spLay = QVBoxLayout(self.shortcutsPanel); spLay.setContentsMargins(8, 6, 8, 6); spLay.setSpacing(4)
        headerRow = QHBoxLayout(); lblAtajos = QLabel("⌨️ Atajos disponibles"); lblAtajos.setStyleSheet("font-weight:700; color:#343a40;")
        headerRow.addWidget(lblAtajos); headerRow.addStretch()
        self.btnCloseShort = QPushButton("✕"); self.btnCloseShort.setObjectName("shortcutsBtn"); self.btnCloseShort.setFixedSize(30, 26)
        self.btnCloseShort.clicked.connect(self._toggle_shortcuts_panel); headerRow.addWidget(self.btnCloseShort)
        spLay.addLayout(headerRow)
        self.lblAtajosList = QLabel(self._shortcuts_text_html()); self.lblAtajosList.setTextFormat(Qt.RichText); self.lblAtajosList.setWordWrap(True)
        self.lblAtajosList.setStyleSheet("color:#495057; font-size:12px;"); self.lblAtajosList.setMinimumWidth(340)
        scrollAtajos = QScrollArea(); scrollAtajos.setWidgetResizable(True); scrollAtajos.setFrameShape(QFrame.NoFrame)
        wrapW = QWidget(); wrapL = QVBoxLayout(wrapW); wrapL.setContentsMargins(0,0,0,0); wrapL.addWidget(self.lblAtajosList)
        scrollAtajos.setWidget(wrapW); spLay.addWidget(scrollAtajos)
        self.shortcutsPanel.setMaximumHeight(0); self.shortcutsPanel.setMinimumHeight(0); self.shortcutsPanel.setVisible(True)
        root.addWidget(self.shortcutsPanel)

        # Registro de llamada
        cardForm = card_frame()
        formL = QVBoxLayout(cardForm); formL.setContentsMargins(10, 8, 10, 8); formL.setSpacing(6)
        formL.addWidget(label_icon_title("☎️", "Registro de Llamada"))
        gridW = QWidget(); grid = QFormLayout(gridW)
        grid.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter); grid.setFormAlignment(Qt.AlignTop)
        grid.setHorizontalSpacing(12); grid.setVerticalSpacing(6)
        self.cmbTipo = QComboBox(); self.cmbArea = QComboBox(); self.cmbMotivo = QComboBox()
        self.txtObs = QTextEdit(); self.txtObs.setPlaceholderText(f"Escribe observaciones (máx. {OBS_MAX} caracteres)"); self.txtObs.setFixedHeight(88)
        self.txtObs.textChanged.connect(self._update_obs_counter)
        self.lblObsCount = QLabel(f"0/{OBS_MAX}"); self.lblObsCount.setAlignment(Qt.AlignRight); self.lblObsCount.setStyleSheet("color:#6b7280;")
        grid.addRow("Tipo:", self._with_right_tool(self.cmbTipo))
        grid.addRow("Área:", self._with_right_tool(self.cmbArea))
        grid.addRow("Motivo:", self._with_right_tool(self.cmbMotivo))
        obsWrap = QWidget(); obsLay = QVBoxLayout(obsWrap); obsLay.setContentsMargins(0,0,0,0); obsLay.setSpacing(2)
        obsLay.addWidget(self.txtObs); obsLay.addWidget(self.lblObsCount)
        grid.addRow("Observaciones:", obsWrap)
        formL.addWidget(gridW)
        root.addWidget(cardForm)

        # Botones acción
        actionsW = QWidget(); actionsL = QHBoxLayout(actionsW); actionsL.setContentsMargins(0,0,0,0); actionsL.setSpacing(10)
        self.btnRegistrar = QPushButton("💾 REGISTRAR"); self.btnRegistrar.setMinimumHeight(44); self.btnRegistrar.clicked.connect(self._register_call)
        self.btnLimpiar = QPushButton("🧹 LIMPIAR"); self.btnLimpiar.setMinimumHeight(44); self.btnLimpiar.clicked.connect(self._clear_form)
        actionsL.addWidget(self.btnRegistrar); actionsL.addWidget(self.btnLimpiar)
        root.addWidget(actionsW)

        # Ver registros
        self.btnVerRegistros = QPushButton("📋 VER REGISTROS"); self.btnVerRegistros.setMinimumHeight(44)
        self.btnVerRegistros.clicked.connect(self._show_today_records)
        root.addWidget(self.btnVerRegistros)

        # Spacer final
        root.addItem(QSpacerItem(0, 4, QSizePolicy.Minimum, QSizePolicy.Minimum))

        # Timer
        self.timer = QTimer(self); self.timer.timeout.connect(self._tick); self.timer.start(1000)

        # Precalentar toggle
        QTimer.singleShot(0, lambda: self._toggle_shortcuts_panel())
        QTimer.singleShot(0, lambda: self._toggle_shortcuts_panel())

        # Shortcuts
        self._setup_shortcuts()

    def _apply_styles(self):
        self.setStyleSheet("""
        QWidget {
            font-family: "Segoe UI", Arial, Helvetica, sans-serif;
            font-size: 13px;
            color: #111827;
            background: #FFF6E8;
        }
        #Card {
            border: 1px solid #E5E7EB;
            border-radius: 10px;
            background: #FFFFFF;
        }
        QLabel[secondary="true"] { color: #6B7280; }

        QPushButton {
            background-color: #E07A1F;
            color: #FFFFFF;
            border: none;
            border-radius: 8px;
            padding: 8px 12px;
            font-weight: 700;
        }
        QPushButton:hover { background-color: #C56614; }
        QPushButton:pressed { background-color: #A95510; }
        QPushButton:disabled { background-color: #CFCFD4; color: #F8FAFC; }

        QPushButton#shortcutsBtn {
            background: #F3F4F6; color: #374151; font-weight: 700;
            border-radius: 8px; padding: 4px 8px;
        }
        QPushButton#shortcutsBtn:hover { background: #E5E7EB; }

        QComboBox, QTextEdit, QLineEdit {
            border: 1px solid #E5E7EB; border-radius: 8px; padding: 6px 8px;
            background: #F8FAFC; color: #111827;
            selection-background-color: #0E7490; selection-color: #FFFFFF;
        }
        QComboBox:hover, QTextEdit:hover, QLineEdit:hover { border-color: #D1D5DB; }
        QComboBox:focus, QTextEdit:focus, QLineEdit:focus {
            border: 2px solid #0E7490; background: #FFFFFF;
        }
        QFormLayout > QLabel { color: #374151; font-weight: 600; }

        QTableWidget {
            background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 8px;
            gridline-color: #E5E7EB; selection-background-color: #FFE7CF;
            selection-color: #1F2937;
        }
        QHeaderView::section {
            background: #F3F4F6; color: #374151; padding: 4px 6px;
            border: 1px solid #E5E7EB; font-weight: 700;
        }
        QTabWidget::pane {
            border: 1px solid #E5E7EB; border-radius: 8px; padding: 6px; background: #FFFFFF;
        }
        QTabBar::tab {
            background: #F3F4F6; color: #374151; padding: 4px 10px; margin-right: 4px;
            border-top-left-radius: 8px; border-top-right-radius: 8px;
        }
        QTabBar::tab:selected { background: #FFFFFF; color: #111827; font-weight: 700; }
        QScrollArea { border: none; background: transparent; }
        QDialog { background: #FFFDF9; }
        QMessageBox { background: #FFFFFF; }
        """)

    def _post_build(self):
        self._refresh_combos_from_catalog()
        self._update_header()

    # ---------- Login/Admin ----------
    def _force_login_on_start(self):
        self._login_or_admin(startup=True)

    def _login_or_admin(self, startup=False):
        if not self.user["usuario"]:
            dlg = LoginDialog(self)
            if dlg.exec_() == QDialog.Accepted:
                u, p = dlg.get_credentials()
                rec = self.users_record
                user = get_user(rec, u)
                if not user or not user.get("active"):
                    QMessageBox.warning(self, "Login", "Usuario no encontrado o inactivo.")
                    if startup: self._force_login_on_start()
                    return
                if not password_verify(p, user.get("password", {})):
                    QMessageBox.warning(self, "Login", "Contraseña incorrecta.")
                    if startup: self._force_login_on_start()
                    return
                self.user = {"usuario": u, "rol": normalize_role(user.get("role", "USER"))}
                self._update_header()
                if user.get("must_change_password"):
                    ch = LoginDialog(self, force_change=True, username=u)
                    if ch.exec_() == QDialog.Accepted:
                        _, new1, new2 = ch.get_credentials()
                        if not new1 or len(new1) < 4 or new1 != new2:
                            QMessageBox.warning(self, "Cambio de contraseña", "Las contraseñas no coinciden o son muy cortas (mínimo 4).")
                            self.user = {"usuario": None, "rol": "USER"}
                            if startup: self._force_login_on_start()
                            return
                        user["password"] = password_hash(new1)
                        user["must_change_password"] = False
                        save_users(rec)
                        QMessageBox.information(self, "Contraseña", "Contraseña actualizada.")
                    else:
                        self.user = {"usuario": None, "rol": "USER"}
                        if startup: self._force_login_on_start()
                        return
        else:
            role = normalize_role(self.user.get("rol"))
            if role in (ROLE_ADMIN, ROLE_SUPERVISOR):
                self._open_admin_panel()
            else:
                QMessageBox.information(self, "Usuario", "No tienes permisos de administrador.")

    def _update_header(self):
        rol = self.user.get("rol", "USER")
        usr = self.user.get("usuario", None)
        self.lblSheetsStatus.setText(" Conectado" if gsheets_is_connected() else " Desconectado")
        self.lblSheetsStatus.setStyleSheet("color:#16a34a;" if gsheets_is_connected() else "color:#dc2626;")
        if usr:
            self.lblSession.setText(f"{usr} ({rol})")
            self.setWindowTitle(f"{APP_NAME} - {rol.title()}")
        else:
            self.lblSession.setText("(sin sesión) (USER)")
            self.setWindowTitle(f"{APP_NAME} - Usuario")

    # ---------- Atajos ----------
    def _setup_shortcuts(self):
        self.btnMenu.setShortcut("Ctrl+C")
        self.btnVerRegistros.setShortcut("Ctrl+V")
        self.btnRegistrar.setShortcut("Ctrl+R")

    def _shortcuts_text_html(self):
        return """
        <div style='font-size:14px'>
          <ul style='margin:0 0 0 16px;'>
            <li><b>Ctrl+C</b> — Configurar</li>
            <li><b>Ctrl+V</b> — Ver Registros</li>
            <li><b>Ctrl+R</b> — Registrar</li>
          </ul>
        </div>
        """

    def _toggle_shortcuts_panel(self):
        current = self.shortcutsPanel.maximumHeight()
        target = 0 if current > 0 else 160
        anim = QPropertyAnimation(self.shortcutsPanel, b"maximumHeight", self)
        anim.setDuration(180)
        anim.setStartValue(current)
        anim.setEndValue(target)
        anim.setEasingCurve(QEasingCurve.InOutCubic)
        anim.start()
        self._animShortcuts = anim

        def after():
            self.shortcutsPanel.setMaximumHeight(target)
            self.shortcutsPanel.setMinimumHeight(0 if target == 0 else 100)
            self.shortcutsPanel.updateGeometry()
            cw = self.centralWidget() if hasattr(self, "centralWidget") else None
            if cw:
                cw.updateGeometry()
        anim.finished.connect(after)

    # ---------- Helpers de Form ----------
    def _with_right_tool(self, widget):
        w = QWidget(); h = QHBoxLayout(w); h.setContentsMargins(0,0,0,0)
        h.addWidget(widget)
        btn = QPushButton("−"); btn.setFixedSize(26, 26); btn.setEnabled(False)
        h.addWidget(btn)
        return w

    def _update_obs_counter(self):
        text = self.txtObs.toPlainText()
        if len(text) > OBS_MAX:
            self.txtObs.blockSignals(True)
            self.txtObs.setPlainText(text[:OBS_MAX])
            cursor = self.txtObs.textCursor()
            cursor.movePosition(cursor.End)
            self.txtObs.setTextCursor(cursor)
            self.txtObs.blockSignals(False)
        self.lblObsCount.setText(f"{len(self.txtObs.toPlainText())}/{OBS_MAX}")

    # ---------- Reloj/Resumen ----------
    def _tick(self):
        now = datetime.now()
        self.lblDateTime.setText(now.strftime("%d/%m/%Y - %H:%M:%S"))
        self._update_summary()

    def _update_summary(self):
        self.badgeIn.setText(f"Entrantes: {self.counters['Entrantes']}")
        self.badgeOut.setText(f"Salientes: {self.counters['Salientes']}")
        if hasattr(self, 'lblSummary'):
            self.lblSummary.setText(f"Entrantes: {self.counters['Entrantes']}  Salientes: {self.counters['Salientes']}")

    # ---------- Acciones ----------
    def _validate_form(self):
        tipo = self.cmbTipo.currentText()
        area = self.cmbArea.currentText()
        motivo = self.cmbMotivo.currentText()
        if tipo == "Selecciona..." or area == "Selecciona..." or motivo == "Selecciona...":
            QMessageBox.warning(self, "Validación", "Completa Tipo, Área y Motivo.")
            return None
        return tipo, area, motivo

    def _register_call(self):
        valid = self._validate_form()
        if not valid: return
        tipo, area, motivo = valid
        obs = self.txtObs.toPlainText().strip()

        now = datetime.now()
        fecha = now.strftime("%d/%m/%Y")
        hora = now.strftime("%H:%M:%S")
        usuario = self.user.get("usuario") or "sin_sesion"
        rol = self.user.get("rol") or "USER"

        row = [fecha, hora, usuario, rol, tipo, area, motivo, obs]

        saved = False
        try:
            gsheets_append_row(row)
            saved = True
        except Exception:
            saved = False

        if not saved:
            with open(LOCAL_CSV, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if f.tell() == 0:
                    writer.writerow(["Fecha","Hora","Usuario","Rol","Tipo","Área","Motivo","Observaciones"])
                writer.writerow(row)

        if tipo.lower().startswith("entra"):
            self.counters["Entrantes"] += 1
        else:
            self.counters["Salientes"] += 1
        self._update_summary()

        QMessageBox.information(self, "Registro", "Llamada registrada correctamente.")
        self._clear_form()

    def _clear_form(self):
        self.cmbTipo.setCurrentIndex(0)
        self.cmbArea.setCurrentIndex(0)
        self.cmbMotivo.setCurrentIndex(0)
        self.txtObs.clear()
        self.lblObsCount.setText(f"0/{OBS_MAX}")

    def _show_today_records(self):
        rows = []
        try:
            rows = gsheets_fetch_today_records()
        except Exception:
            rows = []

        if not rows:
            try:
                with open(LOCAL_CSV, "r", encoding="utf-8") as f:
                    rd = csv.DictReader(f)
                    h = datetime.now().strftime("%d/%m/%Y")
                    for r in rd:
                        if r.get("Fecha") == h:
                            rows.append([
                                r.get("Fecha",""), r.get("Hora",""), r.get("Usuario",""),
                                r.get("Rol",""), r.get("Tipo",""), r.get("Área","") or r.get("Area",""),
                                r.get("Motivo",""), r.get("Observaciones","")
                            ])
            except FileNotFoundError:
                pass

        TodayRecordsDialog(rows, self).exec_()

    # ---------- Catálogo (JSON) ----------
    def _load_catalogo_json(self):
        if os.path.isfile(CATALOGO_JSON):
            try:
                with open(CATALOGO_JSON, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for k in ("tipos","areas","motivos"):
                    if k in data and isinstance(data[k], list):
                        self.catalogo[k] = data[k]
            except Exception:
                pass
        self._refresh_combos_from_catalog()

    def _save_catalogo_json(self):
        try:
            with open(CATALOGO_JSON, "w", encoding="utf-8") as f:
                json.dump(self.catalogo, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    def _refresh_combos_from_catalog(self):
        if hasattr(self, "cmbTipo"):
            self.cmbTipo.clear(); self.cmbTipo.addItems(["Selecciona..."] + self.catalogo["tipos"])
        if hasattr(self, "cmbArea"):
            self.cmbArea.clear(); self.cmbArea.addItems(["Selecciona..."] + self.catalogo["areas"])
        if hasattr(self, "cmbMotivo"):
            self.cmbMotivo.clear(); self.cmbMotivo.addItems(["Selecciona..."] + self.catalogo["motivos"])

    # ---------- Panel de Administración ----------
    def _open_admin_panel(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Panel de Administración")
        dlg.resize(760, 560)
        tabs = QTabWidget(dlg)

        # --- Tab Catálogo ---
        tabCatalog = QWidget(); catL = QVBoxLayout(tabCatalog); catL.setContentsMargins(10,8,10,8); catL.setSpacing(6)

        def make_list_editor(title, key):
            frame = QFrame(); frame.setObjectName("Card")
            lay = QVBoxLayout(frame); lay.setContentsMargins(10,8,10,8); lay.setSpacing(6)
            lay.addWidget(QLabel(f"🗂️ {title}"))
            listw = QListWidget(); listw.addItems(self.catalogo.get(key, [])); lay.addWidget(listw)
            row = QHBoxLayout(); inp = QLineEdit(); inp.setPlaceholderText(f"Nuevo {title[:-1].lower()}...")
            btnAdd = QPushButton("➕ Agregar"); btnDel = QPushButton("🗑️ Eliminar")
            row.addWidget(inp); row.addWidget(btnAdd); row.addWidget(btnDel); lay.addLayout(row)

            def add_item():
                txt = inp.text().strip()
                if not txt: return
                items = [listw.item(i).text() for i in range(listw.count())]
                if txt in items:
                    QMessageBox.information(dlg, "Duplicado", f"Ya existe: {txt}"); return
                listw.addItem(txt); inp.clear()

            def del_item():
                it = listw.currentItem()
                if it: listw.takeItem(listw.row(it))

            btnAdd.clicked.connect(add_item); btnDel.clicked.connect(del_item)
            return frame, listw

        boxTipos, listTipos = make_list_editor("Tipos", "tipos")
        boxAreas, listAreas = make_list_editor("Áreas", "areas")
        boxMotivos, listMotivos = make_list_editor("Motivos", "motivos")
        catL.addWidget(boxTipos); catL.addWidget(boxAreas); catL.addWidget(boxMotivos)

        btnsCat = QDialogButtonBox(QDialogButtonBox.Save)
        btnsCat.button(QDialogButtonBox.Save).setText("Guardar Catálogo")

        def on_save_catalog():
            self.catalogo["tipos"] = [listTipos.item(i).text() for i in range(listTipos.count())]
            self.catalogo["areas"] = [listAreas.item(i).text() for i in range(listAreas.count())]
            self.catalogo["motivos"] = [listMotivos.item(i).text() for i in range(listMotivos.count())]
            if self._save_catalogo_json():
                self._refresh_combos_from_catalog()
                QMessageBox.information(dlg, "Guardado", "Catálogo actualizado.")
            else:
                QMessageBox.warning(dlg, "Error", "No se pudo guardar el catálogo.")
        btnsCat.accepted.connect(on_save_catalog)
        catL.addWidget(btnsCat)

        # --- Tab Usuarios ---
        tabUsers = QWidget(); usrL = QVBoxLayout(tabUsers); usrL.setContentsMargins(10,8,10,8); usrL.setSpacing(6)

        self._users_table = QListWidget()
        usrL.addWidget(QLabel("👥 Usuarios")); usrL.addWidget(self._users_table)

        def refresh_users_list():
            self._users_table.clear()
            self.users_record = load_users()
            for u in self.users_record.get("users", []):
                status = "Activo" if u.get("active") else "Inactivo"
                self._users_table.addItem(f"{u.get('username')} — {normalize_role(u.get('role'))} — {status}")
        refresh_users_list()

        rowU1 = QHBoxLayout()
        self.inpUser = QLineEdit(); self.inpUser.setPlaceholderText("Usuario")
        self.cmbRole = QComboBox(); self.cmbRole.addItems(["USER", "SUPERVISOR", "ADMIN"])
        self.chkActive = QCheckBox("Activo"); self.chkActive.setChecked(True)
        rowU1.addWidget(self.inpUser); rowU1.addWidget(self.cmbRole); rowU1.addWidget(self.chkActive)
        usrL.addLayout(rowU1)

        rowU2 = QHBoxLayout()
        self.inpPass1 = QLineEdit(); self.inpPass1.setEchoMode(QLineEdit.Password); self.inpPass1.setPlaceholderText("Contraseña")
        self.inpPass2 = QLineEdit(); self.inpPass2.setEchoMode(QLineEdit.Password); self.inpPass2.setPlaceholderText("Confirmar")
        rowU2.addWidget(self.inpPass1); rowU2.addWidget(self.inpPass2)
        usrL.addLayout(rowU2)

        rowBtns = QHBoxLayout()
        btnAddU = QPushButton("➕ Crear/Actualizar")
        btnResetPass = QPushButton("🔑 Cambiar contraseña")
        btnToggleActive = QPushButton("⏯️ Activar/Desactivar")
        btnDeleteU = QPushButton("🗑️ Eliminar")
        for b in (btnAddU, btnResetPass, btnToggleActive, btnDeleteU):
            b.setMinimumHeight(36)
        rowBtns.addWidget(btnAddU); rowBtns.addWidget(btnResetPass); rowBtns.addWidget(btnToggleActive); rowBtns.addWidget(btnDeleteU)
        usrL.addLayout(rowBtns)

        def save_users_record():
            try:
                save_users(self.users_record)
                refresh_users_list()
                QMessageBox.information(dlg, "Usuarios", "Cambios guardados.")
            except Exception as e:
                QMessageBox.warning(dlg, "Usuarios", f"Error al guardar: {e}")

        def add_or_update_user():
            username = (self.inpUser.text() or "").strip()
            role = normalize_role(self.cmbRole.currentText())
            active = self.chkActive.isChecked()
            p1 = self.inpPass1.text(); p2 = self.inpPass2.text()
            if not username:
                QMessageBox.warning(dlg, "Usuarios", "Usuario requerido."); return
            rec = self.users_record
            existing = get_user(rec, username)
            if existing:
                if role == ROLE_ADMIN and not active and count_active_admins(rec) <= 1:
                    QMessageBox.warning(dlg, "Usuarios", "No puedes desactivar al último ADMIN."); return
                existing["role"] = role; existing["active"] = active
                if p1 or p2:
                    if len(p1) < 4 or p1 != p2:
                        QMessageBox.warning(dlg, "Usuarios", "Contraseña inválida o no coincide (mín. 4)."); return
                    existing["password"] = password_hash(p1); existing["must_change_password"] = False
            else:
                if len(p1) < 4 or p1 != p2:
                    QMessageBox.warning(dlg, "Usuarios", "Contraseña inválida o no coincide (mín. 4)."); return
                rec["users"].append({
                    "username": username, "role": role, "active": active,
                    "must_change_password": False, "password": password_hash(p1)
                })
            save_users_record()

        def reset_password():
            idx = self._users_table.currentRow()
            if idx < 0:
                QMessageBox.information(dlg, "Usuarios", "Selecciona un usuario de la lista."); return
            p1 = self.inpPass1.text(); p2 = self.inpPass2.text()
            if len(p1) < 4 or p1 != p2:
                QMessageBox.warning(dlg, "Usuarios", "Contraseña inválida o no coincide (mín. 4)."); return
            self.users_record["users"][idx]["password"] = password_hash(p1)
            self.users_record["users"][idx]["must_change_password"] = False
            save_users_record()

        def toggle_active():
            idx = self._users_table.currentRow()
            if idx < 0:
                QMessageBox.information(dlg, "Usuarios", "Selecciona un usuario."); return
            u = self.users_record["users"][idx]
            if normalize_role(u["role"]) == ROLE_ADMIN and count_active_admins(self.users_record) <= 1 and u["active"]:
                QMessageBox.warning(dlg, "Usuarios", "No puedes desactivar al último ADMIN."); return
            u["active"] = not u["active"]; save_users_record()

        def delete_user():
            idx = self._users_table.currentRow()
            if idx < 0:
                QMessageBox.information(dlg, "Usuarios", "Selecciona un usuario."); return
            u = self.users_record["users"][idx]
            if normalize_role(u["role"]) == ROLE_ADMIN and count_active_admins(self.users_record) <= 1:
                QMessageBox.warning(dlg, "Usuarios", "No puedes eliminar al último ADMIN."); return
            if QMessageBox.question(dlg, "Eliminar", f"¿Eliminar usuario '{u['username']}'?") == QMessageBox.Yes:
                del self.users_record["users"][idx]; save_users_record()

        btnAddU.clicked.connect(add_or_update_user)
        btnResetPass.clicked.connect(reset_password)
        btnToggleActive.clicked.connect(toggle_active)
        btnDeleteU.clicked.connect(delete_user)

        # --- Tab Google Sheets ---
        tabSheets = QWidget(); gsL = QFormLayout(tabSheets); gsL.setHorizontalSpacing(12); gsL.setVerticalSpacing(6)
        cfg = load_settings().get("google_sheets", {})
        self.edCreds = QLineEdit(cfg.get("credentials_file", "")); self.edSheetId = QLineEdit(cfg.get("sheet_id", "")); self.edTab = QLineEdit(cfg.get("sheet_tab", "Llamadas"))
        btnBrowse = QPushButton("Buscar JSON...")
        def pick_json():
            path, _ = QFileDialog.getOpenFileName(dlg, "Seleccionar credenciales JSON", "", "JSON (*.json)")
            if path: self.edCreds.setText(path)
        btnBrowse.clicked.connect(pick_json)

        rowCred = QHBoxLayout(); rowCred.addWidget(self.edCreds); rowCred.addWidget(btnBrowse)
        wrap = QWidget(); wrap.setLayout(rowCred)
        gsL.addRow("Credenciales JSON", wrap); gsL.addRow("Spreadsheet ID", self.edSheetId); gsL.addRow("Nombre de pestaña", self.edTab)
        btnsGs = QDialogButtonBox(QDialogButtonBox.Save); btnsGs.button(QDialogButtonBox.Save).setText("Guardar Configuración")

        def save_gs():
            s = load_settings()
            s["google_sheets"]["credentials_file"] = self.edCreds.text().strip()
            s["google_sheets"]["sheet_id"] = self.edSheetId.text().strip()
            s["google_sheets"]["sheet_tab"] = self.edTab.text().strip() or "Llamadas"
            save_settings(s); _gs_reset_cache()
            ok = gsheets_is_connected()
            QMessageBox.information(dlg, "Google Sheets", "Conectado correctamente." if ok else "Configuración guardada. Aún no conecta.")
            self._update_header()
        btnsGs.accepted.connect(save_gs)
        gsL.addRow(btnsGs)

        # --- Tab Bitrix (en desarrollo) ---
        tabBitrix = QWidget(); bxL = QVBoxLayout(tabBitrix); bxL.setContentsMargins(10,8,10,8); bxL.setSpacing(6)
        banner = QLabel("⚠️ Bitrix — En desarrollo")
        banner.setStyleSheet("background:#fee2e2; color:#b91c1c; font-weight:800; border:1px solid #fecaca; border-radius:8px; padding:8px 10px;")
        bxL.addWidget(banner)
        info = QLabel("Aquí podrás configurar la integración con Bitrix desde la app. Esta sección aún está en desarrollo.")
        info.setWordWrap(True); bxL.addWidget(info); bxL.addStretch()

        # Tabs
        tabs.addTab(tabCatalog, "Catálogo")
        idx_users = tabs.addTab(tabUsers, "Usuarios")
        idx_sheets = tabs.addTab(tabSheets, "Google Sheets")
        idx_bitrix = tabs.addTab(tabBitrix, "Bitrix")
        tabs.setTabText(idx_bitrix, "Bitrix (En desarrollo)")
        tabs.tabBar().setStyleSheet("QTabBar::tab:selected{background:#dc2626;color:#ffffff;} QTabBar::tab{padding:4px 10px;}")

        # Permisos
        role = normalize_role(self.user.get("rol"))
        is_admin = role == ROLE_ADMIN
        if not is_admin:
            for w in [self._users_table, self.inpUser, self.cmbRole, self.chkActive, self.inpPass1, self.inpPass2, btnAddU, btnResetPass, btnToggleActive, btnDeleteU]:
                if w: w.setDisabled(True); w.setToolTip("Gestión de usuarios: Solo disponible para Administrador")

        for w in [self.edCreds, self.edSheetId, self.edTab, btnBrowse, btnsGs]:
            if w:
                if is_admin:
                    w.setEnabled(True)
                else:
                    w.setDisabled(True); w.setToolTip("Solo disponible para Administrador")

        lay = QVBoxLayout(dlg); lay.setContentsMargins(10,8,10,8); lay.setSpacing(6)
        lay.addWidget(tabs)

        closeBtns = QDialogButtonBox(QDialogButtonBox.Close)
        closeBtns.button(QDialogButtonBox.Close).setText("Cerrar")
        closeBtns.rejected.connect(dlg.reject)
        lay.addWidget(closeBtns)

        dlg.exec_()

# =================== SINGLE INSTANCE (NUEVO) ===================
_single_server = None

def ensure_single_instance() -> bool:
    """True si esta es la única instancia; False si ya hay otra."""
    global _single_server
    # ¿Existe ya un servidor? -> hay otra instancia
    socket = QLocalSocket()
    socket.connectToServer(SINGLE_INSTANCE_KEY)
    if socket.waitForConnected(100):
        socket.abort()
        return False

    # Crear servidor y limpiar colgados
    _single_server = QLocalServer()
    try:
        QLocalServer.removeServer(SINGLE_INSTANCE_KEY)
    except Exception:
        pass
    ok = _single_server.listen(SINGLE_INSTANCE_KEY)
    return ok

# =================== MAIN ===================
def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)

    # Instancia única
    if not ensure_single_instance():
        print("Otra instancia de Tipificador ya está ejecutándose. Cerrando.")
        return 0

    # Icono de la aplicación (si existe)
    if os.path.isfile(APP_ICON_PATH):
        app.setWindowIcon(QIcon(APP_ICON_PATH))

    w = MainWindow()
    w.show()

    # Mantener viva la referencia del servidor
    app._single_instance_server = _single_server

    try:
        return app.exec_()
    except Exception as e:
        import traceback
        print("Fallo en app.exec_():", e)
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())