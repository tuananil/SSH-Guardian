"""
styles.py
---------
PyQt5 Qt Stylesheet (QSS). CSS benzeri sözdizimi ile dark cyber tema.

Renk paleti seçimi:
- Arka plan: #0E141B (koyu lacivert) - göze yormaz, gece çalışan SOC için ideal.
- Accent  : #00E5A8 (neon cyan)      - 'siber' hissi (Matrix, NSA-Lab vibe).
- Tehlike : #FF4D6D (kırmızı)        - HIGH risk uyarısı.
"""

# Renk paleti (Python sabitleri olarak da dışa açıyoruz - widget'lardan kullanırız)
COLOR_BG = "#0E141B"
COLOR_SURFACE = "#161E27"
COLOR_SURFACE_ALT = "#1E2935"
COLOR_BORDER = "#26303B"
COLOR_TEXT = "#E6EDF3"
COLOR_TEXT_DIM = "#8B98A5"
COLOR_ACCENT = "#00E5A8"
COLOR_DANGER = "#FF4D6D"
COLOR_WARNING = "#FFB454"
COLOR_SUCCESS = "#3DDC97"


# QSS string'i — uygulamanın tamamı için
APP_QSS = f"""
/* ========== GENEL ========== */
QWidget {{
    background-color: {COLOR_BG};
    color: {COLOR_TEXT};
    font-family: "Segoe UI", "SF Pro Display", "Helvetica Neue", Arial;
    font-size: 13px;
}}

QMainWindow {{
    background-color: {COLOR_BG};
}}

/* ========== SIDEBAR ========== */
#Sidebar {{
    background-color: {COLOR_SURFACE};
    border-right: 1px solid {COLOR_BORDER};
}}

#SidebarTitle {{
    color: {COLOR_ACCENT};
    font-size: 20px;
    font-weight: 700;
    padding: 24px 20px 8px 20px;
}}

#SidebarSubtitle {{
    color: {COLOR_TEXT_DIM};
    font-size: 11px;
    padding: 0px 20px 24px 20px;
}}

QPushButton#SidebarBtn {{
    background-color: transparent;
    color: {COLOR_TEXT};
    text-align: left;
    padding: 12px 20px;
    border: none;
    border-left: 3px solid transparent;
    font-size: 13px;
}}

QPushButton#SidebarBtn:hover {{
    background-color: {COLOR_SURFACE_ALT};
    border-left: 3px solid {COLOR_ACCENT};
}}

QPushButton#SidebarBtn:checked {{
    background-color: {COLOR_SURFACE_ALT};
    border-left: 3px solid {COLOR_ACCENT};
    color: {COLOR_ACCENT};
    font-weight: 600;
}}

/* ========== PRIMARY BUTTON ========== */
QPushButton#PrimaryBtn {{
    background-color: {COLOR_ACCENT};
    color: {COLOR_BG};
    font-weight: 700;
    border: none;
    border-radius: 6px;
    padding: 10px 18px;
}}

QPushButton#PrimaryBtn:hover {{
    background-color: #1FFFC0;
}}

QPushButton#SecondaryBtn {{
    background-color: {COLOR_SURFACE_ALT};
    color: {COLOR_TEXT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 10px 18px;
}}
QPushButton#SecondaryBtn:hover {{
    border: 1px solid {COLOR_ACCENT};
    color: {COLOR_ACCENT};
}}

/* ========== STAT CARDS ========== */
QFrame#StatCard {{
    background-color: {COLOR_SURFACE};
    border: 1px solid {COLOR_BORDER};
    border-radius: 10px;
    padding: 16px;
}}

QLabel#StatLabel {{
    color: {COLOR_TEXT_DIM};
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

QLabel#StatValue {{
    color: {COLOR_TEXT};
    font-size: 26px;
    font-weight: 800;
}}

/* ========== TABLE ========== */
QTableWidget {{
    background-color: {COLOR_SURFACE};
    alternate-background-color: {COLOR_SURFACE_ALT};
    gridline-color: {COLOR_BORDER};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    selection-background-color: {COLOR_ACCENT};
    selection-color: {COLOR_BG};
}}

QHeaderView::section {{
    background-color: {COLOR_SURFACE_ALT};
    color: {COLOR_TEXT_DIM};
    padding: 10px;
    border: none;
    border-bottom: 1px solid {COLOR_BORDER};
    font-weight: 700;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 1px;
}}

QTableWidget::item {{
    padding: 8px;
}}

/* ========== TEXT EDIT (logs viewer) ========== */
QPlainTextEdit, QTextEdit {{
    background-color: {COLOR_SURFACE};
    color: {COLOR_TEXT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    padding: 8px;
    font-family: "Consolas", "Menlo", "Courier New", monospace;
    font-size: 12px;
}}

/* ========== STATUS BAR ========== */
QStatusBar {{
    background-color: {COLOR_SURFACE};
    color: {COLOR_TEXT_DIM};
    border-top: 1px solid {COLOR_BORDER};
}}

/* ========== SCROLLBAR ========== */
QScrollBar:vertical {{
    background: {COLOR_BG};
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {COLOR_BORDER};
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {COLOR_ACCENT};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

/* ========== SPINBOX ========== */
QSpinBox {{
    background-color: {COLOR_SURFACE_ALT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 6px;
    color: {COLOR_TEXT};
}}
"""
