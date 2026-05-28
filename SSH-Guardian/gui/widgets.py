"""
widgets.py
----------
Yeniden kullanılabilir özel PyQt5 bileşenleri.

OOP prensibi: PyQt widget'larından türetip 'kendi component'lerimizi' yazarız.
Böylece dashboard.py daha temiz ve okunabilir kalır.
"""

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QFrame,
    QLabel,
    QVBoxLayout,
)

from gui.styles import COLOR_ACCENT, COLOR_DANGER, COLOR_WARNING, COLOR_SUCCESS


class StatCard(QFrame):
    """
    Tek bir KPI/metrik gösterir (örn. 'Failed Logins: 1,234').

    Kullanım:
        card = StatCard("Failed Logins", "0", accent="danger")
        card.set_value("1,234")
    """

    # Accent renk sözlüğü - string -> hex
    ACCENT_MAP = {
        "accent": COLOR_ACCENT,
        "danger": COLOR_DANGER,
        "warning": COLOR_WARNING,
        "success": COLOR_SUCCESS,
    }

    def __init__(self, label: str, value: str = "0",
                 accent: str = "accent", parent=None) -> None:
        super().__init__(parent)
        # objectName -> QSS'te #StatCard ile stillenir
        self.setObjectName("StatCard")
        self.setFrameShape(QFrame.NoFrame)

        color = self.ACCENT_MAP.get(accent, COLOR_ACCENT)

        # Layout: dikey - üstte küçük etiket, altta büyük değer
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(6)

        self.label_widget = QLabel(label.upper())
        self.label_widget.setObjectName("StatLabel")

        self.value_widget = QLabel(value)
        self.value_widget.setObjectName("StatValue")
        # Accent rengini dinamik olarak inline uyguluyoruz
        self.value_widget.setStyleSheet(f"color: {color};")

        layout.addWidget(self.label_widget)
        layout.addWidget(self.value_widget)
        layout.addStretch(1)

    def set_value(self, value: str) -> None:
        """Dışarıdan kart değeri güncellemek için."""
        self.value_widget.setText(value)
