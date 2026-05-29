"""
charts.py
---------
PyQt5 içine GÖMÜLÜ matplotlib bar grafiği.

Kavram: matplotlib.backends.backend_qt5agg.FigureCanvasQTAgg, bir matplotlib
Figure'unu QWidget gibi davranan bir 'canvas'a saran adaptördür. Böylece
grafiği doğrudan PyQt layout'una koyabiliriz.

GeoIP veya saatlik grafik gibi görsel raporlar SOC analistleri için kritiktir.
"""

from datetime import datetime

from PyQt5.QtWidgets import QWidget, QVBoxLayout

import matplotlib
matplotlib.use("Qt5Agg")   # PyQt5 backend'ini önceden seç
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.dates as mdates

from gui.styles import (
    COLOR_BG, COLOR_SURFACE, COLOR_TEXT, COLOR_TEXT_DIM,
    COLOR_DANGER, COLOR_ACCENT,
)


class AttackChartWidget(QWidget):
    """
    Saatlik başarısız SSH login dağılımını gösteren bar grafiği.

    Kullanım:
        chart = AttackChartWidget()
        chart.update_data(result.hourly_failures)
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        # Figure (matplotlib'in ana çizim alanı)
        self.fig = Figure(figsize=(8, 4), facecolor=COLOR_BG, tight_layout=True)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvas(self.fig)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)

        self._apply_dark_style()
        self._draw_empty()

    # ------------------------------------------------------------------
    def _apply_dark_style(self) -> None:
        """Matplotlib eksenlerini dark cyber temaya uydur."""
        self.ax.set_facecolor(COLOR_SURFACE)
        for spine in self.ax.spines.values():
            spine.set_color(COLOR_TEXT_DIM)
        self.ax.tick_params(colors=COLOR_TEXT_DIM, which="both")
        self.ax.xaxis.label.set_color(COLOR_TEXT)
        self.ax.yaxis.label.set_color(COLOR_TEXT)
        self.ax.title.set_color(COLOR_ACCENT)
        self.ax.grid(True, color=COLOR_TEXT_DIM, alpha=0.15, linestyle="--")

    # ------------------------------------------------------------------
    def _draw_empty(self) -> None:
        self.ax.clear()
        self._apply_dark_style()
        self.ax.set_title("Hourly Failed Login Distribution")
        self.ax.text(
            0.5, 0.5,
            "Import an auth.log file to see the chart.",
            ha="center", va="center",
            transform=self.ax.transAxes,
            color=COLOR_TEXT_DIM, fontsize=11,
        )
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        self.canvas.draw_idle()

    # ------------------------------------------------------------------
    def update_data(self, hourly: list[tuple[datetime, int]]) -> None:
        """
        AnalysisResult.hourly_failures listesi ile grafiği yenile.

        Args:
            hourly: [(datetime_hour, failed_count), ...]
        """
        self.ax.clear()
        self._apply_dark_style()
        self.ax.set_title("Hourly Failed Login Distribution")

        if not hourly:
            self._draw_empty()
            return

        # Veriyi paketle
        times = [t for t, _ in hourly]
        counts = [c for _, c in hourly]

        # Renk: en yüksek bar kırmızı, diğerleri accent
        max_count = max(counts) if counts else 0
        colors = [
            COLOR_DANGER if c == max_count else COLOR_ACCENT for c in counts
        ]

        # Bar genişliği = 1 saat (matplotlib datetime için 1/24 gün)
        bars = self.ax.bar(times, counts, width=1 / 24, color=colors,
                           edgecolor=COLOR_BG, linewidth=0.5)

        # Eksen formatları
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Failed attempts")
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
        self.fig.autofmt_xdate(rotation=35)

        # En yüksek bar'a etiket yapıştır
        if max_count > 0:
            for bar, val in zip(bars, counts):
                if val == max_count:
                    self.ax.annotate(
                        f"⚠ {val}",
                        xy=(bar.get_x() + bar.get_width() / 2, val),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", color=COLOR_DANGER,
                        fontweight="bold", fontsize=9,
                    )
                    break

        self.canvas.draw_idle()
