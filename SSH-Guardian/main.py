"""
main.py
-------
SSH Guardian uygulamasının GİRİŞ NOKTASI.

Yapı:
  1. QApplication oluştur (her PyQt uygulamasında 1 tane olmalı)
  2. DashboardWindow oluştur
  3. Göster ve event loop'u başlat

Çalıştırma:
    python main.py
"""

import sys
from PyQt5.QtWidgets import QApplication

from gui.dashboard import DashboardWindow
from utils.constants import APP_NAME


def main() -> int:
    # QApplication: tüm GUI olaylarını yöneten ana nesne.
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)

    window = DashboardWindow()
    window.show()

    # exec_() -> event loop'u başlatır. Kullanıcı pencereyi kapatana kadar bloklar.
    return app.exec_()


if __name__ == "__main__":
    # if __name__ == "__main__" deyimi:
    # Bu dosya import edildiğinde main() çalışmaz, sadece doğrudan
    # çalıştırıldığında çalışır. Standart Python pratiğidir.
    sys.exit(main())
