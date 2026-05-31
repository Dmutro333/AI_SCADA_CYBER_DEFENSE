from PyQt5.QtWidgets import QWidget
from PyQt5.QtGui import QPainter, QColor, QPen, QBrush, QFont
from PyQt5.QtCore import Qt


class NetworkTopologyPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumHeight(560)
        self.attack = None
        self.firewall_blocked = False
        self.ai_result = None

    def update_state(self, attack=None, firewall_blocked=False, ai_result=None):
        self.attack = attack
        self.firewall_blocked = firewall_blocked
        self.ai_result = ai_result
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor("#0f172a"))

        painter.setPen(QColor("#38bdf8"))
        painter.setFont(QFont("Arial", 18, QFont.Bold))
        painter.drawText(
            self.rect(),
            Qt.AlignTop | Qt.AlignHCenter,
            "Network Topology — архітектура OT/ICS мережі"
        )

        nodes = {
            "Internet\nAttack Source": {"x": 70, "y": 150, "color": "#7f1d1d"},
            "Firewall\nIPS/IDS": {"x": 310, "y": 150, "color": "#065f46"},
            "SCADA\nServer": {"x": 560, "y": 150, "color": "#0f172a"},
            "HMI\nOperator": {"x": 810, "y": 150, "color": "#0f172a"},
            "AI Engine\nDetection": {"x": 310, "y": 350, "color": "#0c4a6e"},
            "PLC\nController": {"x": 560, "y": 350, "color": "#0f172a"},
            "Database\nSQLite": {"x": 810, "y": 350, "color": "#0f172a"},
            "Sensor Gateway\nDigital Twin": {"x": 1060, "y": 350, "color": "#0f172a"},
        }

        if self.attack:
            nodes["Internet\nAttack Source"]["color"] = "#991b1b"

        if self.firewall_blocked:
            nodes["Firewall\nIPS/IDS"]["color"] = "#16a34a"

        if self.ai_result and self.ai_result.get("threat_level") in ["HIGH", "CRITICAL"]:
            nodes["AI Engine\nDetection"]["color"] = "#7f1d1d"

        connections = [
            ("Internet\nAttack Source", "Firewall\nIPS/IDS"),
            ("Firewall\nIPS/IDS", "SCADA\nServer"),
            ("SCADA\nServer", "HMI\nOperator"),
            ("SCADA\nServer", "AI Engine\nDetection"),
            ("AI Engine\nDetection", "PLC\nController"),
            ("SCADA\nServer", "PLC\nController"),
            ("PLC\nController", "Database\nSQLite"),
            ("Database\nSQLite", "Sensor Gateway\nDigital Twin"),
        ]

        centers = {}
        for name, item in nodes.items():
            centers[name] = (item["x"] + 75, item["y"] + 35)

        for a, b in connections:
            if self.attack and a == "Internet\nAttack Source":
                painter.setPen(QPen(QColor("#ef4444"), 5))
            elif self.firewall_blocked and a == "Firewall\nIPS/IDS":
                painter.setPen(QPen(QColor("#22c55e"), 5))
            else:
                painter.setPen(QPen(QColor("#64748b"), 3))

            x1, y1 = centers[a]
            x2, y2 = centers[b]
            painter.drawLine(x1, y1, x2, y2)

        for name, item in nodes.items():
            x = item["x"]
            y = item["y"]
            color = item["color"]

            painter.setPen(QPen(QColor("#38bdf8"), 2))
            painter.setBrush(QBrush(QColor(color)))
            painter.drawRoundedRect(x, y, 150, 70, 12, 12)

            painter.setPen(QColor("white"))
            painter.setFont(QFont("Arial", 10, QFont.Bold))
            painter.drawText(x, y, 150, 70, Qt.AlignCenter, name)

        self._draw_status_panel(painter)

    def _draw_status_panel(self, painter):
        x = 70
        y = 470
        w = 1150
        h = 70

        painter.setPen(QPen(QColor("#38bdf8"), 2))
        painter.setBrush(QBrush(QColor("#020617")))
        painter.drawRoundedRect(x, y, w, h, 12, 12)

        attack_text = "NONE"
        firewall_text = "WAITING"
        threat_text = "LOW"

        if self.attack:
            attack_text = self.attack.get("attack_type", "UNKNOWN")
            firewall_text = "BLOCKED" if self.firewall_blocked else "SUSPICIOUS"

        if self.ai_result:
            threat_text = self.ai_result.get("threat_level", "LOW")

        text = (
            f"Attack: {attack_text}     |     "
            f"Firewall: {firewall_text}     |     "
            f"AI Threat Level: {threat_text}"
        )

        painter.setPen(QColor("#e2e8f0"))
        painter.setFont(QFont("Arial", 12, QFont.Bold))
        painter.drawText(x, y, w, h, Qt.AlignCenter, text)