from PyQt5.QtWidgets import QWidget
from PyQt5.QtGui import QPainter, QColor, QPen, QBrush, QFont, QLinearGradient, QPolygonF
from PyQt5.QtCore import Qt, QRectF, QTimer, QPointF


class MimicPanel(QWidget):
    """Professional responsive SCADA mimic panel for TEC/ICS dashboard."""

    def __init__(self):
        super().__init__()
        self.data = None
        self.pulse = 0
        self.setMinimumHeight(260)
        self.animation_timer = QTimer(self)
        self.animation_timer.timeout.connect(self._tick)
        self.animation_timer.start(180)

    def _tick(self):
        self.pulse = (self.pulse + 1) % 12
        self.update()

    def update_data(self, data):
        self.data = data
        self.update()

    def _status(self):
        if not self.data:
            return "UNKNOWN"
        return self.data.get("system_status", "UNKNOWN")

    def get_status_color(self):
        status = self._status()
        if status in ["NORMAL", "SAFE_MODE"]:
            return QColor("#22c55e")
        if status in ["WARNING", "OVERLOAD"]:
            return QColor("#facc15")
        if status in ["FAKE_SENSOR_ATTACK"]:
            return QColor("#a855f7")
        if status in ["PLC_ATTACK"]:
            return QColor("#fb923c")
        if status in ["EMERGENCY_STOP"]:
            return QColor("#60a5fa")
        return QColor("#ef4444")

    def get_component_color(self, component):
        base = QColor("#111827")
        if not self.data:
            return base

        status = self._status()
        t = float(self.data.get("temperature", 0))
        p = float(self.data.get("pressure", 0))
        rpm = float(self.data.get("turbine_rpm", 0))
        vib = float(self.data.get("vibration", 0))
        water = float(self.data.get("water_level", 100))

        danger = QColor("#7f1d1d")
        warning = QColor("#78350f")
        purple = QColor("#581c87")
        orange = QColor("#7c2d12")
        safe = QColor("#052e16")

        if status == "SAFE_MODE":
            return safe
        if component == "plc" and status == "FAKE_SENSOR_ATTACK":
            return purple
        if component == "plc" and status == "PLC_ATTACK":
            return orange
        if component == "boiler" and (t > 600 or p > 17):
            return danger
        if component == "boiler" and (t > 555 or p > 15.3):
            return warning
        if component == "turbine" and (rpm > 3300 or vib > 4.0):
            return danger
        if component == "turbine" and (rpm > 3150 or vib > 2.5):
            return warning
        if component == "pump" and water < 40:
            return danger
        if component == "pump" and water < 55:
            return warning
        if component == "generator" and status in ["OVERLOAD", "CRITICAL"]:
            return warning
        return base

    def sx(self, x):
        return self.left + x * self.scale

    def sy(self, y):
        return self.top + y * self.scale

    def sw(self, w):
        return w * self.scale

    def sh(self, h):
        return h * self.scale

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        bg = QLinearGradient(0, 0, self.width(), self.height())
        bg.setColorAt(0, QColor("#020617"))
        bg.setColorAt(1, QColor("#071427"))
        painter.fillRect(self.rect(), bg)

        design_w, design_h = 1180, 300
        self.scale = min(self.width() / design_w, self.height() / design_h)
        self.left = (self.width() - design_w * self.scale) / 2
        self.top = (self.height() - design_h * self.scale) / 2

        self._draw_grid(painter)
        self._draw_flows(painter)
        self._draw_components(painter)
        self._draw_alarm_overlay(painter)
        self._draw_status(painter)
        self._draw_values(painter)
        self._draw_legend(painter)

    def _draw_grid(self, painter):
        painter.setPen(QPen(QColor(20, 184, 166, 25), 1))
        for x in range(0, 1180, 40):
            painter.drawLine(int(self.sx(x)), int(self.sy(0)), int(self.sx(x)), int(self.sy(300)))
        for y in range(0, 300, 40):
            painter.drawLine(int(self.sx(0)), int(self.sy(y)), int(self.sx(1180)), int(self.sy(y)))

    def _draw_flows(self, painter):
        painter.setPen(QPen(QColor("#64748b"), max(2, int(4 * self.scale))))
        lines = [((210, 125), (310, 135)), ((430, 135), (525, 130)), ((700, 130), (790, 130)), ((520, 205), (520, 180))]
        for a, b in lines:
            painter.drawLine(int(self.sx(a[0])), int(self.sy(a[1])), int(self.sx(b[0])), int(self.sy(b[1])))

        status = self._status()
        if status != "UNKNOWN":
            flow_color = self.get_status_color()
            painter.setBrush(QBrush(flow_color))
            painter.setPen(Qt.NoPen)
            points = [(230 + self.pulse * 6, 126), (450 + self.pulse * 6, 133), (710 + self.pulse * 5, 130)]
            for x, y in points:
                painter.drawEllipse(int(self.sx(x)), int(self.sy(y)), max(5, int(8*self.scale)), max(5, int(8*self.scale)))

        # Animated direction arrows on pipelines
        if status != "UNKNOWN":
            arrow_color = self.get_status_color()
            painter.setBrush(QBrush(arrow_color))
            painter.setPen(Qt.NoPen)
            arrow_sets = [(250 + self.pulse * 7, 130), (470 + self.pulse * 7, 132), (735 + self.pulse * 6, 130)]
            for x, y in arrow_sets:
                if x < 300 or 445 < x < 520 or 705 < x < 785:
                    poly = QPolygonF([QPointF(self.sx(x), self.sy(y-6)), QPointF(self.sx(x+16), self.sy(y)), QPointF(self.sx(x), self.sy(y+6))])
                    painter.drawPolygon(poly)

    def _draw_components(self, painter):
        pen = QPen(QColor("#38bdf8"), max(2, int(3 * self.scale)))
        painter.setPen(pen)
        self._component_rect(painter, "boiler", 50, 70, 165, 105, "BOILER")
        self._component_circle(painter, "turbine", 310, 75, 118, "TURBINE")
        self._component_rect(painter, "generator", 525, 80, 170, 100, "GENERATOR")
        self._component_rect(painter, "pump", 790, 90, 150, 80, "PUMP")
        self._component_rect(painter, "plc", 430, 205, 170, 45, "PLC CONTROL")

    def _component_rect(self, painter, name, x, y, w, h, label):
        painter.setBrush(QBrush(self.get_component_color(name)))
        painter.setPen(QPen(QColor("#38bdf8"), max(2, int(3*self.scale))))
        painter.drawRoundedRect(QRectF(self.sx(x), self.sy(y), self.sw(w), self.sh(h)), self.sw(14), self.sh(14))
        self.draw_text(painter, x, y + h/2 + 5, label, size=11, center_w=w)

    def _component_circle(self, painter, name, x, y, d, label):
        painter.setBrush(QBrush(self.get_component_color(name)))
        painter.setPen(QPen(QColor("#94a3b8"), max(1, int(2*self.scale))))
        painter.drawEllipse(QRectF(self.sx(x), self.sy(y), self.sw(d), self.sh(d)))
        self.draw_text(painter, x, y + d/2 + 5, label, size=11, center_w=d)

    def _draw_turbine_animation(self, painter):
        if not self.data:
            return
        cx, cy, r = self.sx(369), self.sy(134), self.sw(42)
        color = self.get_status_color()
        painter.setPen(QPen(color, max(2, int(2*self.scale))))
        import math
        angle0 = self.pulse * 0.52
        for i in range(6):
            a = angle0 + i * math.pi / 3
            painter.drawLine(int(cx), int(cy), int(cx + math.cos(a) * r), int(cy + math.sin(a) * r))

    def _draw_alarm_overlay(self, painter):
        self._draw_turbine_animation(painter)
        status = self._status()
        if status in ["WARNING", "OVERLOAD", "PLC_ATTACK", "FAKE_SENSOR_ATTACK", "CRITICAL", "EMERGENCY_STOP"] and self.pulse % 2 == 0:
            color = self.get_status_color()
            painter.setPen(QPen(color, max(3, int(4*self.scale))))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(QRectF(self.sx(8), self.sy(8), self.sw(1164), self.sh(284)), self.sw(18), self.sh(18))
            painter.setFont(QFont("Arial", max(10, int(13*self.scale)), QFont.Bold))
            painter.drawText(int(self.sx(965)), int(self.sy(105)), "⚠ ACTIVE ALARM")

    def _draw_status(self, painter):
        color = self.get_status_color()
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QRectF(self.sx(970), self.sy(45), self.sw(36), self.sh(36)))
        painter.setPen(QPen(QColor("white")))
        painter.setFont(QFont("Arial", max(9, int(14 * self.scale)), QFont.Bold))
        painter.drawText(int(self.sx(1015)), int(self.sy(70)), f"STATUS: {self._status()}")

    def _draw_values(self, painter):
        if not self.data:
            return
        painter.setFont(QFont("Arial", max(8, int(10 * self.scale))))
        painter.setPen(QPen(QColor("#e5e7eb")))
        values = [
            (50, 215, f"Temp: {self.data['temperature']} °C"),
            (50, 235, f"Pressure: {self.data['pressure']} MPa"),
            (310, 215, f"RPM: {self.data['turbine_rpm']}"),
            (310, 235, f"Vibration: {self.data['vibration']} mm/s"),
            (525, 215, f"Power: {self.data['power_output']} MW"),
            (525, 235, f"Load: {self.data['load_percent']} %"),
            (790, 215, f"Water: {self.data['water_level']} %"),
        ]
        for x, y, text in values:
            painter.drawText(int(self.sx(x)), int(self.sy(y)), text)

    def _draw_legend(self, painter):
        painter.setFont(QFont("Arial", max(7, int(9 * self.scale))))
        painter.setPen(QPen(QColor("#94a3b8")))
        painter.drawText(int(self.sx(50)), int(self.sy(280)), "Green/NORMAL | Yellow/WARNING | Purple/AI anomaly | Orange/PLC | Red/CRITICAL/ATTACK")

    def draw_text(self, painter, x, y, text, size=11, center_w=None):
        painter.setPen(QPen(QColor("#e5e7eb")))
        painter.setFont(QFont("Arial", max(8, int(size * self.scale)), QFont.Bold))
        if center_w:
            rect = QRectF(self.sx(x), self.sy(y - 16), self.sw(center_w), self.sh(32))
            painter.drawText(rect, Qt.AlignCenter, text)
        else:
            painter.drawText(int(self.sx(x)), int(self.sy(y)), text)
