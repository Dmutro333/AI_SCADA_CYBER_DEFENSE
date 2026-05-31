from war_room_mode import WarRoomWindow
from ai_ml_engine import RealAIMLEngine
import os
import webbrowser
import random

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QGridLayout, QTableWidget, QTableWidgetItem,
    QTabWidget, QMessageBox, QFrame, QLineEdit, QComboBox, QInputDialog,
    QGraphicsDropShadowEffect, QScrollArea, QSplitter, QSizePolicy, QHeaderView, QApplication
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QColor

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from sensors import TECSensors
from event_logger import EventLogger
from attack_engine import AttackEngine
from ai_engine import AIEngine
from defense_engine import DefenseEngine
from firewall_engine import FirewallEngine
from traffic_monitor import TrafficMonitor
from threat_intelligence import ThreatIntelligence
from mitre_mapper import MITREMapper
from risk_engine import RiskEngine
from correlation_engine import CorrelationEngine
from notification_center import NotificationCenter
from alert_rules import AlertRulesEngine
from training_engine import AITrainingEngine
from ml_model_trainer import MLModelTrainer
from ml_predictor import MLPredictor
from ml_report_exporter import MLReportExporter
from report_generator import IncidentReportGenerator
from dataset_exporter import DatasetExporter
from map_generator import AttackMapGenerator
from mimic_panel import MimicPanel
from network_topology import NetworkTopologyPanel
from config import THRESHOLDS, update_threshold, reset_thresholds
from backup_manager import BackupManager
from health_checker import HealthChecker
from session_manager import SessionManager
from rbac_report import RBACReportGenerator
from live_analytics_engine import LiveAnalyticsEngine
from ai_soc_orchestrator import LiveAISOCOrchestrator

from database import (
    add_sensor_data, get_event_logs,
    add_attack_record, get_attack_records,
    add_defense_record, get_defense_records,
    get_system_statistics,
    get_users, add_user,
    add_audit_record, get_audit_records,
    add_risk_record, get_risk_records,
    add_correlated_incident, get_correlated_incidents,
    add_notification_record, get_notification_records, clear_notification_records,
)


class SCADAWindow(QMainWindow):
    def __init__(self, username, role):
        self.real_ai_engine = RealAIMLEngine()
        self.real_ai_enabled = True
        super().__init__()
        self.username = username
        self.role = role

        self.session_manager = SessionManager(timeout_seconds=1800)
        self.sensors = TECSensors()
        self.logger = EventLogger(username, role)
        self.attack_engine = AttackEngine()
        self.ai_engine = AIEngine()
        self.defense_engine = DefenseEngine()
        self.firewall_engine = FirewallEngine()
        self.traffic_monitor = TrafficMonitor()
        self.threat_intel = ThreatIntelligence()
        self.mitre_mapper = MITREMapper()
        self.risk_engine = RiskEngine()
        self.correlation_engine = CorrelationEngine()
        self.notification_center = NotificationCenter()
        self.alert_rules = AlertRulesEngine()
        self.training_engine = AITrainingEngine()
        self.ml_trainer = MLModelTrainer()
        self.ml_predictor = MLPredictor()
        self.ml_report_exporter = MLReportExporter()
        self.report_generator = IncidentReportGenerator()
        self.dataset_exporter = DatasetExporter()
        self.map_generator = AttackMapGenerator()
        self.backup_manager = BackupManager()
        self.health_checker = HealthChecker()
        self.rbac_report_generator = RBACReportGenerator()
        self.live_analytics = LiveAnalyticsEngine()
        self.ai_soc_orchestrator = LiveAISOCOrchestrator()

        self.current_sensor_data = None
        self.last_attack = None
        self.last_ml_prediction = "MODEL_NOT_TRAINED"
        self.last_threat_intel_result = None
        self.last_mitre_result = None
        self.last_risk_result = None
        self.last_firewall_blocked = False
        self.last_incident = None
        self.auto_defense_enabled = False
        self._auto_defense_in_progress = False

        self.chart_time = []
        self.chart_temperature = []
        self.chart_pressure = []
        self.chart_rpm = []
        self.chart_load = []
        self.chart_vibration = []
        self.chart_anomaly = []
        self.chart_expected_rpm = []
        self.chart_expected_power = []
        self.chart_counter = 0
        self.last_ml_confidence = 0
        self.last_live_analytics = None
        self.soar_actions_history = []
        self.attack_timeline_history = []
        self.attack_propagation_stage = "IDLE"
        self.demo_mode_running = False
        self.demo_step_index = 0
        self.demo_steps_log = []
        self.live_attack_mode = False
        self.live_attack_counter = 0

        self.setWindowTitle(f"AI SCADA Cyber Defense — {username} / {role}")
        self.setGeometry(120, 60, 1450, 850)
        self.setMinimumSize(1280, 760)
        self.setStyleSheet(self.main_stylesheet())

        self.init_ui()

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_normal_data)
        self.timer.start(3000)

        self.session_timer = QTimer()
        self.session_timer.timeout.connect(self.update_session_label)
        self.session_timer.start(1000)

        self.timeout_timer = QTimer()
        self.timeout_timer.timeout.connect(self.check_session_timeout)
        self.timeout_timer.start(5000)

        self.live_attack_timer = QTimer()
        self.live_attack_timer.timeout.connect(self.live_attack_tick)

        self.logger.log_info("Відкрито головне SCADA-вікно")

    def create_button(self, text, callback, color="#2563eb"):
        button = QPushButton(text)
        button.clicked.connect(callback)
        if "EMERGENCY" in text.upper():
            base_color, hover_color, border_color = "#dc2626", "#ef4444", "#fca5a5"
        elif "RESET" in text.upper():
            base_color, hover_color, border_color = "#0284c7", "#0ea5e9", "#67e8f9"
        else:
            base_color, hover_color, border_color = color, "#0ea5e9", "#38bdf8"
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {base_color};
                border: 1px solid {border_color};
                border-radius: 10px;
                color: white;
                font-weight: bold;
                min-height: 34px;
                font-size: 13px;
                padding: 6px;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
                border: 2px solid #67e8f9;
            }}
            QPushButton:pressed {{
                background-color: #1d4ed8;
            }}
        """)
        return button

    def main_stylesheet(self):
        return """
            QMainWindow, QWidget { background-color: #0f172a; color: white; font-family: Arial; }
            QLabel { font-size: 14px; }
            QPushButton { padding: 10px; border-radius: 8px; background-color: #2563eb; color: white; font-weight: bold; }
            QPushButton:hover { background-color: #1d4ed8; }
            QTableWidget { background-color: #111827; color: white; gridline-color: #334155; border: 1px solid #334155; }
            QHeaderView::section { background-color: #1e293b; color: white; padding: 6px; }
            QTabWidget::pane { border: 1px solid #334155; }
            QTabBar::tab { background: #1e293b; color: white; padding: 10px; border-radius: 6px; margin: 2px; }
            QTabBar::tab:selected { background: #2563eb; }
            QFrame { background-color: #111827; border-radius: 12px; padding: 12px; }
        """

    # ---------- INIT UI ----------
    def init_ui(self):
        self.tabs = QTabWidget()
        tab_names = [
            ("dashboard_tab", "SCADA Dashboard"),
            ("summary_tab", "Summary Dashboard"),
            ("executive_tab", "Executive Dashboard"),
            ("digital_twin_tab", "Digital Twin"),
            ("attack_tab", "Attack Simulation"),
            ("demo_tab", "Demo Mode"),
            ("attack_map_tab", "Attack Map"),
            ("topology_tab", "Network Topology"),
            ("firewall_tab", "Firewall"),
            ("traffic_tab", "Traffic Monitor"),
            ("threat_intel_tab", "Threat Intel"),
            ("mitre_tab", "MITRE ICS"),
            ("risk_tab", "Risk Scoring"),
            ("correlation_tab", "Correlation"),
            ("notifications_tab", "Notifications"),
            ("ai_tab", "AI Analysis"),
            ("defense_tab", "Defense Center"),
            ("system_status_tab", "System Status"),
            ("timeline_tab", "Event Timeline"),
            ("analytics_tab", "Analytics"),
            ("charts_tab", "Live Charts"),
            ("logs_tab", "Журнал подій"),
            ("roles_tab", "Ролі доступу"),
            ("users_tab", "User Management"),
            ("config_tab", "Configuration"),
            ("backup_tab", "Backup"),
            ("health_tab", "Health Check"),
            ("audit_tab", "Audit Trail"),
            ("training_tab", "AI Training"),
        ]
        for attr, title in tab_names:
            widget = QWidget()
            setattr(self, attr, widget)
            self.tabs.addTab(widget, title)

        self.init_dashboard_tab()
        self.init_summary_tab()
        self.init_executive_tab()
        self.init_digital_twin_tab()
        self.init_attack_tab()
        self.init_demo_tab()
        self.init_attack_map_tab()
        self.init_topology_tab()
        self.init_firewall_tab()
        self.init_traffic_tab()
        self.init_threat_intel_tab()
        self.init_mitre_tab()
        self.init_risk_tab()
        self.init_correlation_tab()
        self.init_notifications_tab()
        self.init_ai_tab()
        self.init_defense_tab()
        self.init_system_status_tab()
        self.init_timeline_tab()
        self.init_analytics_tab()
        self.init_charts_tab()
        self.init_logs_tab()
        self.init_roles_tab()
        self.init_users_tab()
        self.init_config_tab()
        self.init_backup_tab()
        self.init_health_tab()
        self.init_audit_tab()
        self.init_training_tab()

        self.apply_role_permissions()
        self.setCentralWidget(self.tabs)

    def apply_role_permissions(self):
        if self.role == "Operator":
            self.hide_tabs_by_names(["Attack Simulation", "Demo Mode", "AI Training", "User Management", "Configuration", "Backup", "Firewall"])
        elif self.role == "Analyst":
            self.hide_tabs_by_names(["User Management", "Configuration", "Backup"])

    def hide_tabs_by_names(self, names):
        for name in names:
            for i in range(self.tabs.count() - 1, -1, -1):
                if self.tabs.tabText(i) == name:
                    self.tabs.removeTab(i)


    # ---------- SOC DASHBOARD WIDGETS ----------
    def create_soc_overview_panel(self):
        panel = QFrame()
        panel.setMinimumWidth(360)
        panel.setMaximumWidth(430)
        panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        panel.setStyleSheet("""
            QFrame { background-color: #07111f; border: 1px solid #164e63; border-radius: 14px; padding: 8px; }
            QLabel { border: none; }
        """)
        layout = QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        title = QLabel("SOC / SIEM LIVE PANEL")
        title.setAlignment(Qt.AlignCenter)
        title.setFixedHeight(30)
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #38bdf8;")

        self.soc_status_label = QLabel("Очікування подій...")
        self.soc_status_label.setMinimumHeight(82)
        self.soc_status_label.setMaximumHeight(105)
        self.soc_status_label.setStyleSheet("font-size: 13px; color: #e5e7eb; background-color: #020617; border: 1px solid #12395b; border-radius: 10px; padding: 10px;")
        self.soc_status_label.setWordWrap(True)

        self.soc_alert_table = QTableWidget(0, 4)
        self.soc_alert_table.setHorizontalHeaderLabels(["Time", "Type", "Severity", "AI"])
        self.soc_alert_table.setMinimumHeight(150)
        self.soc_alert_table.setMaximumHeight(210)
        self.soc_alert_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.soc_alert_table.verticalHeader().setVisible(False)
        self.soc_alert_table.setStyleSheet("QTableWidget { font-size: 11px; }")

        self.soc_action_label = QLabel("Auto Defense: OFF\nFirewall: READY\nCorrelation: READY")
        self.soc_action_label.setMinimumHeight(84)
        self.soc_action_label.setMaximumHeight(120)
        self.soc_action_label.setStyleSheet("font-size: 12px; color: #a7f3d0; background-color: #020617; border: 1px solid #14532d; border-radius: 10px; padding: 8px;")
        self.soc_action_label.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(self.soc_status_label)
        layout.addWidget(self.soc_alert_table)
        layout.addWidget(self.soc_action_label)
        layout.addStretch(1)
        panel.setLayout(layout)
        return panel

    def update_soc_panel(self, event_type="SYSTEM", severity="INFO", ai_result=None):
        if not hasattr(self, "soc_status_label"):
            return
        d = self.current_sensor_data or {}
        ai = ai_result or self.ai_engine.analyze(d) if d else {"threat_level": "UNKNOWN", "confidence": 0, "score": 0}
        attack = self.last_attack or {}
        attack_line = "Немає активної атаки"
        if attack:
            attack_line = f"{attack.get('attack_type')} | {attack.get('source_ip')} -> {attack.get('target')}"
        self.soc_status_label.setText(
            f"Plant: {d.get('system_status', 'UNKNOWN')}\n"
            f"Threat: {ai.get('threat_level', 'UNKNOWN')} | Score: {ai.get('score', 0)} | Confidence: {ai.get('confidence', 0)}%\n"
            f"Last attack: {attack_line}"
        )
        row = self.soc_alert_table.rowCount()
        self.soc_alert_table.insertRow(row)
        import datetime
        values = [datetime.datetime.now().strftime("%H:%M:%S"), event_type, severity, str(ai.get("confidence", 0)) + "%"]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            if severity in ["CRITICAL", "HIGH"]:
                item.setForeground(QColor("#ef4444"))
            elif severity in ["WARNING", "MEDIUM"]:
                item.setForeground(QColor("#facc15"))
            else:
                item.setForeground(QColor("#22c55e"))
            self.soc_alert_table.setItem(row, col, item)
        if self.soc_alert_table.rowCount() > 8:
            self.soc_alert_table.removeRow(0)
        self.soc_alert_table.scrollToBottom()
        self.soc_action_label.setText(
            f"Auto Defense: {'ON' if self.auto_defense_enabled else 'OFF'}\n"
            f"Safe Mode: {self.defense_engine.safe_mode}\n"
            f"PLC Isolated: {self.defense_engine.isolated_plc}\n"
            f"Blocked IPs: {', '.join(self.defense_engine.blocked_ips) if self.defense_engine.blocked_ips else 'немає'}"
        )

    # ---------- DASHBOARD ----------
    def init_dashboard_tab(self):
        """Enterprise-style adaptive dashboard layout.

        Верх: назва + користувач/сесія.
        Центр: QSplitter = SCADA mimic зліва + SOC/SIEM панель справа.
        Низ: KPI-картки + кнопки керування. Така схема не роз'їжджається при
        зміні розміру вікна і не створює велику порожню область зверху.
        """
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 8, 10, 8)
        main_layout.setSpacing(8)

        header = QLabel("AI SCADA CYBER DEFENSE SYSTEM — ТЕЦ / CRITICAL INFRASTRUCTURE")
        header.setAlignment(Qt.AlignCenter)
        header.setFixedHeight(34)
        header.setStyleSheet("""
            font-size: 21px;
            font-weight: bold;
            color: #38bdf8;
            padding: 2px;
        """)

        top_row = QHBoxLayout()
        top_row.setContentsMargins(4, 0, 4, 0)
        user_label = QLabel(f"Користувач: {self.username} | Роль: {self.role}")
        user_label.setStyleSheet("font-size: 13px; font-weight: bold; color: white;")
        user_label.setAlignment(Qt.AlignLeft)
        self.session_label = QLabel("Сесія: —")
        self.session_label.setStyleSheet("font-size: 13px; font-weight: bold; color: white;")
        self.session_label.setAlignment(Qt.AlignRight)
        top_row.addWidget(user_label)
        top_row.addStretch()
        top_row.addWidget(self.session_label)

        # LEFT SIDE: SCADA mimic + KPI cards + command buttons
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        self.mimic_panel = MimicPanel()
        self.mimic_panel.setMinimumHeight(280)
        self.mimic_panel.setMaximumHeight(330)
        self.mimic_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        left_layout.addWidget(self.mimic_panel)

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)

        self.temperature_label = self.create_sensor_card("Температура пари", "— °C")
        self.pressure_label = self.create_sensor_card("Тиск", "— МПа")
        self.rpm_label = self.create_sensor_card("Оберти турбіни", "— RPM")
        self.power_label = self.create_sensor_card("Генерація", "— MW")
        self.vibration_label = self.create_sensor_card("Вібрація", "— mm/s")
        self.water_label = self.create_sensor_card("Рівень води", "— %")
        self.load_label = self.create_sensor_card("Навантаження ТЕЦ", "— %")
        self.status_label = self.create_sensor_card("Стан системи", "UNKNOWN")
        self.ai_threat_label = self.create_sensor_card("AI Threat Level", "UNKNOWN")
        self.ai_confidence_label = self.create_sensor_card("AI Confidence", "— %")
        self.ml_prediction_label = self.create_sensor_card("ML Prediction", "NOT TRAINED")

        widgets = [
            self.temperature_label, self.pressure_label, self.rpm_label,
            self.power_label, self.vibration_label, self.water_label,
            self.load_label, self.status_label, self.ai_threat_label,
            self.ai_confidence_label, self.ml_prediction_label,
        ]
        for idx, widget in enumerate(widgets):
            grid.addWidget(widget, idx // 3, idx % 3)
        left_layout.addLayout(grid)

        btn_layout = QGridLayout()
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setHorizontalSpacing(8)
        btn_layout.setVerticalSpacing(6)
        dashboard_buttons = [
            ("NORMAL MODE", self.update_normal_data, "#2563eb"),
            ("WARNING", self.simulate_warning, "#ca8a04"),
            ("CRITICAL", self.simulate_critical, "#dc2626"),
            ("Fake Sensor Attack", self.simulate_fake_sensor_attack, "#7c3aed"),
            ("PLC Attack", self.simulate_plc_attack, "#ea580c"),
            ("Оновити журнал", self.load_logs, "#2563eb"),
        ]
        all_buttons = []
        for text, callback, color in dashboard_buttons:
            all_buttons.append(self.create_button(text, callback, color))
        self.auto_defense_btn = self.create_button("Auto Defense: OFF", self.toggle_auto_defense, "#2563eb")
        all_buttons += [
            self.auto_defense_btn,
            self.create_button("EMERGENCY STOP", self.emergency_stop, "#dc2626"),
            self.create_button("RESET PLANT", self.reset_plant, "#0284c7"),
            self.create_button("Вийти", self.logout, "#334155"),
        ]
        for idx, btn in enumerate(all_buttons):
            btn.setMinimumHeight(36)
            btn_layout.addWidget(btn, idx // 5, idx % 5)
        left_layout.addLayout(btn_layout)
        left_widget.setLayout(left_layout)

        # RIGHT SIDE: SOC / SIEM overview
        self.soc_panel = self.create_soc_overview_panel()

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(6)
        splitter.addWidget(left_widget)
        splitter.addWidget(self.soc_panel)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([1080, 390])

        main_layout.addWidget(header)
        main_layout.addLayout(top_row)
        main_layout.addWidget(splitter, 1)

        self.dashboard_tab.setLayout(main_layout)

    def create_sensor_card(self, title, value):
        frame = QFrame()
        frame.setMinimumHeight(82)
        frame.setMaximumHeight(96)
        frame.setStyleSheet("""
            QFrame { background-color: #081426; border: 1px solid #12395b; border-radius: 14px; padding: 4px; }
            QFrame:hover { border: 2px solid #38bdf8; }
        """)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setOffset(0, 0)
        shadow.setColor(QColor(0, 180, 255, 35))
        frame.setGraphicsEffect(shadow)
        layout = QVBoxLayout()
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(6)
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 13px; font-weight: bold; color: #94a3b8; border: none;")
        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #22c55e; border: none;")
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        frame.setLayout(layout)
        frame.value_label = value_label
        return frame

    def update_sensor_labels(self, data):
        self.current_sensor_data = data
        self.temperature_label.value_label.setText(f"{data['temperature']} °C")
        self.pressure_label.value_label.setText(f"{data['pressure']} МПа")
        self.rpm_label.value_label.setText(f"{data['turbine_rpm']} RPM")
        self.power_label.value_label.setText(f"{data['power_output']} MW")
        self.vibration_label.value_label.setText(f"{data['vibration']} mm/s")
        self.water_label.value_label.setText(f"{data['water_level']} %")
        self.load_label.value_label.setText(f"{data['load_percent']} %")
        self.status_label.value_label.setText(data["system_status"])
        color = {"NORMAL": "#22c55e", "SAFE_MODE": "#38bdf8", "WARNING": "#facc15", "EMERGENCY_STOP": "#a855f7"}.get(data["system_status"], "#ef4444")
        self.status_label.value_label.setStyleSheet(f"font-size: 26px; font-weight: bold; color: {color};")
        add_sensor_data(data["temperature"], data["pressure"], data["turbine_rpm"], data["power_output"], data["vibration"], data["water_level"], data["load_percent"], data["system_status"])
        self.mimic_panel.update_data(data)
        if hasattr(self, "digital_twin_mimic"):
            self.digital_twin_mimic.update_data(data)
        if hasattr(self, "dt_temperature"):
            self.dt_temperature.value_label.setText(f"{data['temperature']} °C")
            self.dt_pressure.value_label.setText(f"{data['pressure']} МПа")
            self.dt_rpm.value_label.setText(f"{data['turbine_rpm']} RPM")
            self.dt_power.value_label.setText(f"{data['power_output']} MW")
            self.dt_vibration.value_label.setText(f"{data['vibration']} mm/s")
            self.dt_water.value_label.setText(f"{data['water_level']} %")
        self.run_ai_analysis(data)
        if hasattr(self, "update_soc_panel"):
            self.update_soc_panel("SENSOR", data.get("system_status", "INFO"))
        self.evaluate_alerts(data)
        self.update_chart_history(data)
        if hasattr(self, "system_status_text"):
            self.update_system_status_panel()
        if hasattr(self, "summary_label"):
            self.update_summary_dashboard()
        if hasattr(self, "executive_label"):
            self.update_executive_dashboard()
        if hasattr(self, "risk_label"):
            self.calculate_risk(silent=True)

    def update_normal_data(self):
        self.update_sensor_labels(self.sensors.generate_normal_data())

    def simulate_warning(self):
        self.mark_activity()
        self.update_sensor_labels(self.sensors.generate_warning_data())
        self.logger.log_warning("Виявлено попереджувальний стан технологічного процесу")
        self.load_logs()

    def simulate_critical(self):
        self.mark_activity()
        self.update_sensor_labels(self.sensors.generate_critical_data())
        self.logger.log_critical("Критичний стан ТЕЦ: перевищення допустимих параметрів")
        self.load_logs()

    # ---------- ATTACKS ----------
    def init_attack_tab(self):
        layout = QVBoxLayout()
        title = QLabel("Attack Simulation Center — кіберполігон OT/ICS")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #ef4444;")
        desc = QLabel("Симуляція атак OT/ICS: DDoS, Modbus Injection, Fake Sensor, Replay, PLC Manipulation, MITM, Unauthorized Modbus Write, Brute Force, Coordinated Turbine Sabotage.")
        desc.setStyleSheet("font-size: 16px; color: #e5e7eb;")
        grid = QGridLayout()
        attacks = [
            ("DDoS Attack", self.simulate_ddos_attack),
            ("Modbus Command Injection", self.simulate_modbus_attack),
            ("Fake Sensor Data", self.simulate_fake_sensor_attack),
            ("Replay Attack", self.simulate_replay_attack),
            ("PLC Manipulation", self.simulate_plc_attack),
            ("Database Attack", self.simulate_database_attack),
            ("MITM Attack", self.simulate_mitm_attack),
            ("Unauthorized Modbus Write", self.simulate_unauthorized_modbus_write),
            ("Brute Force SCADA Login", self.simulate_bruteforce_attack),
            ("Coordinated Turbine Sabotage", self.simulate_turbine_sabotage),
            ("Random Attack Scenario", self.simulate_random_attack),
            ("START FULL DEFENSE DEMO", self.start_full_attack_demo),
        ]
        for i, (text, callback) in enumerate(attacks):
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            grid.addWidget(btn, i // 3, i % 3)

        self.live_attack_btn = QPushButton("LIVE SOC ATTACKS: OFF")
        self.live_attack_btn.setStyleSheet("background-color:#0f766e; color:white; font-weight:bold; padding:12px; border-radius:10px;")
        self.live_attack_btn.clicked.connect(self.toggle_live_attack_mode)
        grid.addWidget(self.live_attack_btn, 4, 0, 1, 3)

        self.attack_info = QLabel("Очікування запуску сценарію атаки...")
        self.attack_info.setAlignment(Qt.AlignCenter)
        self.attack_info.setStyleSheet("font-size: 16px; color: #facc15; background-color: #111827; padding: 20px; border-radius: 12px;")
        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addLayout(grid)
        layout.addWidget(self.attack_info)
        self.attack_tab.setLayout(layout)

    def check_attack_permission(self):
        if self.role not in ["Admin", "Analyst"]:
            QMessageBox.warning(self, "Обмеження доступу", "Запуск симуляцій атак доступний лише Admin або Analyst.")
            return False
        return True

    def log_attack_event(self, attack):
        self.mark_activity()
        self.last_attack = attack
        self.last_mitre_result = self.mitre_mapper.map_attack(attack["attack_type"])
        self.last_threat_intel_result = self.threat_intel.analyze_attack(attack)
        firewall_result = self.firewall_engine.inspect_attack(attack)
        self.last_firewall_blocked = firewall_result["blocked"]
        self.traffic_monitor.generate_attack_traffic(attack, blocked=firewall_result["blocked"])
        description = f"{attack['attack_type']} | Джерело: {attack['source_ip']} ({attack['source']}) | Ціль: {attack['target']} | Опис: {attack['description']} | Вплив: {attack['impact']}"
        self.logger.log_attack(description)
        if firewall_result["blocked"]:
            self.logger.log_defense(f"Firewall заблокував IP {firewall_result['source_ip']} через {firewall_result['reason']}")
        self.logger.log_warning(f"Threat Intelligence: IP={self.last_threat_intel_result['source_ip']}, Risk={self.last_threat_intel_result['final_risk']}, Listed={self.last_threat_intel_result['ip_listed']}")
        self.add_notification("Кібератака", f"{attack['attack_type']} з IP {attack['source_ip']} на {attack['target']}", attack["severity"])
        add_attack_record(attack)
        if hasattr(self, "attack_info"):
            indicators = ", ".join(attack.get("network_indicators", [])) or "немає"
            self.attack_info.setText(
                f"Атака: {attack['attack_type']}\n"
                f"Attack ID: {attack.get('attack_id')}\n"
                f"Kill Chain: {attack.get('kill_chain_phase', 'UNKNOWN')}\n"
                f"Джерело: {attack['source_ip']} ({attack['source']})\n"
                f"Ціль: {attack['target']}\n"
                f"Рівень: {attack['severity']}\n"
                f"Індикатори: {indicators}\n"
                f"Вплив: {attack['impact']}\n"
                f"Рекомендована реакція: {attack.get('recommended_response', '')}"
            )
        self.run_post_attack_soc_workflow(attack)
        self.update_attack_related_panels()
        if hasattr(self, "update_soc_panel"):
            self.update_soc_panel(attack.get("attack_type", "ATTACK"), attack.get("severity", "HIGH"))
        self.attack_timeline_history.append({
            "time": self.session_manager.get_login_time(),
            "attack": attack.get("attack_type"),
            "source_ip": attack.get("source_ip"),
            "target": attack.get("target"),
            "severity": attack.get("severity"),
            "mitre": (self.last_mitre_result or {}).get("technique_id", "N/A"),
            "incident": (self.last_incident or {}).get("incident_level", "N/A"),
            "propagation": self.attack_propagation_stage,
        })
        self.load_logs()
        if hasattr(self, "timeline_text"):
            self.load_timeline()
        if hasattr(self, "executive_label"):
            self.update_executive_dashboard()
        if not getattr(self, "demo_mode_running", False):
            QMessageBox.information(self, "Симуляція атаки", f"Атака: {attack['attack_type']}\nДжерело: {attack['source_ip']}\nЦіль: {attack['target']}\nРівень: {attack['severity']}\n\n{attack['impact']}\n\nРекомендована реакція:\n{attack.get('recommended_response', '')}")

    def run_post_attack_soc_workflow(self, attack):
        """SOAR-style workflow: Attack -> AI -> Risk -> Correlation -> Auto Defense."""
        if not self.current_sensor_data:
            return
        ai = self.ai_engine.analyze(self.current_sensor_data)
        self.last_risk_result = self.risk_engine.calculate_risk(
            self.current_sensor_data,
            ai,
            attack,
            self.last_threat_intel_result,
            self.last_mitre_result,
            self.last_firewall_blocked
        )
        add_risk_record(self.last_risk_result)
        self.last_incident = self.correlation_engine.correlate(
            self.current_sensor_data,
            ai,
            attack,
            self.last_threat_intel_result,
            self.last_risk_result,
            self.defense_engine,
            self.last_mitre_result,
            self.last_firewall_blocked
        )
        add_correlated_incident(self.last_incident)
        self.logger.log_warning(
            f"SOAR Workflow: attack={attack.get('attack_type')}, "
            f"risk={self.last_risk_result['risk_level']}({self.last_risk_result['risk_score']}), "
            f"incident={self.last_incident['incident_level']}({self.last_incident['incident_score']})"
        )
        if hasattr(self, "risk_label"):
            factors = "\n".join([f"- {x}" for x in self.last_risk_result["factors"]])
            self.risk_label.setText(
                f"RISK SCORING RESULT\n\nRisk Level: {self.last_risk_result['risk_level']}\n"
                f"Risk Score: {self.last_risk_result['risk_score']} / 100\n\nФактори ризику:\n{factors}"
            )
        if hasattr(self, "correlation_label"):
            findings = "\n".join([f"- {x}" for x in self.last_incident["findings"]])
            self.correlation_label.setText(
                f"CORRELATED INCIDENT\n\nЧас: {self.last_incident['time']}\n"
                f"Incident Type: {self.last_incident['incident_type']}\n"
                f"Incident Level: {self.last_incident['incident_level']}\n"
                f"Incident Score: {self.last_incident['incident_score']} / 100\n\nОзнаки:\n{findings}\n\n"
                f"Рекомендація: {self.last_incident['recommendation']}"
            )
        if self.auto_defense_enabled and self.last_incident["incident_level"] in ["HIGH", "CRITICAL"]:
            defense = self.defense_engine.activate_defense(ai, attack)
            add_defense_record(defense)
            self.soar_actions_history.append({"attack": attack.get("attack_type"), "level": self.last_incident["incident_level"], "actions": defense.get("actions", [])})
            self.add_notification("SOAR AUTO RESPONSE", "; ".join(defense.get("actions", [])), "CRITICAL")
            self.logger.log_defense("SOAR AUTO RESPONSE: " + "; ".join(defense["actions"]))
            if hasattr(self, "defense_status_label"):
                self.show_defense_result(defense)
            if defense.get("safe_mode"):
                self.update_sensor_labels(self.sensors.apply_safe_mode())
            if hasattr(self, "update_soc_panel"):
                self.update_soc_panel("SOAR_RESPONSE", self.last_incident["incident_level"])

    def update_attack_related_panels(self):
        if hasattr(self, "traffic_table"):
            self.load_traffic()
        if hasattr(self, "threat_intel_label"):
            self.update_threat_intel_panel()
        if hasattr(self, "mitre_label"):
            self.update_mitre_panel()
        if hasattr(self, "firewall_status_label"):
            self.update_firewall_status()
        if hasattr(self, "topology_panel"):
            self.update_topology()
        if hasattr(self, "attack_map_label") and self.last_attack:
            self.update_attack_map(self.last_attack)

    def toggle_live_attack_mode(self):
        """Вмикає/вимикає режим живого SOC-кіберполігону."""
        if not self.check_attack_permission():
            return
        self.live_attack_mode = not self.live_attack_mode
        if self.live_attack_mode:
            self.live_attack_counter = 0
            self.live_attack_timer.start(7000)
            if hasattr(self, "live_attack_btn"):
                self.live_attack_btn.setText("LIVE SOC ATTACKS: ON")
                self.live_attack_btn.setStyleSheet("background-color:#16a34a; color:white; font-weight:bold; padding:12px; border-radius:10px;")
            if hasattr(self, "attack_info"):
                self.attack_info.setText(
                    "LIVE SOC MODE УВІМКНЕНО\n\n"
                    "Система автоматично генерує OT/ICS атаки кожні 7 секунд, "
                    "оновлює AI/SIEM, карту, timeline, risk scoring та SOAR-рекомендації."
                )
            self.add_notification("LIVE SOC MODE", "Автоматична генерація атак увімкнена", "WARNING")
            self.logger.log_warning("LIVE SOC MODE ON: автоматична генерація атак запущена")
            self.live_attack_tick()
        else:
            self.live_attack_timer.stop()
            if hasattr(self, "live_attack_btn"):
                self.live_attack_btn.setText("LIVE SOC ATTACKS: OFF")
                self.live_attack_btn.setStyleSheet("background-color:#0f766e; color:white; font-weight:bold; padding:12px; border-radius:10px;")
            if hasattr(self, "attack_info"):
                self.attack_info.setText("LIVE SOC MODE ВИМКНЕНО\n\nАвтоматична генерація атак зупинена.")
            self.logger.log_info("LIVE SOC MODE OFF: автоматична генерація атак зупинена")

    def live_attack_tick(self):
        """Один крок live SOC: random attack -> sensors -> AI/risk/correlation -> map/timeline."""
        try:
            if not self.live_attack_mode:
                return

            self.live_attack_counter += 1
            attack = self.attack_engine.simulate_random_attack()

            # Для демонстрації кожна 3-тя атака робиться критичною OT/PLC подією.
            if self.live_attack_counter % 3 == 0:
                attack = self.attack_engine.simulate_plc_manipulation()
                attack["severity"] = "CRITICAL"

            # Step 13: cyber event is translated into real Digital Twin process impact.
            impacted_data = self.ai_soc_orchestrator.apply_attack_impact(
                self.sensors,
                attack,
                self.live_attack_counter
            )
            self.update_sensor_labels(impacted_data)

            # Не показуємо QMessageBox на кожній live-атаці.
            old_demo_flag = getattr(self, "demo_mode_running", False)
            self.demo_mode_running = True
            try:
                self.log_attack_event(attack)
            finally:
                self.demo_mode_running = old_demo_flag

            if hasattr(self, "attack_info"):
                self.attack_info.setText(
                    f"LIVE SOC EVENT #{self.live_attack_counter}\n\n"
                    f"Attack: {attack.get('attack_type')}\n"
                    f"Source: {attack.get('source_ip')} / {attack.get('source')}\n"
                    f"Target: {attack.get('target')}\n"
                    f"Severity: {attack.get('severity')}\n\n"
                    "AI/SIEM correlation, MITRE ICS mapping, risk scoring та Attack Map оновлено автоматично."
                )

            # Для вау-ефекту при critical + Auto Defense ON система сама реагує.
            if self.auto_defense_enabled and str(attack.get("severity", "")).upper() == "CRITICAL":
                self.activate_defense()

            if hasattr(self, "timeline_text"):
                self.load_timeline()
            if hasattr(self, "executive_label"):
                self.update_executive_dashboard()

        except Exception as exc:
            self.live_attack_timer.stop()
            self.live_attack_mode = False
            if hasattr(self, "live_attack_btn"):
                self.live_attack_btn.setText("LIVE SOC ATTACKS: ERROR")
                self.live_attack_btn.setStyleSheet("background-color:#dc2626; color:white; font-weight:bold; padding:12px; border-radius:10px;")
            msg = f"LIVE SOC error: {type(exc).__name__}: {exc}"
            try:
                self.logger.log_error(msg)
            except Exception:
                pass
            QMessageBox.critical(self, "LIVE SOC MODE", msg)

    def simulate_ddos_attack(self):
        if self.check_attack_permission():
            self.log_attack_event(self.attack_engine.simulate_ddos())
            self.audit("Attack Simulation", "DDoS Attack запущено", "OK")

    def simulate_modbus_attack(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_modbus_command_injection()
            self.update_sensor_labels(self.sensors.simulate_plc_attack())
            self.log_attack_event(attack)
            self.audit("Attack Simulation", "Modbus Injection запущено", "OK")

    def simulate_fake_sensor_attack(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_fake_sensor_data()
            self.update_sensor_labels(self.sensors.simulate_fake_sensor_attack())
            self.log_attack_event(attack)
            self.audit("Attack Simulation", "Fake Sensor Data запущено", "OK")

    def simulate_replay_attack(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_replay_attack()
            self.update_sensor_labels(self.sensors.generate_warning_data())
            self.log_attack_event(attack)
            self.audit("Attack Simulation", "Replay Attack запущено", "OK")

    def simulate_plc_attack(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_plc_manipulation()
            self.update_sensor_labels(self.sensors.simulate_plc_attack())
            self.log_attack_event(attack)
            self.audit("Attack Simulation", "PLC Manipulation запущено", "OK")

    def simulate_database_attack(self):
        if self.check_attack_permission():
            self.log_attack_event(self.attack_engine.simulate_database_attack())
            self.audit("Attack Simulation", "Database Attack запущено", "OK")

    def simulate_mitm_attack(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_mitm_attack()
            self.update_sensor_labels(self.sensors.generate_warning_data())
            self.log_attack_event(attack)
            self.audit("Attack Simulation", "MITM Attack запущено", "OK")

    def simulate_unauthorized_modbus_write(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_unauthorized_modbus_write()
            self.update_sensor_labels(self.sensors.simulate_plc_attack())
            self.log_attack_event(attack)
            self.audit("Attack Simulation", "Unauthorized Modbus Write запущено", "OK")

    def simulate_bruteforce_attack(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_brute_force_login()
            self.log_attack_event(attack)
            self.audit("Attack Simulation", "Brute Force SCADA Login запущено", "OK")

    def simulate_turbine_sabotage(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_turbine_sabotage_scenario()
            self.update_sensor_labels(self.sensors.simulate_plc_attack())
            self.log_attack_event(attack)
            self.audit("Attack Simulation", "Coordinated Turbine Sabotage запущено", "OK")

    def simulate_random_attack(self):
        if self.check_attack_permission():
            attack = self.attack_engine.simulate_random_attack()
            if attack.get("severity") == "CRITICAL" or "Modbus" in attack.get("attack_type", "") or "PLC" in attack.get("target_component", ""):
                self.update_sensor_labels(self.sensors.simulate_plc_attack())
            elif attack.get("attack_type") in ["Fake Sensor Data Injection", "MITM Attack", "Replay Attack"]:
                self.update_sensor_labels(self.sensors.generate_warning_data())
            self.log_attack_event(attack)
            self.audit("Attack Simulation", f"Random Attack Scenario: {attack.get('attack_type')}", "OK")

    # ---------- DEMO MODE ----------
    def init_demo_tab(self):
        layout = QVBoxLayout()
        title = QLabel("Demo Mode — повний сценарій захисту ТЕЦ")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #22d3ee;")

        self.demo_status_label = QLabel(
            "Готово до демонстрації. Натисни START FULL DEFENSE DEMO, щоб автоматично показати ланцюг:\n"
            "Normal telemetry → attack → AI detection → MITRE ICS → Risk scoring → SOAR → SAFE MODE → Report."
        )
        self.demo_status_label.setAlignment(Qt.AlignTop)
        self.demo_status_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #020617; padding: 22px; border: 1px solid #0ea5e9; border-radius: 12px;")

        self.demo_steps_label = QLabel("Очікування запуску demo-сценарію...")
        self.demo_steps_label.setAlignment(Qt.AlignTop)
        self.demo_steps_label.setStyleSheet("font-size: 15px; color: #a7f3d0; background-color: #020617; padding: 18px; border: 1px solid #22c55e; border-radius: 12px;")

        row = QHBoxLayout()
        start_btn = QPushButton("START FULL DEFENSE DEMO")
        start_btn.setStyleSheet("background-color:#dc2626; color:white; font-weight:bold; padding:14px; border-radius:10px;")
        start_btn.clicked.connect(self.start_full_attack_demo)
        reset_btn = QPushButton("Reset demo / plant")
        reset_btn.clicked.connect(self.reset_demo_mode)
        report_btn = QPushButton("Generate Final Incident Report")
        report_btn.clicked.connect(self.generate_incident_report)
        row.addWidget(start_btn); row.addWidget(reset_btn); row.addWidget(report_btn)

        layout.addWidget(title)
        layout.addWidget(self.demo_status_label)
        layout.addWidget(self.demo_steps_label)
        layout.addLayout(row)
        self.demo_tab.setLayout(layout)

    def _append_demo_step(self, text):
        self.demo_steps_log.append(text)
        if hasattr(self, "demo_steps_label"):
            self.demo_steps_label.setText("\n".join(self.demo_steps_log[-20:]))

    def start_full_defense_demo(self):
        """Final defense demo alias for diploma presentation."""
        return self.start_full_attack_demo()

    def start_full_attack_demo(self):
        """Безпечний demo-сценарій без падіння GUI.
        У попередній версії етапи запускались через QTimer.singleShot; якщо один з етапів
        кидав виняток, PyQt міг просто закрити програму. Тут увесь сценарій захищений try/except.
        """
        if not self.check_attack_permission():
            return
        try:
            self.demo_mode_running = True
            self.demo_steps_log = []
            self._append_demo_step("[1] DEMO START: нормальний режим ТЕЦ, збір телеметрії.")
            if hasattr(self, "demo_status_label"):
                self.demo_status_label.setText("DEMO RUNNING: виконується повний сценарій Attack → AI/SIEM → SOAR → Report.")
            QApplication.processEvents()

            if not self.auto_defense_enabled:
                self.toggle_auto_defense()
            self.update_sensor_labels(self.sensors.generate_normal_data())
            QApplication.processEvents()

            self._demo_stage_recon(run_next=False)
            QApplication.processEvents()
            self._demo_stage_plc_write(run_next=False)
            QApplication.processEvents()
            self._demo_stage_ai_correlation(run_next=False)
            QApplication.processEvents()
            self._demo_stage_soar(run_next=False)
            QApplication.processEvents()
            self._demo_stage_report(show_message=True)
        except Exception as exc:
            self.demo_mode_running = False
            msg = f"Demo Mode error: {type(exc).__name__}: {exc}"
            self._append_demo_step("[!] " + msg)
            try:
                self.logger.log_error(msg)
            except Exception:
                pass
            QMessageBox.critical(self, "Demo Mode crash prevented", msg)

    def _demo_stage_recon(self, run_next=True):
        self._append_demo_step("[2] Recon/Initial Access: підозрілий вузол готує доступ до engineering workstation.")
        attack = self.attack_engine.simulate_brute_force_login()
        attack["severity"] = "MEDIUM"
        self.log_attack_event(attack)
        if run_next:
            QTimer.singleShot(1100, self._demo_stage_plc_write)

    def _demo_stage_plc_write(self, run_next=True):
        self._append_demo_step("[3] PLC Manipulation: несанкціонована зміна логіки PLC / Modbus write.")
        self.update_sensor_labels(self.sensors.simulate_plc_attack())
        attack = self.attack_engine.simulate_plc_manipulation()
        self.log_attack_event(attack)
        if run_next:
            QTimer.singleShot(1100, self._demo_stage_ai_correlation)

    def _demo_stage_ai_correlation(self, run_next=True):
        self._append_demo_step("[4] AI + Digital Twin: виявлено відхилення фізичних параметрів від очікуваної моделі.")
        if self.current_sensor_data:
            self.run_ai_analysis(self.current_sensor_data)
        # HOTFIX: у цій версії метод називається update_charts(), а не update_live_charts().
        # Перевірка через hasattr не дає Demo Mode падати після AI/Digital Twin етапу.
        if hasattr(self, "update_charts"):
            self.update_charts()
        self.load_timeline()
        if run_next:
            QTimer.singleShot(1100, self._demo_stage_soar)

    def _demo_stage_soar(self, run_next=True):
        self._append_demo_step("[5] SOAR: автоматично активовано SAFE MODE, ізольовано PLC, знижено навантаження.")
        self.activate_defense()
        self.update_system_status_panel()
        self.update_executive_dashboard()
        if run_next:
            QTimer.singleShot(1100, self._demo_stage_report)

    def _demo_stage_report(self, show_message=False):
        self._append_demo_step("[6] Reporting: сформовано артефакти інциденту для керівництва та SOC-аналітика.")
        try:
            if self.current_sensor_data:
                ai = self.ai_engine.analyze(self.current_sensor_data)
                path = self.report_generator.generate_report(
                    self.current_sensor_data, ai, self.last_attack, self.defense_engine,
                    self.last_risk_result, self.last_incident, timeline=self.attack_timeline_history,
                    soar_actions=self.soar_actions_history, live_analytics=self.last_live_analytics
                )
                self._append_demo_step(f"[7] REPORT READY: {path}")
                self.logger.log_info(f"Demo Mode сформував звіт: {path}")
        except Exception as exc:
            self._append_demo_step(f"[!] Report generation warning: {exc}")
        self.demo_mode_running = False
        self.demo_status_label.setText("DEMO COMPLETE: показано повний цикл Attack → AI/SIEM → SOAR → Report.")
        if show_message:
            QMessageBox.information(self, "Demo Mode", "Повний demo-сценарій завершено. Перевір вкладки SCADA Dashboard, Attack Map, Event Timeline, Defense Center, Executive Dashboard і reports.")

    def reset_demo_mode(self):
        self.demo_mode_running = False
        self.demo_steps_log = []
        self.reset_plant()
        self.reset_defense()
        if hasattr(self, "demo_status_label"):
            self.demo_status_label.setText("Demo reset: об’єкт повернуто у штатний режим.")
        if hasattr(self, "demo_steps_label"):
            self.demo_steps_label.setText("Очікування запуску demo-сценарію...")

    # ---------- SHORT TABS ----------
    def make_text_tab(self, tab, title_text, body_text):
        layout = QVBoxLayout()
        title = QLabel(title_text)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        body = QLabel(body_text)
        body.setAlignment(Qt.AlignTop)
        body.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        layout.addWidget(title)
        layout.addWidget(body)
        tab.setLayout(layout)
        return body

    def init_summary_tab(self):
        layout = QVBoxLayout()
        title = QLabel("Summary Dashboard — загальна статистика системи")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.summary_label = QLabel("Очікування статистики...")
        self.summary_label.setAlignment(Qt.AlignTop)
        self.summary_label.setStyleSheet("font-size: 18px; color: #e5e7eb; background-color: #111827; padding: 25px; border-radius: 12px;")
        btn = QPushButton("Оновити статистику")
        btn.clicked.connect(self.update_summary_dashboard)
        layout.addWidget(title); layout.addWidget(self.summary_label); layout.addWidget(btn)
        self.summary_tab.setLayout(layout)
        self.update_summary_dashboard()

    def update_summary_dashboard(self):
        stats = get_system_statistics()
        ai_text = "AI ще не виконував аналіз"
        if self.current_sensor_data:
            ai = self.ai_engine.analyze(self.current_sensor_data)
            ai_text = f"AI Threat Level: {ai['threat_level']}\nAI Score: {ai['score']} / 100\nAI Confidence: {ai['confidence']} %"
        self.summary_label.setText(f"ЗАГАЛЬНА СТАТИСТИКА\n\nЗаписів датчиків у базі: {stats['sensor_count']}\nЗареєстрованих атак: {stats['attack_count']}\nДій захисту: {stats['defense_count']}\nКритичних/небезпечних подій: {stats['critical_events']}\nОстанній технологічний статус: {stats['last_status']}\n\n{ai_text}\n\nAuto Defense: {'ON' if self.auto_defense_enabled else 'OFF'}\nSafe Mode: {self.defense_engine.safe_mode}\nPLC ізольовано: {self.defense_engine.isolated_plc}\nЗаблоковані IP: {', '.join(self.defense_engine.blocked_ips) if self.defense_engine.blocked_ips else 'немає'}")

    def init_executive_tab(self):
        layout = QVBoxLayout()
        title = QLabel("Executive Dashboard — керівницький огляд кіберстійкості ТЕЦ")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.executive_label = QLabel("Очікування даних...")
        self.executive_label.setAlignment(Qt.AlignTop)
        self.executive_label.setWordWrap(True)
        self.executive_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #020617; border: 1px solid #164e63; padding: 22px; border-radius: 14px;")
        btn_row = QHBoxLayout()
        b1 = QPushButton("Оновити Executive Dashboard")
        b1.clicked.connect(self.update_executive_dashboard)
        b2 = QPushButton("Сформувати Incident Report")
        b2.clicked.connect(self.generate_incident_report)
        btn_row.addWidget(b1)
        btn_row.addWidget(b2)
        layout.addWidget(title)
        layout.addWidget(self.executive_label)
        layout.addLayout(btn_row)
        self.executive_tab.setLayout(layout)
        self.update_executive_dashboard()

    def update_executive_dashboard(self):
        attacks = get_attack_records()
        defenses = get_defense_records()
        total_attacks = len(attacks)
        total_defenses = len(defenses)
        critical_count = 0
        for row in attacks:
            txt = " ".join([str(x) for x in row]).upper()
            if "CRITICAL" in txt or "HIGH" in txt:
                critical_count += 1
        ai_efficiency = 0
        if total_attacks:
            ai_efficiency = min(100, int((len(self.attack_timeline_history) / max(1, total_attacks)) * 100))
        last_attack = self.last_attack or {}
        last_risk = self.last_risk_result or {}
        last_incident = self.last_incident or {}
        defense_state = "ON" if self.auto_defense_enabled else "OFF"
        safe = "ACTIVE" if self.defense_engine.safe_mode else "STANDBY"
        plc = "ISOLATED" if self.defense_engine.isolated_plc else "CONNECTED"
        blocked_ips = ", ".join(self.defense_engine.blocked_ips) if self.defense_engine.blocked_ips else "немає"
        self.executive_label.setText(
            "EXECUTIVE CYBER RESILIENCE OVERVIEW\n\n"
            f"Загальна кількість атак: {total_attacks}\n"
            f"Критичні/високі події: {critical_count}\n"
            f"Дій захисту/SOAR: {total_defenses}\n"
            f"AI/SOC coverage: {ai_efficiency}%\n\n"
            "ПОТОЧНИЙ СТАН\n"
            f"Auto Defense: {defense_state}\n"
            f"SAFE MODE: {safe}\n"
            f"PLC: {plc}\n"
            f"Заблоковані IP: {blocked_ips}\n\n"
            "ОСТАННІЙ ІНЦИДЕНТ\n"
            f"Тип атаки: {last_attack.get('attack_type', 'немає')}\n"
            f"Джерело: {last_attack.get('source_ip', 'N/A')} → {last_attack.get('target', 'N/A')}\n"
            f"Risk: {last_risk.get('risk_level', 'N/A')} / {last_risk.get('risk_score', 'N/A')}\n"
            f"Incident: {last_incident.get('incident_level', 'N/A')} / {last_incident.get('incident_score', 'N/A')}\n\n"
            "КЛЮЧОВИЙ ВИСНОВОК ДЛЯ КЕРІВНИЦТВА\n"
            "Платформа забезпечує моніторинг OT/ICS, AI-виявлення аномалій, "
            "SIEM-кореляцію подій та SOAR-реагування для зменшення кіберфізичного ризику ТЕЦ."
        )

    def init_digital_twin_tab(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(12)
        title = QLabel("Digital Twin ТЕЦ — цифрова модель технологічного процесу")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #38bdf8; padding: 8px;")
        self.digital_twin_mimic = MimicPanel()
        self.digital_twin_mimic.setMinimumHeight(300)
        self.digital_twin_mimic.setMaximumHeight(330)
        grid = QGridLayout()
        grid.setSpacing(10)
        self.dt_temperature = self.create_sensor_card("Температура пари", "— °C")
        self.dt_pressure = self.create_sensor_card("Тиск", "— МПа")
        self.dt_rpm = self.create_sensor_card("Оберти турбіни", "— RPM")
        self.dt_power = self.create_sensor_card("Генерація", "— MW")
        self.dt_vibration = self.create_sensor_card("Вібрація", "— mm/s")
        self.dt_water = self.create_sensor_card("Рівень води", "— %")
        for i, card in enumerate([self.dt_temperature, self.dt_pressure, self.dt_rpm, self.dt_power, self.dt_vibration, self.dt_water]):
            grid.addWidget(card, i // 3, i % 3)
        desc = QLabel("Digital Twin моделює фізичний стан ТЕЦ: температуру, тиск, оберти турбіни, генерацію, вібрацію, рівень води, аварійні та аномальні режими.")
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet("font-size: 15px; color: #cbd5e1; padding: 8px;")
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.create_button("Симуляція відмови охолодження", self.simulate_cooling_failure, "#dc2626"))
        row.addWidget(self.create_button("Симуляція перевантаження ТЕЦ", self.simulate_overload, "#ea580c"))
        row.addWidget(self.create_button("Повернути NORMAL MODE", self.update_normal_data, "#2563eb"))
        layout.addWidget(title)
        layout.addWidget(self.digital_twin_mimic)
        layout.addLayout(grid)
        layout.addWidget(desc)
        layout.addLayout(row)
        self.digital_twin_tab.setLayout(layout)

    def simulate_cooling_failure(self):
        self.mark_activity(); self.update_sensor_labels(self.sensors.simulate_cooling_failure()); self.logger.log_critical("Digital Twin: відмова системи охолодження"); self.load_logs()

    def simulate_overload(self):
        self.mark_activity(); self.update_sensor_labels(self.sensors.simulate_overload()); self.logger.log_critical("Digital Twin: перевантаження ТЕЦ"); self.load_logs()

    def init_attack_map_tab(self):
        layout = QVBoxLayout()
        title = QLabel("Attack Map + Propagation — карта та ланцюг атаки")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #ef4444;")
        self.attack_route_label = QLabel("SCADA Facility: Kyiv / Ukraine → очікування атаки")
        self.attack_route_label.setAlignment(Qt.AlignCenter)
        self.attack_route_label.setStyleSheet("font-size: 20px; color: #facc15;")
        self.attack_map_label = QLabel("Карта очікує першу атаку...")
        self.attack_map_label.setAlignment(Qt.AlignTop)
        self.attack_map_label.setWordWrap(True)
        self.attack_map_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #020617; padding: 20px; border: 1px solid #38bdf8; border-radius: 12px;")
        self.propagation_label = QLabel("Propagation Chain: IDLE")
        self.propagation_label.setAlignment(Qt.AlignCenter)
        self.propagation_label.setWordWrap(True)
        self.propagation_label.setStyleSheet("font-size: 17px; color: #22c55e; background-color: #111827; padding: 16px; border: 1px solid #334155; border-radius: 12px;")
        btn = QPushButton("Відкрити HTML-карту атак")
        btn.clicked.connect(self.open_attack_map)
        layout.addWidget(title)
        layout.addWidget(self.attack_route_label)
        layout.addWidget(self.attack_map_label, 2)
        layout.addWidget(self.propagation_label)
        layout.addWidget(btn)
        self.attack_map_tab.setLayout(layout)

    def open_attack_map(self):
        attacks = []
        if self.last_attack:
            attacks.append(self.last_attack)
        path = self.map_generator.generate_map(attacks)
        webbrowser.open(os.path.abspath(path))

    def update_attack_map(self, attack):
        country = attack.get("country", "Unknown")
        city = attack.get("city", "Unknown")
        severity = attack.get("severity", "HIGH")
        mitre = self.last_mitre_result or self.mitre_mapper.map_attack(attack.get("attack_type", "Unknown"))
        color = {"LOW": "#22c55e", "MEDIUM": "#facc15", "HIGH": "#fb923c", "CRITICAL": "#ef4444"}.get(severity, "#38bdf8")
        route = f"{city}, {country} → Kyiv, Ukraine / ТЕЦ SCADA"
        self.attack_route_label.setText(route)
        self.attack_route_label.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {color};")
        indicators = ", ".join(attack.get("network_indicators", [])) or "немає"
        self.attack_map_label.setText(
            f"<b style='color:{color};'>LIVE ATTACK ROUTE</b><br><br>"
            f"🌍 Джерело: <b>{city}, {country}</b><br>"
            f"🔢 IP: <b>{attack['source_ip']}</b><br>"
            f"🎯 Ціль: <b>{attack['target']}</b><br>"
            f"⚠️ Тип: <b>{attack['attack_type']}</b><br>"
            f"🔥 Severity: <b>{severity}</b><br>"
            f"🧭 MITRE ICS: <b>{mitre.get('technique_id', 'N/A')} — {mitre.get('technique', 'N/A')}</b><br>"
            f"📡 Індикатори: {indicators}<br><br>"
            f"<b>Опис:</b> {attack['description']}<br>"
            f"<b>Вплив:</b> {attack['impact']}<br><br>"
            f"<b>Маршрут:</b> {route}"
        )
        self.update_propagation_chain(attack)
        self.map_generator.generate_map([attack])

    def update_propagation_chain(self, attack):
        attack_type = attack.get("attack_type", "ATTACK") if attack else "ATTACK"
        chains = {
            "DDoS": ["Internet", "Firewall", "SCADA Server", "Operator HMI"],
            "PLC Manipulation": ["Attacker", "Engineering Workstation", "PLC Logic", "Turbine", "Generator"],
            "Unauthorized Modbus Write": ["Attacker", "Modbus TCP", "PLC Register", "Actuator", "Process"],
            "Fake Sensor Data": ["Attacker", "Sensor Channel", "SCADA HMI", "AI Digital Twin"],
            "Coordinated Turbine Sabotage": ["Attacker", "SCADA", "PLC", "Turbine", "Generator", "Safety System"],
        }
        chain = chains.get(attack_type, ["Attacker", "Network", "SCADA", "PLC", "Process"])
        rendered = "  ➜  ".join(chain)
        self.attack_propagation_stage = rendered
        if hasattr(self, "propagation_label"):
            self.propagation_label.setText(f"Propagation Chain: {rendered}")
            self.propagation_label.setStyleSheet("font-size: 17px; font-weight: bold; color: #facc15; background-color: #111827; padding: 16px; border: 1px solid #facc15; border-radius: 12px;")

    def init_topology_tab(self):
        layout = QVBoxLayout(); title = QLabel("Network Topology — архітектура OT/ICS мережі"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.topology_panel = NetworkTopologyPanel(); btn = QPushButton("Оновити топологію"); btn.clicked.connect(self.update_topology)
        layout.addWidget(title); layout.addWidget(self.topology_panel); layout.addWidget(btn); self.topology_tab.setLayout(layout); self.update_topology()

    def update_topology(self):
        if hasattr(self, "topology_panel"):
            ai_level = "LOW"
            if hasattr(self, "ai_threat_label"):
                ai_level = self.ai_threat_label.value_label.text()
            self.topology_panel.update_state(
                attack=self.last_attack,
                firewall_blocked=self.last_firewall_blocked,
                ai_result={"threat_level": ai_level}
            )

    def init_firewall_tab(self):
        layout = QVBoxLayout(); title = QLabel("Firewall / IPS Center — захист мережевого периметра"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #22c55e;")
        self.firewall_status_label = QLabel("Firewall очікує події..."); self.firewall_status_label.setAlignment(Qt.AlignTop); self.firewall_status_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        b1 = QPushButton("Увімкнути / вимкнути Firewall"); b1.clicked.connect(self.toggle_firewall)
        b2 = QPushButton("Очистити заблоковані IP"); b2.clicked.connect(self.reset_firewall_blocks)
        b3 = QPushButton("Оновити Firewall"); b3.clicked.connect(self.update_firewall_status)
        layout.addWidget(title); layout.addWidget(self.firewall_status_label); layout.addWidget(b1); layout.addWidget(b2); layout.addWidget(b3); self.firewall_tab.setLayout(layout); self.update_firewall_status()

    def update_firewall_status(self):
        status = "ON" if self.firewall_engine.enabled else "OFF"; blocked = "\n".join(self.firewall_engine.blocked_ips) if self.firewall_engine.blocked_ips else "немає"
        self.firewall_status_label.setText(f"Firewall status: {status}\n\nОстання подія:\n{self.firewall_engine.last_event}\n\nЗаблоковані IP:\n{blocked}")

    def toggle_firewall(self):
        self.mark_activity()
        if self.role != "Admin": QMessageBox.warning(self, "Обмеження доступу", "Керувати Firewall може лише Admin."); return
        enabled = self.firewall_engine.toggle_firewall(); self.logger.log_info(f"Firewall {'увімкнено' if enabled else 'вимкнено'}"); self.audit("Firewall", f"Firewall {'ON' if enabled else 'OFF'}", "OK"); self.update_firewall_status(); self.load_logs()

    def reset_firewall_blocks(self):
        self.mark_activity()
        if self.role != "Admin": QMessageBox.warning(self, "Обмеження доступу", "Очищати Firewall blocklist може лише Admin."); return
        self.firewall_engine.reset_blocks(); self.logger.log_info("Firewall blocklist очищено"); self.audit("Firewall", "Очищено список заблокованих IP", "OK"); self.update_firewall_status(); self.load_logs()

    def init_traffic_tab(self):
        layout = QVBoxLayout(); title = QLabel("Traffic Monitor — моніторинг OT/ICS трафіку"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.traffic_table = QTableWidget(); self.traffic_table.setColumnCount(6); self.traffic_table.setHorizontalHeaderLabels(["Час", "IP джерела", "Ціль", "Протокол", "Дія", "Статус"])
        b1 = QPushButton("Згенерувати нормальний трафік"); b1.clicked.connect(self.generate_normal_traffic)
        b2 = QPushButton("Оновити трафік"); b2.clicked.connect(self.load_traffic)
        layout.addWidget(title); layout.addWidget(self.traffic_table); layout.addWidget(b1); layout.addWidget(b2); self.traffic_tab.setLayout(layout); self.load_traffic()

    def generate_normal_traffic(self):
        self.mark_activity(); event = self.traffic_monitor.generate_normal_traffic(); self.logger.log_info(f"Traffic Monitor: {event['protocol']} {event['source_ip']} → {event['target']} / {event['status']}"); self.audit("Traffic Monitor", "Згенеровано нормальний OT/ICS трафік", "OK"); self.load_traffic(); self.load_logs()

    def load_traffic(self):
        events = self.traffic_monitor.get_events(); self.traffic_table.setRowCount(len(events))
        for r, e in enumerate(events):
            for c, v in enumerate([e["time"], e["source_ip"], e["target"], e["protocol"], e["action"], e["status"]]): self.traffic_table.setItem(r, c, QTableWidgetItem(str(v)))
        self.traffic_table.resizeColumnsToContents()

    def init_threat_intel_tab(self): self.threat_intel_label = self.make_text_tab(self.threat_intel_tab, "Threat Intelligence Center", "Очікування атаки для аналізу...")
    def update_threat_intel_panel(self):
        if not self.last_threat_intel_result: self.threat_intel_label.setText("Threat Intelligence очікує першу атаку."); return
        r = self.last_threat_intel_result
        apt = r.get("apt_similarity", {})
        apt_text = ""
        if apt:
            apt_text = f"\n\nCTI / APT similarity:\nНайближчий профіль: {apt.get('name')}\nСхожість: {apt.get('score')} %\nОпис: {apt.get('description')}"
        self.threat_intel_label.setText(f"IP: {r['source_ip']}\nТип атаки: {r['attack_type']}\nФінальний ризик: {r['final_risk']}\nRisk score: {r.get('risk_score', 0)}\nIP у blacklist: {r['ip_listed']}\nОпис IP: {r['ip_description']}\nКритичний тип атаки: {r['attack_suspicious']}\nОпис: {r['attack_description']}\nРекомендація: {r.get('recommendation', '')}{apt_text}")
    def init_mitre_tab(self): self.mitre_label = self.make_text_tab(self.mitre_tab, "MITRE ATT&CK for ICS", "Очікування атаки для MITRE-класифікації...")
    def update_mitre_panel(self):
        if not self.last_attack or not self.last_mitre_result: self.mitre_label.setText("MITRE ICS очікує першу атаку."); return
        self.mitre_label.setText(f"Тип атаки: {self.last_attack['attack_type']}\nЦіль: {self.last_attack['target']}\nIP: {self.last_attack['source_ip']}\n\nТактика: {self.last_mitre_result['tactic']}\nТехніка: {self.last_mitre_result['technique']}\n\nОпис:\n{self.last_mitre_result['description']}")

    def init_risk_tab(self):
        layout = QVBoxLayout(); title = QLabel("Risk Scoring Center — інтегральна оцінка ризику"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #facc15;")
        self.risk_label = QLabel("Очікування даних для оцінки ризику..."); self.risk_label.setAlignment(Qt.AlignTop); self.risk_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        btn = QPushButton("Розрахувати ризик"); btn.clicked.connect(self.calculate_risk)
        layout.addWidget(title); layout.addWidget(self.risk_label); layout.addWidget(btn); self.risk_tab.setLayout(layout)

    def calculate_risk(self, silent=False):
        if not self.current_sensor_data:
            if not silent: QMessageBox.warning(self, "Risk Scoring", "Немає поточних даних.")
            return
        ai = self.ai_engine.analyze(self.current_sensor_data)
        self.last_risk_result = self.risk_engine.calculate_risk(self.current_sensor_data, ai, self.last_attack, self.last_threat_intel_result, self.last_mitre_result, self.last_firewall_blocked)
        add_risk_record(self.last_risk_result)
        factors = "\n".join([f"- {x}" for x in self.last_risk_result["factors"]])
        self.risk_label.setText(f"RISK SCORING RESULT\n\nRisk Level: {self.last_risk_result['risk_level']}\nRisk Score: {self.last_risk_result['risk_score']} / 100\n\nФактори ризику:\n{factors}")
        if not silent:
            self.add_notification("Risk Scoring", f"Risk Level: {self.last_risk_result['risk_level']} / Score: {self.last_risk_result['risk_score']}", self.last_risk_result["risk_level"])
            self.logger.log_info(f"Risk Scoring виконано: {self.last_risk_result['risk_level']} ({self.last_risk_result['risk_score']}/100)")
            self.audit("Risk Scoring", "Розраховано інтегральний ризик", "OK"); self.load_logs()

    def init_correlation_tab(self):
        layout = QVBoxLayout(); title = QLabel("Incident Correlation — кореляція подій SCADA/SOC"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.correlation_label = QLabel("Очікування даних для кореляції..."); self.correlation_label.setAlignment(Qt.AlignTop); self.correlation_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        btn = QPushButton("Виконати кореляцію інциденту"); btn.clicked.connect(self.correlate_incident)
        layout.addWidget(title); layout.addWidget(self.correlation_label); layout.addWidget(btn); self.correlation_tab.setLayout(layout)

    def correlate_incident(self):
        self.mark_activity()
        if not self.current_sensor_data: QMessageBox.warning(self, "Correlation", "Немає поточних даних."); return
        ai = self.ai_engine.analyze(self.current_sensor_data)
        self.last_incident = self.correlation_engine.correlate(self.current_sensor_data, ai, self.last_attack, self.last_threat_intel_result, self.last_risk_result, self.defense_engine)
        add_correlated_incident(self.last_incident)
        findings = "\n".join([f"- {x}" for x in self.last_incident["findings"]])
        self.correlation_label.setText(f"CORRELATED INCIDENT\n\nЧас: {self.last_incident['time']}\nIncident Level: {self.last_incident['incident_level']}\nIncident Score: {self.last_incident['incident_score']} / 100\n\nОзнаки:\n{findings}")
        self.logger.log_warning(f"Incident Correlation: {self.last_incident['incident_level']} ({self.last_incident['incident_score']}/100)")
        self.audit("Correlation", "Виконано кореляцію інциденту", "OK"); self.load_logs()

    def init_notifications_tab(self):
        layout = QVBoxLayout(); title = QLabel("Notification Center — сповіщення системи"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.notifications_table = QTableWidget(); self.notifications_table.setColumnCount(4); self.notifications_table.setHorizontalHeaderLabels(["Час", "Рівень", "Заголовок", "Повідомлення"])
        b1 = QPushButton("Оновити сповіщення"); b1.clicked.connect(self.load_notifications)
        b2 = QPushButton("Очистити сповіщення"); b2.clicked.connect(self.clear_notifications)
        layout.addWidget(title); layout.addWidget(self.notifications_table); layout.addWidget(b1); layout.addWidget(b2); self.notifications_tab.setLayout(layout); self.load_notifications()

    def add_notification(self, title, message, level="INFO"):
        n = self.notification_center.add_notification(title, message, level)
        if n is None: return
        add_notification_record(n)
        if hasattr(self, "notifications_table"): self.load_notifications()

    def load_notifications(self):
        rows = get_notification_records(); self.notifications_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, v in enumerate(row): self.notifications_table.setItem(r, c, QTableWidgetItem(str(v)))
        self.notifications_table.resizeColumnsToContents()

    def clear_notifications(self):
        self.mark_activity()
        if self.role != "Admin": QMessageBox.warning(self, "Обмеження доступу", "Очищати історію сповіщень може лише Admin."); return
        self.notification_center.clear_notifications(); clear_notification_records(); self.logger.log_info("Admin очистив історію сповіщень"); self.audit("Notifications", "Очищено історію сповіщень", "OK"); self.load_notifications(); self.load_logs(); QMessageBox.information(self, "Notifications", "Історію сповіщень очищено.")

    def evaluate_alerts(self, data):
        ai = self.ai_engine.analyze(data); alerts = self.alert_rules.evaluate(data, ai, self.last_risk_result)
        for title, message, level in alerts:
            self.add_notification(title, message, level); self.logger.log_warning(f"ALERT: {title} — {message}")

    def init_ai_tab(self):
        layout = QVBoxLayout(); title = QLabel("AI Analysis Center — аналіз загроз"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.ai_result_label = QLabel("AI очікує дані для аналізу..."); self.ai_result_label.setAlignment(Qt.AlignTop); self.ai_result_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        btn = QPushButton("Виконати AI-аналіз поточного стану"); btn.clicked.connect(self.manual_ai_analysis)
        layout.addWidget(title); layout.addWidget(self.ai_result_label); layout.addWidget(btn); self.ai_tab.setLayout(layout)

    def manual_ai_analysis(self):
        self.mark_activity()
        if not self.current_sensor_data: QMessageBox.warning(self, "AI Analysis", "Ще немає даних датчиків для аналізу."); return
        self.show_ai_result(self.ai_engine.analyze(self.current_sensor_data))

    def run_ai_analysis(self, data):
        result = self.ai_engine.analyze(data)
        ml = self.ml_predictor.predict(data)
        self.last_ml_prediction = ml["prediction"] if ml["success"] else "MODEL_NOT_TRAINED"
        self.last_ml_confidence = ml.get("confidence", 0) if ml.get("success") else 0
        self.last_live_analytics = self.live_analytics.analyze(data, result, ml, self.last_attack)

        self.ai_threat_label.value_label.setText(result["threat_level"])
        self.ai_confidence_label.value_label.setText(f"{result['confidence']} %")
        ml_text = self.last_ml_prediction if not self.last_ml_confidence else f"{self.last_ml_prediction} ({self.last_ml_confidence}%)"
        self.ml_prediction_label.value_label.setText(ml_text)

        color = {"LOW": "#22c55e", "MEDIUM": "#facc15", "HIGH": "#fb923c", "CRITICAL": "#ef4444"}.get(result["threat_level"], "#ef4444")
        twin_color = {"LOW": "#22c55e", "MEDIUM": "#facc15", "HIGH": "#fb923c", "CRITICAL": "#ef4444"}.get(self.last_live_analytics.get("twin_status", "LOW"), color)
        self.ai_threat_label.value_label.setStyleSheet(f"font-size: 26px; font-weight: bold; color: {color};")
        self.ai_confidence_label.value_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
        self.ml_prediction_label.value_label.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {twin_color};")

        if hasattr(self, "ai_result_label"):
            self.show_ai_result(result)
        if hasattr(self, "live_analytics_label"):
            self.update_live_analytics_panel()
        if hasattr(self, "update_soc_panel"):
            self.update_soc_panel("AI_ANALYSIS", result.get("threat_level", "INFO"), result)
        if self.auto_defense_enabled and not self._auto_defense_in_progress and (result["threat_level"] in ["HIGH", "CRITICAL"] or self.last_live_analytics.get("twin_status") in ["HIGH", "CRITICAL"]):
            self._auto_defense_in_progress = True
            try:
                defense = self.defense_engine.activate_defense(result, self.last_attack); add_defense_record(defense)
                if hasattr(self, "defense_status_label"): self.show_defense_result(defense)
                if defense["safe_mode"] and data.get("system_status") != "SAFE_MODE": self.update_sensor_labels(self.sensors.apply_safe_mode())
                self.logger.log_defense("AUTO DEFENSE TRIGGERED: " + "; ".join(defense["actions"])); self.load_logs()
            finally:
                self._auto_defense_in_progress = False

    def show_ai_result(self, result):
        reasons = "\n".join([f"- {x}" for x in result["reasons"]])
        twin_text = ""
        if self.last_live_analytics:
            twin_reasons = "\n".join([f"- {x}" for x in self.last_live_analytics["reasons"]])
            twin_text = (
                f"\n\nDIGITAL TWIN ANALYTICS:\n"
                f"Twin Status: {self.last_live_analytics['twin_status']}\n"
                f"Anomaly Score: {self.last_live_analytics['anomaly_score']} / 100\n"
                f"Expected RPM: {self.last_live_analytics['expected_rpm']} | Delta: {self.last_live_analytics['rpm_delta']}\n"
                f"Expected Pressure: {self.last_live_analytics['expected_pressure']} | Delta: {self.last_live_analytics['pressure_delta']}\n"
                f"Причини Digital Twin:\n{twin_reasons}\n"
                f"Рекомендація Twin/SOAR: {self.last_live_analytics['recommendation']}"
            )
        self.ai_result_label.setText(
            f"Рівень загрози: {result['threat_level']}\n"
            f"AI Score: {result['score']} / 100\n"
            f"AI Confidence: {result['confidence']} %\n"
            f"ML Prediction: {self.last_ml_prediction} | ML Confidence: {self.last_ml_confidence} %\n\n"
            f"Причини рішення AI:\n{reasons}\n\n"
            f"Рекомендація:\n{result['recommendation']}" + twin_text
        )

    def update_live_analytics_panel(self):
        if not self.last_live_analytics:
            return
        a = self.last_live_analytics
        reasons = "\n".join([f"• {x}" for x in a["reasons"][:5]])
        rolling = a.get("rolling", {})
        self.live_analytics_label.setText(
            f"LIVE AI / DIGITAL TWIN ANALYTICS\n\n"
            f"Twin Status: {a['twin_status']}\n"
            f"Anomaly Score: {a['anomaly_score']} / 100\n"
            f"Expected RPM: {a['expected_rpm']} | Actual: {self.current_sensor_data.get('turbine_rpm') if self.current_sensor_data else '—'} | Δ {a['rpm_delta']}\n"
            f"Expected Pressure: {a['expected_pressure']} | Actual: {self.current_sensor_data.get('pressure') if self.current_sensor_data else '—'} | Δ {a['pressure_delta']}\n"
            f"Rolling avg RPM: {rolling.get('rpm_avg', '—')}\n"
            f"Rolling avg Vibration: {rolling.get('vibration_avg', '—')}\n"
            f"Rolling avg Anomaly: {rolling.get('anomaly_avg', '—')}\n\n"
            f"Пояснення:\n{reasons}\n\n"
            f"SOAR Recommendation:\n{a['recommendation']}"
        )

    def init_defense_tab(self):
        layout = QVBoxLayout(); title = QLabel("Defense Center — автоматичний захист SCADA/OT"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #22c55e;")
        self.defense_status_label = QLabel("Захист очікує активації..."); self.defense_status_label.setAlignment(Qt.AlignTop); self.defense_status_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        row = QHBoxLayout(); b1 = QPushButton("Активувати захист"); b1.clicked.connect(self.activate_defense); b2 = QPushButton("AI Auto Defense"); b2.clicked.connect(self.ai_auto_defense); b3 = QPushButton("Скинути захист"); b3.clicked.connect(self.reset_defense)
        row.addWidget(b1); row.addWidget(b2); row.addWidget(b3); layout.addWidget(title); layout.addWidget(self.defense_status_label); layout.addLayout(row); self.defense_tab.setLayout(layout)

    def activate_defense(self):
        self.mark_activity()
        if not self.current_sensor_data: QMessageBox.warning(self, "Defense Center", "Немає поточних даних для аналізу."); return
        ai = self.ai_engine.analyze(self.current_sensor_data); ml = self.ml_predictor.predict(self.current_sensor_data); self.last_ml_prediction = ml["prediction"] if ml["success"] else "MODEL_NOT_TRAINED"
        defense = self.defense_engine.activate_defense(ai, self.last_attack); add_defense_record(defense); self.audit("Defense Center", "Захист активовано", "OK"); self.add_notification("Захист активовано", "Defense Engine виконав захисні дії.", "MEDIUM"); self.show_defense_result(defense)
        if defense["safe_mode"]: self.update_sensor_labels(self.sensors.apply_safe_mode())
        self.logger.log_defense("Активовано захисні дії: " + "; ".join(defense["actions"])); self.load_logs(); self.update_topology()

    def ai_auto_defense(self):
        self.mark_activity()
        if not self.current_sensor_data: QMessageBox.warning(self, "AI Auto Defense", "Немає поточних даних для аналізу."); return
        ai = self.ai_engine.analyze(self.current_sensor_data)
        if ai["threat_level"] in ["HIGH", "CRITICAL"]: self.activate_defense()
        else: self.defense_status_label.setText(f"AI Auto Defense не активовано.\nПоточний рівень загрози: {ai['threat_level']}\nАктивне втручання не потрібне.")

    def reset_defense(self):
        self.mark_activity(); defense = self.defense_engine.reset_defense(); add_defense_record(defense); self.show_defense_result(defense); self.logger.log_defense("Захист повернуто у штатний режим"); self.audit("Defense Center", "Захист скинуто", "OK"); self.load_logs(); self.update_topology()

    def show_defense_result(self, defense):
        actions = "\n".join([f"- {x}" for x in defense["actions"]]); blocked = ", ".join(defense["blocked_ips"]) if defense["blocked_ips"] else "немає"
        self.defense_status_label.setText(f"Час: {defense['time']}\n\nSAFE MODE: {defense['safe_mode']}\nPLC ізольовано: {defense['isolated_plc']}\nНавантаження знижено: {defense['load_reduced']}\nЗаблоковані IP: {blocked}\n\nДії системи захисту:\n{actions}")

    def toggle_auto_defense(self):
        self.mark_activity()
        self.auto_defense_enabled = not self.auto_defense_enabled
        if self.auto_defense_enabled:
            self.auto_defense_btn.setText("Auto Defense: ON")
            self.auto_defense_btn.setStyleSheet("""
                QPushButton { background-color: #16a34a; border: 1px solid #86efac; border-radius: 10px; color: white; font-weight: bold; min-height: 34px; font-size: 13px; padding: 6px; }
                QPushButton:hover { background-color: #22c55e; border: 2px solid #bbf7d0; }
            """)
            self.logger.log_info("AI Auto Defense увімкнено")
        else:
            self.auto_defense_btn.setText("Auto Defense: OFF")
            self.auto_defense_btn.setStyleSheet("""
                QPushButton { background-color: #2563eb; border: 1px solid #38bdf8; border-radius: 10px; color: white; font-weight: bold; min-height: 34px; font-size: 13px; padding: 6px; }
                QPushButton:hover { background-color: #0ea5e9; border: 2px solid #67e8f9; }
            """)
            self.logger.log_info("AI Auto Defense вимкнено")
        if hasattr(self, "update_soc_panel"):
            self.update_soc_panel("AUTO_DEFENSE", "ON" if self.auto_defense_enabled else "OFF")
        self.load_logs()

    def init_system_status_tab(self):
        layout = QVBoxLayout(); title = QLabel("System Status — оперативний стан об’єкта"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.system_status_text = QLabel("Очікування даних системи..."); self.system_status_text.setAlignment(Qt.AlignTop); self.system_status_text.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        b1 = QPushButton("Оновити статус системи"); b1.clicked.connect(self.update_system_status_panel); b2 = QPushButton("Сформувати звіт про інцидент"); b2.clicked.connect(self.generate_incident_report)
        layout.addWidget(title); layout.addWidget(self.system_status_text); layout.addWidget(b1); layout.addWidget(b2); self.system_status_tab.setLayout(layout)

    def update_system_status_panel(self):
        if not self.current_sensor_data: self.system_status_text.setText("Немає поточних даних датчиків."); return
        d = self.current_sensor_data; ai = self.ai_engine.analyze(d); last = "Остання атака: не зафіксовано"
        if self.last_attack: last = f"Остання атака:\n- тип: {self.last_attack['attack_type']}\n- IP: {self.last_attack['source_ip']}\n- ціль: {self.last_attack['target']}\n- рівень: {self.last_attack['severity']}"
        self.system_status_text.setText(f"ПОТОЧНИЙ СТАН ТЕЦ\n\nСтатус: {d['system_status']}\nТемпература: {d['temperature']} °C\nТиск: {d['pressure']} МПа\nОберти: {d['turbine_rpm']} RPM\nГенерація: {d['power_output']} MW\nВібрація: {d['vibration']} mm/s\nРівень води: {d['water_level']} %\nНавантаження: {d['load_percent']} %\n\nAI: {ai['threat_level']} / {ai['score']} / confidence {ai['confidence']} %\nРекомендація: {ai['recommendation']}\n\n{last}\n\nSAFE MODE: {self.defense_engine.safe_mode}\nPLC ізольовано: {self.defense_engine.isolated_plc}\nЗаблоковані IP: {', '.join(self.defense_engine.blocked_ips) if self.defense_engine.blocked_ips else 'немає'}")

    def generate_incident_report(self):
        self.mark_activity()
        if not self.current_sensor_data: QMessageBox.warning(self, "Звіт", "Немає даних для формування звіту."); return
        ai = self.ai_engine.analyze(self.current_sensor_data); path = self.report_generator.generate_report(self.current_sensor_data, ai, self.last_attack, self.defense_engine, self.last_risk_result, self.last_incident, timeline=self.attack_timeline_history, soar_actions=self.soar_actions_history, live_analytics=self.last_live_analytics); self.logger.log_info(f"Сформовано звіт про інцидент: {path}"); self.audit("Reports", "Сформовано звіт про інцидент", "OK"); self.load_logs(); QMessageBox.information(self, "Звіт сформовано", f"Звіт збережено у файл:\n{path}")

    def init_timeline_tab(self):
        layout = QVBoxLayout(); title = QLabel("Event Timeline — хронологія інцидентів"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.timeline_text = QLabel("Очікування подій..."); self.timeline_text.setAlignment(Qt.AlignTop); self.timeline_text.setStyleSheet("font-size: 15px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        btn = QPushButton("Оновити хронологію"); btn.clicked.connect(self.load_timeline); layout.addWidget(title); layout.addWidget(self.timeline_text); layout.addWidget(btn); self.timeline_tab.setLayout(layout); self.load_timeline()

    def load_timeline(self):
        logs = get_event_logs(30)
        lines = []
        if self.attack_timeline_history:
            lines.append("=== ATTACK KILL CHAIN / SOAR TIMELINE ===")
            for item in self.attack_timeline_history[-10:]:
                lines.append(
                    f"[{item['time']}] {item['severity']} | {item['attack']} | MITRE {item['mitre']}\n"
                    f"Source: {item['source_ip']} → Target: {item['target']}\n"
                    f"Incident: {item['incident']}\nPropagation: {item['propagation']}\n"
                    f"AI/SOAR: detection → correlation → risk scoring → {'auto response' if self.auto_defense_enabled else 'manual response'}\n"
                    + "-" * 90
                )
            lines.append("")
        if logs:
            lines.append("=== SYSTEM EVENT LOGS ===")
            lines.extend([f"[{x[0]}] {x[5]} | {x[3]}\nКористувач: {x[1]} / {x[2]}\n{x[4]}\n{'-'*80}" for x in reversed(logs)])
        if not lines:
            self.timeline_text.setText("Подій поки немає.")
        else:
            self.timeline_text.setText("\n".join(lines))

    def init_analytics_tab(self):
        layout = QVBoxLayout(); title = QLabel("Analytics Center — історія атак і дій захисту"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.attacks_table = self.make_table(["Час", "Тип атаки", "IP", "Джерело", "Ціль", "Рівень", "Опис", "Вплив"])
        self.defense_table = self.make_table(["Час", "SAFE MODE", "PLC ізольовано", "Навантаження знижено", "IP", "Дії"])
        self.risk_table = self.make_table(["Час", "Рівень ризику", "Risk Score", "Фактори"])
        self.incidents_table = self.make_table(["Час", "Рівень інциденту", "Incident Score", "Ознаки"])
        btn = QPushButton("Оновити аналітику"); btn.clicked.connect(self.load_analytics)
        for label, table in [("Історія атак:", self.attacks_table), ("Історія дій захисту:", self.defense_table), ("Історія оцінок ризику:", self.risk_table), ("Скорельовані інциденти:", self.incidents_table)]: layout.addWidget(QLabel(label)); layout.addWidget(table)
        layout.addWidget(btn); self.analytics_tab.setLayout(layout); self.load_analytics()

    def make_table(self, headers):
        t = QTableWidget(); t.setColumnCount(len(headers)); t.setHorizontalHeaderLabels(headers); return t

    def fill_table(self, table, rows):
        table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, v in enumerate(row): table.setItem(r, c, QTableWidgetItem(str(v)))
        table.resizeColumnsToContents()

    def load_analytics(self):
        self.fill_table(self.attacks_table, get_attack_records()); self.fill_table(self.defense_table, get_defense_records()); self.fill_table(self.risk_table, get_risk_records()); self.fill_table(self.incidents_table, get_correlated_incidents())

    def init_charts_tab(self):
        layout = QVBoxLayout()
        title = QLabel("Live Charts + Digital Twin — AI-аналітика у реальному часі")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")

        splitter = QSplitter(Qt.Horizontal)
        chart_widget = QWidget()
        chart_layout = QVBoxLayout()
        self.figure = Figure(figsize=(10, 7))
        self.canvas = FigureCanvas(self.figure)
        chart_layout.addWidget(self.canvas)
        chart_widget.setLayout(chart_layout)

        side_widget = QWidget()
        side_layout = QVBoxLayout()
        self.live_analytics_label = QLabel("Очікування даних Digital Twin...")
        self.live_analytics_label.setAlignment(Qt.AlignTop)
        self.live_analytics_label.setWordWrap(True)
        self.live_analytics_label.setStyleSheet("font-size: 14px; color: #e5e7eb; background-color: #020617; border: 1px solid #0ea5e9; padding: 16px; border-radius: 12px;")
        btn = QPushButton("Оновити графіки")
        btn.clicked.connect(self.update_charts)
        side_layout.addWidget(self.live_analytics_label)
        side_layout.addWidget(btn)
        side_widget.setLayout(side_layout)

        splitter.addWidget(chart_widget)
        splitter.addWidget(side_widget)
        splitter.setSizes([950, 360])
        layout.addWidget(title)
        layout.addWidget(splitter)
        self.charts_tab.setLayout(layout)

    def update_chart_history(self, data):
        self.chart_counter += 1
        expected = self.live_analytics.expected_values(data) if hasattr(self, "live_analytics") else {"expected_rpm": data["turbine_rpm"], "expected_power": data["power_output"]}
        anomaly = self.last_live_analytics.get("anomaly_score", 0) if self.last_live_analytics else 0
        for arr, value in [
            (self.chart_time, self.chart_counter),
            (self.chart_temperature, data["temperature"]),
            (self.chart_pressure, data["pressure"]),
            (self.chart_rpm, data["turbine_rpm"]),
            (self.chart_load, data["load_percent"]),
            (self.chart_vibration, data["vibration"]),
            (self.chart_anomaly, anomaly),
            (self.chart_expected_rpm, expected["expected_rpm"]),
            (self.chart_expected_power, expected["expected_power"]),
        ]:
            arr.append(value)
        max_points = 45
        self.chart_time = self.chart_time[-max_points:]
        self.chart_temperature = self.chart_temperature[-max_points:]
        self.chart_pressure = self.chart_pressure[-max_points:]
        self.chart_rpm = self.chart_rpm[-max_points:]
        self.chart_load = self.chart_load[-max_points:]
        self.chart_vibration = self.chart_vibration[-max_points:]
        self.chart_anomaly = self.chart_anomaly[-max_points:]
        self.chart_expected_rpm = self.chart_expected_rpm[-max_points:]
        self.chart_expected_power = self.chart_expected_power[-max_points:]
        if hasattr(self, "canvas"):
            self.update_charts()

    def update_charts(self):
        if not hasattr(self, "figure"):
            return
        self.figure.clear()
        axes = [self.figure.add_subplot(321), self.figure.add_subplot(322), self.figure.add_subplot(323), self.figure.add_subplot(324), self.figure.add_subplot(325), self.figure.add_subplot(326)]

        axes[0].plot(self.chart_time, self.chart_temperature)
        axes[0].set_title("Steam temperature, °C")
        axes[0].grid(True)

        axes[1].plot(self.chart_time, self.chart_pressure)
        axes[1].set_title("Pressure, MPa")
        axes[1].grid(True)

        axes[2].plot(self.chart_time, self.chart_rpm, label="Actual RPM")
        axes[2].plot(self.chart_time, self.chart_expected_rpm, linestyle="--", label="Digital Twin RPM")
        axes[2].set_title("Turbine RPM: actual vs expected")
        axes[2].legend(loc="best")
        axes[2].grid(True)

        axes[3].plot(self.chart_time, self.chart_load, label="Load %")
        axes[3].plot(self.chart_time, self.chart_expected_power, linestyle="--", label="Expected MW")
        axes[3].set_title("Load / expected generation")
        axes[3].legend(loc="best")
        axes[3].grid(True)

        axes[4].plot(self.chart_time, self.chart_vibration)
        axes[4].set_title("Turbine vibration, mm/s")
        axes[4].grid(True)

        axes[5].plot(self.chart_time, self.chart_anomaly)
        axes[5].set_title("AI/Digital Twin anomaly score")
        axes[5].set_ylim(0, 100)
        axes[5].grid(True)

        self.figure.subplots_adjust(hspace=0.55, wspace=0.35, left=0.06, right=0.97, top=0.93, bottom=0.08)
        self.canvas.draw()
        if hasattr(self, "live_analytics_label"):
            self.update_live_analytics_panel()

    def update_live_charts(self):
        """Backward-compatible alias for Demo Mode and older handlers."""
        return self.update_charts()

    def init_logs_tab(self):
        layout = QVBoxLayout(); title = QLabel("Журнал подій системи"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 18px; font-weight: bold; color: #38bdf8;")
        self.logs_table = self.make_table(["Час", "Користувач", "Роль", "Тип події", "Опис", "Рівень"]); btn = QPushButton("Оновити журнал"); btn.clicked.connect(self.load_logs)
        layout.addWidget(title); layout.addWidget(self.logs_table); layout.addWidget(btn); self.logs_tab.setLayout(layout); self.load_logs()

    def load_logs(self):
        self.fill_table(self.logs_table, get_event_logs())
        if hasattr(self, "timeline_text"): self.load_timeline()

    def init_roles_tab(self):
        layout = QVBoxLayout(); title = QLabel("RBAC Matrix — рольова модель доступу"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.roles_table = self.make_table(["Функція", "Admin", "Operator", "Analyst"])
        rows = [("Перегляд SCADA Dashboard", "Так", "Так", "Так"), ("Запуск атак", "Так", "Ні", "Так"), ("AI Training / ML Model", "Так", "Ні", "Так"), ("Emergency Stop", "Так", "Так", "Ні"), ("User Management", "Так", "Ні", "Ні"), ("Configuration", "Так", "Ні", "Ні"), ("Backup / Restore", "Так", "Ні", "Ні"), ("Analytics", "Так", "Перегляд", "Так")]
        self.fill_table(self.roles_table, rows); btn = QPushButton("Експортувати RBAC-звіт"); btn.clicked.connect(self.export_rbac_report)
        layout.addWidget(title); layout.addWidget(self.roles_table); layout.addWidget(btn); self.roles_tab.setLayout(layout)

    def export_rbac_report(self):
        self.mark_activity(); path = self.rbac_report_generator.generate_report(); self.logger.log_info(f"RBAC-звіт сформовано: {path}"); self.audit("RBAC", "Експортовано RBAC-звіт", "OK"); self.load_logs(); QMessageBox.information(self, "RBAC Report", f"RBAC-звіт збережено:\n{path}")

    def init_users_tab(self):
        layout = QVBoxLayout(); title = QLabel("User Management — керування користувачами"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.users_table = self.make_table(["ID", "Логін", "Роль"]); row = QHBoxLayout(); self.new_username_input = QLineEdit(); self.new_username_input.setPlaceholderText("Новий логін"); self.new_password_input = QLineEdit(); self.new_password_input.setPlaceholderText("Пароль"); self.new_password_input.setEchoMode(QLineEdit.Password); self.new_role_combo = QComboBox(); self.new_role_combo.addItems(["Admin", "Operator", "Analyst"])
        b1 = QPushButton("Додати користувача"); b1.clicked.connect(self.add_new_user); b2 = QPushButton("Оновити список"); b2.clicked.connect(self.load_users)
        for w in [self.new_username_input, self.new_password_input, self.new_role_combo, b1, b2]: row.addWidget(w)
        layout.addWidget(title); layout.addWidget(self.users_table); layout.addLayout(row); self.users_tab.setLayout(layout); self.load_users()

    def load_users(self): self.fill_table(self.users_table, get_users())

    def add_new_user(self):
        self.mark_activity()
        if self.role != "Admin": QMessageBox.warning(self, "Обмеження доступу", "Додавати користувачів може лише Admin."); return
        username = self.new_username_input.text().strip(); password = self.new_password_input.text().strip(); role = self.new_role_combo.currentText()
        if not username or not password: QMessageBox.warning(self, "Помилка", "Введіть логін і пароль."); return
        try:
            add_user(username, password, role); self.logger.log_info(f"Admin додав нового користувача: {username} / {role}"); self.audit("User Management", f"Додано користувача {username}", "OK"); self.load_users(); self.load_logs(); self.new_username_input.clear(); self.new_password_input.clear(); QMessageBox.information(self, "Готово", "Користувача додано.")
        except Exception as e: QMessageBox.critical(self, "Помилка", f"Не вдалося додати користувача:\n{e}")

    def init_config_tab(self):
        layout = QVBoxLayout(); title = QLabel("Configuration Center — пороги AI-аналізу"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.config_table = self.make_table(["Параметр", "Значення"]); b1 = QPushButton("Оновити конфігурацію"); b1.clicked.connect(self.load_config_table); b2 = QPushButton("Редагувати вибраний поріг"); b2.clicked.connect(self.edit_selected_threshold); b3 = QPushButton("Скинути пороги за замовчуванням"); b3.clicked.connect(self.reset_ai_thresholds)
        layout.addWidget(title); layout.addWidget(self.config_table); layout.addWidget(b1); layout.addWidget(b2); layout.addWidget(b3); self.config_tab.setLayout(layout); self.load_config_table()

    def load_config_table(self): self.fill_table(self.config_table, list(THRESHOLDS.items()))

    def edit_selected_threshold(self):
        self.mark_activity()
        if self.role != "Admin": QMessageBox.warning(self, "Обмеження доступу", "Редагувати пороги AI-аналізу може лише Admin."); return
        r = self.config_table.currentRow()
        if r < 0: QMessageBox.warning(self, "Помилка", "Оберіть параметр у таблиці."); return
        key = self.config_table.item(r, 0).text(); old = self.config_table.item(r, 1).text(); new, ok = QInputDialog.getDouble(self, "Редагування порогу", f"Новий поріг для {key}:", float(old), 0, 10000, 2)
        if ok: update_threshold(key, new); self.logger.log_info(f"Admin змінив поріг AI: {key} з {old} на {new}"); self.audit("Configuration", f"Змінено поріг {key}", "OK"); self.load_config_table(); self.load_logs(); QMessageBox.information(self, "Готово", f"Поріг {key} змінено на {new}")

    def reset_ai_thresholds(self):
        self.mark_activity()
        if self.role != "Admin": QMessageBox.warning(self, "Обмеження доступу", "Скидати пороги AI-аналізу може лише Admin."); return
        reset_thresholds(); self.logger.log_info("Admin скинув пороги AI-аналізу за замовчуванням"); self.audit("Configuration", "Скинуто пороги AI-аналізу", "OK"); self.load_config_table(); self.load_logs(); QMessageBox.information(self, "Готово", "Пороги AI-аналізу скинуто за замовчуванням.")

    def init_backup_tab(self):
        layout = QVBoxLayout(); title = QLabel("Backup Center — резервне копіювання SQLite"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.backup_table = self.make_table(["Файл резервної копії"]); b1 = QPushButton("Створити резервну копію"); b1.clicked.connect(self.create_database_backup); b2 = QPushButton("Відновити вибрану копію"); b2.clicked.connect(self.restore_database_backup); b3 = QPushButton("Оновити список"); b3.clicked.connect(self.load_backups)
        layout.addWidget(title); layout.addWidget(self.backup_table); layout.addWidget(b1); layout.addWidget(b2); layout.addWidget(b3); self.backup_tab.setLayout(layout); self.load_backups()

    def load_backups(self): self.fill_table(self.backup_table, [(x,) for x in self.backup_manager.list_backups()])
    def create_database_backup(self):
        self.mark_activity()
        if self.role != "Admin": QMessageBox.warning(self, "Доступ", "Резервне копіювання доступне лише Admin."); return
        path = self.backup_manager.create_backup()
        if not path: QMessageBox.warning(self, "Backup", "Базу даних не знайдено."); return
        self.logger.log_info(f"Створено резервну копію бази: {path}"); self.audit("Backup", "Створено резервну копію", "OK"); self.load_logs(); self.load_backups(); QMessageBox.information(self, "Backup", f"Резервну копію створено:\n{path}")

    def restore_database_backup(self):
        self.mark_activity()
        if self.role != "Admin": QMessageBox.warning(self, "Доступ", "Відновлення доступне лише Admin."); return
        r = self.backup_table.currentRow()
        if r < 0: QMessageBox.warning(self, "Restore", "Оберіть резервну копію."); return
        path = self.backup_table.item(r, 0).text(); ok = self.backup_manager.restore_backup(path)
        if ok: self.audit("Backup", "Відновлено резервну копію", "OK"); QMessageBox.information(self, "Restore", "Базу відновлено. Перезапусти програму.")
        else: QMessageBox.critical(self, "Restore", "Не вдалося відновити базу.")

    def init_health_tab(self):
        layout = QVBoxLayout(); title = QLabel("System Health Check — самодіагностика системи"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.health_label = QLabel("Очікування перевірки..."); self.health_label.setAlignment(Qt.AlignTop); self.health_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        btn = QPushButton("Перевірити систему"); btn.clicked.connect(self.run_health_check); layout.addWidget(title); layout.addWidget(self.health_label); layout.addWidget(btn); self.health_tab.setLayout(layout); self.run_health_check()

    def run_health_check(self):
        self.mark_activity()

        res = self.health_checker.run_check()

        lines = []

        for item in res.get("checks", []):
            if len(item) >= 2:
                name = item[0]
                status = item[1]
            else:
                name = str(item)
                status = False

            lines.append(f"{'OK' if status else 'MISSING'} — {name}")

        self.health_label.setText(
            f"""
    РЕЗУЛЬТАТ САМОДІАГНОСТИКИ

    Перевірено: {res.get('checked', 0)}
    Успішно: {res.get('passed', 0)}
    Health Score: {res.get('health_score', 0)} %

    {chr(10).join(lines)}
    """
        )

        self.logger.log_info(
            f"System Health Check виконано: {res.get('health_score', 0)}%"
        )

        self.audit(
            "System Health Check",
            f"Health Score: {res.get('health_score', 0)}%",
            "OK"
        )

    def init_audit_tab(self):
        layout = QVBoxLayout(); title = QLabel("Audit Trail — аудит дій користувачів"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.audit_table = self.make_table(["Час", "Користувач", "Роль", "Модуль", "Дія", "Результат"]); btn = QPushButton("Оновити аудит"); btn.clicked.connect(self.load_audit); layout.addWidget(title); layout.addWidget(self.audit_table); layout.addWidget(btn); self.audit_tab.setLayout(layout); self.load_audit()

    def load_audit(self): self.fill_table(self.audit_table, get_audit_records())
    def audit(self, module, action, result="OK"):
        add_audit_record(self.username, self.role, module, action, result)
        if hasattr(self, "audit_table"): self.load_audit()

    def init_training_tab(self):
        layout = QVBoxLayout(); title = QLabel("AI Training Center — навчання моделі"); title.setAlignment(Qt.AlignCenter); title.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8;")
        self.training_status_label = QLabel("AI модель ще не навчалась."); self.training_status_label.setAlignment(Qt.AlignTop); self.training_status_label.setStyleSheet("font-size: 16px; color: #e5e7eb; background-color: #111827; padding: 20px; border-radius: 12px;")
        buttons = [("Запустити AI Training", self.run_ai_training), ("Оновити статус", self.update_training_status), ("Згенерувати навчальний dataset", self.generate_training_dataset), ("Експортувати dataset у CSV", self.export_dataset), ("Навчити реальну ML-модель", self.train_real_ml_model)]
        layout.addWidget(title); layout.addWidget(self.training_status_label)
        for text, cb in buttons:
            b = QPushButton(text); b.clicked.connect(cb); layout.addWidget(b)
        self.training_tab.setLayout(layout); self.update_training_status()

    def run_ai_training(self):
        self.mark_activity()
        res = self.training_engine.train()
        self.logger.log_info(f"AI Training completed. Accuracy={res.get('model_accuracy', res.get('accuracy', 0))}%")
        self.audit("AI Training", "Імітаційне навчання AI виконано", "OK")
        self.load_logs()
        self.update_training_status()
        QMessageBox.information(self, "AI Training", "Навчання AI-моделі завершено.")

    def update_training_status(self):
        r = self.training_engine.get_status()
        self.training_status_label.setText(
            f"СТАН AI-МОДЕЛІ\n\n"
            f"Training Status: {r['training_status']}\n\n"
            f"Кількість samples: {r['training_samples']}\n"
            f"Нормальні стани: {r['normal_samples']}\n"
            f"Аномалії: {r['anomaly_samples']}\n\n"
            f"Model Accuracy: {r['model_accuracy']} %\n"
            f"Model Loss: {r['model_loss']}"
        )

    def export_dataset(self):
        self.mark_activity(); path, count = self.dataset_exporter.export_sensor_dataset(); self.logger.log_info(f"Експортовано dataset: {path}, записів: {count}"); self.audit("AI Training", "Експортовано dataset у CSV", "OK"); self.load_logs(); QMessageBox.information(self, "Dataset Export", f"Dataset успішно експортовано.\n\nФайл: {path}\nКількість записів: {count}")

    def generate_training_dataset(self):
        self.mark_activity()
        generated = 0
        generators = [
            (self.sensors.generate_normal_data, 34),
            (self.sensors.generate_warning_data, 22),
            (self.sensors.generate_critical_data, 14),
            (self.sensors.simulate_plc_attack, 12),
            (self.sensors.simulate_fake_sensor_attack, 12),
        ]
        for generator, count in generators:
            for _ in range(count):
                d = generator()
                add_sensor_data(d["temperature"], d["pressure"], d["turbine_rpm"], d["power_output"], d["vibration"], d["water_level"], d["load_percent"], d["system_status"])
                generated += 1
        self.logger.log_info(f"Згенеровано навчальний dataset для ML: {generated} записів")
        self.audit("AI Training", f"Згенеровано dataset: {generated} записів", "OK")
        self.load_logs()
        QMessageBox.information(self, "Dataset Generated", f"Створено {generated} навчальних записів у SQLite.\nТепер натисни: Навчити реальну ML-модель.")

    def train_real_ml_model(self):
        self.mark_activity()
        res = self.ml_trainer.train_from_database()
        if not res["success"]:
            QMessageBox.warning(self, "ML Training", res["message"] + "\n\nПорада: натисни 'Згенерувати навчальний dataset', потім повтори навчання.")
            return
        self.ml_predictor.load_model()
        report = self.ml_report_exporter.export_report(res)
        self.last_ml_prediction = "MODEL_TRAINED"
        if hasattr(self, "ml_prediction_label"):
            self.ml_prediction_label.value_label.setText("MODEL_TRAINED")
            self.ml_prediction_label.value_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #22c55e;")
        self.logger.log_info(f"Реальну ML-модель навчено. Accuracy={res['accuracy']}%, records={res['records']}")
        self.audit("AI Training", "ML-модель навчено", "OK")
        self.load_logs()
        QMessageBox.information(self, "ML Training Complete", f"Модель успішно навчено.\n\nЗаписів: {res['records']}\nAccuracy: {res['accuracy']} %\nКласи: {', '.join(res['classes'])}\nФайл моделі: {res['model_path']}\nML-звіт: {report}\n\nFeature importance:\n{res['feature_importance']}")

    def emergency_stop(self):
        self.mark_activity()
        if self.role not in ["Admin", "Operator"]: QMessageBox.warning(self, "Обмеження доступу", "Emergency Stop доступний лише Admin або Operator."); return
        self.update_sensor_labels(self.sensors.emergency_stop()); self.defense_engine.safe_mode = True; self.defense_engine.isolated_plc = True; self.defense_engine.load_reduced = True; self.add_notification("EMERGENCY STOP", "ТЕЦ переведено в аварійне зупинення.", "CRITICAL"); self.logger.log_critical(f"EMERGENCY STOP активовано користувачем {self.username}"); self.audit("SCADA Dashboard", "Emergency Stop активовано", "CRITICAL"); self.load_logs(); self.update_topology(); QMessageBox.critical(self, "EMERGENCY STOP", "ТЕЦ переведено у режим аварійного зупинення.")

    def reset_plant(self):
        self.mark_activity()
        if self.role not in ["Admin", "Operator"]: QMessageBox.warning(self, "Обмеження доступу", "Reset Plant доступний лише Admin або Operator."); return
        self.update_sensor_labels(self.sensors.reset_plant()); self.defense_engine.safe_mode = False; self.defense_engine.isolated_plc = False; self.defense_engine.load_reduced = False; self.add_notification("RESET PLANT", "ТЕЦ повернуто у штатний режим NORMAL.", "INFO"); self.logger.log_info(f"Reset Plant виконано користувачем {self.username}"); self.audit("SCADA Dashboard", "Reset Plant виконано", "OK"); self.load_logs(); self.update_topology(); QMessageBox.information(self, "Reset Plant", "ТЕЦ повернуто у штатний режим NORMAL.")

    def mark_activity(self): self.session_manager.update_activity()
    def update_session_label(self):
        if hasattr(self, "session_label"): self.session_label.setText(f"Час входу: {self.session_manager.get_login_time()} | Тривалість сесії: {self.session_manager.get_session_duration()}")
    def check_session_timeout(self):
        if self.session_manager.is_session_expired():
            self.logger.log_warning(
                f"Сесію користувача {self.username} завершено через неактивність. "
                f"Тривалість сесії: {self.session_manager.get_session_duration()}"
            )
            self.audit("Authentication", "Автоматичне завершення сесії через неактивність", "TIMEOUT")
            QMessageBox.warning(self, "Session Timeout", "Сесію завершено через неактивність.")
            self.close()

    def logout(self):
        self.logger.log_info(f"Користувач {self.username} вийшов із системи. Тривалість сесії: {self.session_manager.get_session_duration()}"); self.audit("Authentication", "Вихід із системи", "OK"); QMessageBox.information(self, "Logout", "Сесію завершено. Програму буде закрито."); self.close()


    def run_real_ai_prediction(self):
        """Run real ML prediction over current SCADA telemetry without crashing GUI."""
        try:
            if not hasattr(self, "real_ai_engine"):
                self.real_ai_engine = RealAIMLEngine()

            attack_type = str(getattr(self, "last_attack_type", "")).lower()

            telemetry = {
                "temperature": getattr(self, "temperature", getattr(self, "temp", 500.0)),
                "pressure": getattr(self, "pressure", 12.5),
                "turbine_rpm": getattr(self, "turbine_rpm", getattr(self, "rpm", 3000.0)),
                "vibration": getattr(self, "vibration", 0.8),
                "power_output": getattr(self, "power_output", getattr(self, "power", 220.0)),
                "water_level": getattr(self, "water_level", getattr(self, "water", 70.0)),
                "load_percent": getattr(self, "load_percent", getattr(self, "load", 65.0)),
                "modbus_write": any(x in attack_type for x in ["plc", "modbus", "write"]),
                "sensor_mismatch": any(x in attack_type for x in ["fake", "sensor", "replay"]),
                "failed_login": any(x in attack_type for x in ["brute", "credential", "login"]),
                "network_scan": any(x in attack_type for x in ["scan", "recon", "ddos"]),
            }

            result = self.real_ai_engine.predict(telemetry)

            self.ai_confidence = result.get("confidence", 60.0)
            self.ai_threat_level = result.get("severity", "LOW")
            self.ml_prediction = f'{result.get("label", "NORMAL")} ({self.ai_confidence:.1f}%)'
            self.ai_recommendation = result.get("recommendation", "Monitoring only.")

            # Best-effort GUI label updates: works only if labels exist.
            for name in ["ai_confidence_label", "confidence_label"]:
                if hasattr(self, name):
                    getattr(self, name).setText(f"{self.ai_confidence:.1f} %")

            for name in ["ai_threat_label", "threat_level_label"]:
                if hasattr(self, name):
                    getattr(self, name).setText(str(self.ai_threat_level))

            for name in ["ml_prediction_label", "prediction_label", "model_status_label"]:
                if hasattr(self, name):
                    getattr(self, name).setText(self.ml_prediction)

            if self.ai_threat_level == "CRITICAL":
                self.system_status = "CRITICAL"
            elif self.ai_threat_level == "HIGH":
                self.system_status = "WARNING"

            if getattr(self, "auto_defense_enabled", False) and self.ai_confidence >= 85:
                if hasattr(self, "activate_auto_defense"):
                    self.activate_auto_defense()

            print("[REAL AI]", self.ml_prediction, result.get("model_used", ""))

        except Exception as e:
            print("[REAL AI ERROR]", e)


    def open_war_room_mode(self):
        """Open fullscreen SOC War Room window."""
        try:
            self.war_room_window = WarRoomWindow(self)
            self.war_room_window.show()
        except Exception as e:
            print("[WAR ROOM ERROR]", e)
