import random
from datetime import datetime


class AttackEngine:
    """Centralized ICS/OT attack scenario generator for the diploma SCADA/SOC platform.

    The engine does not perform any real malicious activity. It only generates
    structured simulation events that are consumed by GUI, AI, SIEM, firewall,
    MITRE mapper, risk engine and defense engine.
    """

    def __init__(self):
        self.attack_sources = [
            ("185.220.101.45", "Unknown / TOR Exit Node", "Germany", "Berlin", 52.5200, 13.4050),
            ("91.203.144.12", "Suspicious External Network", "Russia", "Moscow", 55.7558, 37.6173),
            ("45.155.205.233", "Botnet Infrastructure", "Netherlands", "Amsterdam", 52.3676, 4.9041),
            ("103.27.202.88", "Compromised Host", "Singapore", "Singapore", 1.3521, 103.8198),
            ("176.113.115.77", "Malicious Scanner", "Romania", "Bucharest", 44.4268, 26.1025),
            ("193.29.13.44", "APT-like Infrastructure", "Belarus", "Minsk", 53.9006, 27.5590),
            ("198.51.100.23", "Compromised VPN Account", "United States", "New York", 40.7128, -74.0060),
            ("203.0.113.77", "Rogue Engineering Laptop", "Poland", "Warsaw", 52.2297, 21.0122),
        ]

    def _generate_attack_id(self):
        return f"ATTACK-{datetime.now().strftime('%Y%m%d%H%M%S')}-{random.randint(1000, 9999)}"

    def _base_attack(self, attack_type, target, severity, description, impact, protocol,
                     target_component, mitre_hint, kill_chain_phase="INITIAL_EVENT",
                     network_indicators=None, process_effect=None, recommended_response=None):
        ip, source, country, city, lat, lon = random.choice(self.attack_sources)
        return {
            "attack_id": self._generate_attack_id(),
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": attack_type,
            "source_ip": ip,
            "source": source,
            "country": country,
            "city": city,
            "lat": lat,
            "lon": lon,
            "target": target,
            "target_component": target_component,
            "protocol": protocol,
            "severity": severity,
            "description": description,
            "impact": impact,
            "mitre_hint": mitre_hint,
            "kill_chain_phase": kill_chain_phase,
            "network_indicators": network_indicators or [],
            "process_effect": process_effect or "Немає прямого фізичного ефекту, потрібна кореляція з датчиками.",
            "recommended_response": recommended_response or "Посилити моніторинг, перевірити журнали та ізолювати підозрілий канал за потреби.",
        }

    def simulate_ddos(self):
        return self._base_attack(
            attack_type="DDoS",
            target="SCADA Server",
            severity="HIGH",
            description="Масовий потік запитів до SCADA-сервера з метою перевантаження системи.",
            impact="Затримка оновлення даних, ризик втрати доступності операторської панелі.",
            protocol="HTTP / TCP",
            target_component="SCADA_SERVER",
            mitre_hint="Impact / Denial of View",
            kill_chain_phase="IMPACT",
            network_indicators=["tcp_syn_flood", "hmi_latency", "session_timeout"],
            recommended_response="Увімкнути rate limiting, заблокувати джерело, перевірити доступність HMI.",
        )

    def simulate_modbus_command_injection(self):
        return self._base_attack(
            attack_type="Modbus Command Injection",
            target="PLC Controller",
            severity="CRITICAL",
            description="Спроба надсилання несанкціонованих команд до PLC через Modbus TCP.",
            impact="Можлива зміна стану виконавчих механізмів та порушення технологічного процесу.",
            protocol="Modbus TCP",
            target_component="PLC",
            mitre_hint="Impair Process Control / Unauthorized Command Message",
            kill_chain_phase="CONTROL_MANIPULATION",
            network_indicators=["modbus_fc_05", "modbus_fc_06", "write_single_register", "write_multiple_registers"],
            process_effect="Можлива зміна уставок тиску, навантаження або положення клапанів.",
            recommended_response="Ізолювати PLC-сегмент, заблокувати IP, перевірити журнал команд Modbus.",
        )

    def simulate_fake_sensor_data(self):
        return self._base_attack(
            attack_type="Fake Sensor Data Injection",
            target="Sensor Gateway",
            severity="CRITICAL",
            description="Підміна показників датчиків для приховування реального аварійного стану.",
            impact="Оператор бачить нормальні параметри, хоча фізична система може бути в небезпеці.",
            protocol="OPC UA / Sensor Stream",
            target_component="SENSOR_GATEWAY",
            mitre_hint="Impair Process Control / Spoof Reporting Message",
            kill_chain_phase="EVASION",
            network_indicators=["telemetry_spoofing", "flatline_values", "unexpected_sensor_source"],
            process_effect="Digital Twin може показувати невідповідність між очікуваними і фактичними параметрами.",
            recommended_response="Перевірити джерело телеметрії, виконати cross-check датчиків, активувати Digital Twin validation.",
        )

    def simulate_replay_attack(self):
        return self._base_attack(
            attack_type="Replay Attack",
            target="SCADA Communication Channel",
            severity="MEDIUM",
            description="Повторне відтворення раніше перехоплених легітимних пакетів керування.",
            impact="Система може прийняти старі команди як актуальні.",
            protocol="IEC 60870-5-104",
            target_component="COMMUNICATION_CHANNEL",
            mitre_hint="Evasion / Replay Communication",
            kill_chain_phase="EVASION",
            network_indicators=["duplicate_sequence", "stale_timestamp", "repeated_command"],
            recommended_response="Перевірити часові мітки, сесії, sequence numbers та канали IEC-104.",
        )

    def simulate_plc_manipulation(self):
        return self._base_attack(
            attack_type="PLC Manipulation",
            target="PLC Logic",
            severity="CRITICAL",
            description="Спроба зміни логіки керування PLC або параметрів технологічного процесу.",
            impact="Можливе перевантаження турбіни, зростання тиску та аварійний режим.",
            protocol="Modbus TCP / Engineering Workstation",
            target_component="PLC_LOGIC",
            mitre_hint="Inhibit Response Function / Modify Controller Tasking",
            kill_chain_phase="PERSISTENCE_AND_IMPACT",
            network_indicators=["engineering_station_access", "logic_download", "unauthorized_task_change"],
            process_effect="Підвищення навантаження, вібрації та нестабільність турбіни.",
            recommended_response="Заблокувати engineering workstation, перевірити checksum PLC-логіки, перейти у SAFE_MODE.",
        )

    def simulate_database_attack(self):
        return self._base_attack(
            attack_type="Database Attack",
            target="SQLite Event Database",
            severity="HIGH",
            description="Спроба несанкціонованого доступу до бази даних журналів та сенсорних показників.",
            impact="Ризик підміни або видалення журналів подій.",
            protocol="SQLite / Local Access",
            target_component="DATABASE",
            mitre_hint="Collection / Data Manipulation",
            kill_chain_phase="COLLECTION_AND_IMPACT",
            network_indicators=["failed_db_access", "unexpected_delete", "audit_log_tampering"],
            recommended_response="Зробити backup, перевірити RBAC, audit trail і цілісність журналів.",
        )

    def simulate_mitm_attack(self):
        return self._base_attack(
            attack_type="MITM Attack",
            target="SCADA ↔ PLC Channel",
            severity="HIGH",
            description="Спроба перехоплення та модифікації трафіку між SCADA і PLC.",
            impact="Можлива підміна команд або телеметрії без явного відключення системи.",
            protocol="Modbus TCP / OPC UA",
            target_component="NETWORK_SEGMENT",
            mitre_hint="Evasion / Man-in-the-Middle",
            kill_chain_phase="DISCOVERY_AND_EVASION",
            network_indicators=["arp_spoofing", "unexpected_gateway", "duplicate_mac", "latency_spike"],
            process_effect="Можливі розбіжності між HMI, PLC та Digital Twin.",
            recommended_response="Перевірити ARP/MAC таблиці, увімкнути сегментацію і заблокувати підозрілий вузол.",
        )

    def simulate_unauthorized_modbus_write(self):
        return self._base_attack(
            attack_type="Unauthorized Modbus Write",
            target="Boiler Pressure Register",
            severity="CRITICAL",
            description="Несанкціонований запис у критичний Modbus-регістр технологічного процесу.",
            impact="Можлива зміна уставки тиску котла або режиму насосів.",
            protocol="Modbus TCP Function Code 16",
            target_component="PLC_REGISTER",
            mitre_hint="Impair Process Control / Unauthorized Command Message",
            kill_chain_phase="CONTROL_MANIPULATION",
            network_indicators=["fc16_write_multiple_registers", "critical_register_access", "non_whitelisted_client"],
            process_effect="Різке зростання тиску, температури або навантаження.",
            recommended_response="Заблокувати IP, перевірити whitelist Modbus-команд, ізолювати PLC.",
        )

    def simulate_brute_force_login(self):
        return self._base_attack(
            attack_type="Brute Force SCADA Login",
            target="SCADA Login Service",
            severity="MEDIUM",
            description="Багаторазові невдалі спроби входу в SCADA/HMI під різними обліковими записами.",
            impact="Ризик компрометації операторського або адміністративного облікового запису.",
            protocol="HTTPS / SCADA Auth",
            target_component="AUTH_SERVICE",
            mitre_hint="Initial Access / Valid Accounts",
            kill_chain_phase="INITIAL_ACCESS",
            network_indicators=["many_failed_logins", "password_spray", "admin_account_targeted"],
            recommended_response="Тимчасово заблокувати IP, перевірити облікові записи, увімкнути посилену автентифікацію.",
        )

    def simulate_turbine_sabotage_scenario(self):
        return self._base_attack(
            attack_type="Coordinated Turbine Sabotage",
            target="Turbine Control Loop",
            severity="CRITICAL",
            description="Комбінований сценарій: PLC write + підміна телеметрії + зростання вібрації турбіни.",
            impact="Високий ризик кіберфізичного інциденту, пошкодження турбіни або аварійного зупинення.",
            protocol="Modbus TCP / OPC UA / Engineering Workstation",
            target_component="TURBINE_CONTROL_LOOP",
            mitre_hint="Impair Process Control / Modify Controller Tasking / Spoof Reporting Message",
            kill_chain_phase="CYBER_PHYSICAL_IMPACT",
            network_indicators=["modbus_write", "telemetry_spoofing", "engineering_access", "vibration_growth"],
            process_effect="Турбіна працює нестабільно: вібрація, RPM і навантаження виходять за безпечні межі.",
            recommended_response="Негайно активувати SAFE_MODE, ізолювати PLC, знизити навантаження і провести ручну перевірку.",
        )

    def simulate_random_attack(self):
        scenarios = [
            self.simulate_ddos,
            self.simulate_modbus_command_injection,
            self.simulate_fake_sensor_data,
            self.simulate_replay_attack,
            self.simulate_plc_manipulation,
            self.simulate_database_attack,
            self.simulate_mitm_attack,
            self.simulate_unauthorized_modbus_write,
            self.simulate_brute_force_login,
            self.simulate_turbine_sabotage_scenario,
        ]
        return random.choice(scenarios)()
