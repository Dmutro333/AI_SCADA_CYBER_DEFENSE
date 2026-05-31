from datetime import datetime


class DefenseEngine:
    def __init__(self):
        self.safe_mode = False
        self.blocked_ips = []
        self.isolated_plc = False
        self.load_reduced = False
        self.last_actions = []
        self.last_activation_time = None
        self.defense_status = "IDLE"

    def activate_defense(self, ai_result, attack=None):
        self.last_actions = []

        threat_level = ai_result.get("threat_level", "LOW")
        self.last_activation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if threat_level == "LOW":
            self.defense_status = "MONITORING"
            self.last_actions.append("Моніторинг системи без активного втручання.")

        elif threat_level == "MEDIUM":
            self.defense_status = "ENHANCED_MONITORING"
            self.last_actions.append("Посилено моніторинг SCADA/PLC каналу.")
            self.last_actions.append("Рекомендовано перевірити журнал подій.")

        elif threat_level == "HIGH":
            self.defense_status = "PARTIAL_DEFENSE"
            self.load_reduced = True
            self.last_actions.append("Знижено навантаження ТЕЦ до безпечного рівня.")
            self.last_actions.append("Активовано розширений контроль PLC-команд.")

        elif threat_level == "CRITICAL":
            self.defense_status = "FULL_DEFENSE"
            self.safe_mode = True
            self.isolated_plc = True
            self.load_reduced = True
            self.last_actions.append("Активовано SAFE MODE.")
            self.last_actions.append("Ізольовано PLC-сегмент.")
            self.last_actions.append("Знижено навантаження ТЕЦ.")
            self.last_actions.append("Оператору рекомендовано ручну перевірку системи.")

        else:
            self.defense_status = "UNKNOWN_THREAT_LEVEL"
            self.last_actions.append(
                f"Невідомий рівень загрози: {threat_level}. Виконується моніторинг."
            )

        if attack and attack.get("source_ip"):
            ip = attack["source_ip"]

            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
                self.last_actions.append(f"Заблоковано підозрілу IP-адресу: {ip}")
            else:
                self.last_actions.append(f"IP-адреса вже була заблокована раніше: {ip}")

        return self.get_status()

    def reset_defense(self, clear_blocked_ips=False):
        self.safe_mode = False
        self.isolated_plc = False
        self.load_reduced = False
        self.defense_status = "RESET"
        self.last_activation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if clear_blocked_ips:
            self.blocked_ips.clear()
            self.last_actions = [
                "Систему захисту повернуто у штатний режим.",
                "Список заблокованих IP очищено."
            ]
        else:
            self.last_actions = [
                "Систему захисту повернуто у штатний режим.",
                "Список заблокованих IP залишено без змін."
            ]

        return self.get_status()

    def get_status(self):
        return {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "defense_status": self.defense_status,
            "last_activation_time": self.last_activation_time,
            "safe_mode": self.safe_mode,
            "isolated_plc": self.isolated_plc,
            "load_reduced": self.load_reduced,
            "blocked_ips": list(self.blocked_ips),
            "actions": list(self.last_actions)
        }