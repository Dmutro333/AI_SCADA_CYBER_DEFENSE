from datetime import datetime


class FirewallEngine:
    def __init__(self):
        self.enabled = True

        self.blocked_ips = []
        self.allowed_ips = [
            "127.0.0.1",
            "localhost",
            "192.168.1.10",
            "192.168.1.11",
            "192.168.1.12"
        ]

        self.blocked_count = 0
        self.allowed_count = 0
        self.last_event = "Firewall очікує події"
        self.history = []

    def _now(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _add_history(self, event):
        self.history.insert(0, event)
        self.history = self.history[:100]

    def inspect_attack(self, attack):
        ip = attack.get("source_ip", "UNKNOWN")
        attack_type = attack.get("attack_type", "UNKNOWN_ATTACK")

        if not self.enabled:
            self.last_event = "Firewall вимкнений. Атака не заблокована."

            event = {
                "time": self._now(),
                "source_ip": ip,
                "attack_type": attack_type,
                "blocked": False,
                "status": "DISABLED",
                "reason": "Firewall disabled"
            }

            self._add_history(event)
            return event

        if ip in self.allowed_ips:
            self.allowed_count += 1
            self.last_event = f"IP {ip} дозволений whitelist. Атака не заблокована."

            event = {
                "time": self._now(),
                "source_ip": ip,
                "attack_type": attack_type,
                "blocked": False,
                "status": "ALLOWED",
                "reason": "IP in whitelist"
            }

            self._add_history(event)
            return event

        if ip not in self.blocked_ips:
            self.blocked_ips.append(ip)

        self.blocked_count += 1
        self.last_event = f"IP {ip} заблоковано через {attack_type}"

        event = {
            "time": self._now(),
            "source_ip": ip,
            "attack_type": attack_type,
            "blocked": True,
            "status": "BLOCKED",
            "reason": attack_type
        }

        self._add_history(event)
        return event

    def toggle_firewall(self):
        self.enabled = not self.enabled

        state = "увімкнено" if self.enabled else "вимкнено"
        self.last_event = f"Firewall {state}"

        self._add_history({
            "time": self._now(),
            "source_ip": "-",
            "attack_type": "SYSTEM",
            "blocked": False,
            "status": "ON" if self.enabled else "OFF",
            "reason": self.last_event
        })

        return self.enabled

    def reset_blocks(self):
        self.blocked_ips.clear()
        self.blocked_count = 0
        self.last_event = "Список заблокованих IP очищено"

        self._add_history({
            "time": self._now(),
            "source_ip": "-",
            "attack_type": "SYSTEM",
            "blocked": False,
            "status": "RESET",
            "reason": "Blocklist cleared"
        })

    def add_allowed_ip(self, ip):
        if ip not in self.allowed_ips:
            self.allowed_ips.append(ip)

        self.last_event = f"IP {ip} додано до whitelist"

    def remove_allowed_ip(self, ip):
        if ip in self.allowed_ips:
            self.allowed_ips.remove(ip)

        self.last_event = f"IP {ip} видалено з whitelist"

    def is_blocked(self, ip):
        return ip in self.blocked_ips

    def get_status(self):
        return {
            "enabled": self.enabled,
            "blocked_ips": list(self.blocked_ips),
            "allowed_ips": list(self.allowed_ips),
            "blocked_count": self.blocked_count,
            "allowed_count": self.allowed_count,
            "last_event": self.last_event,
            "history": list(self.history)
        }

    def get_history(self, limit=100):
        return self.history[:limit]