import random
from datetime import datetime


class TrafficMonitor:
    def __init__(self):
        self.protocols = [
            "Modbus TCP",
            "OPC UA",
            "IEC 60870-5-104",
            "HTTP",
            "SQLite"
        ]

        self.targets = [
            "SCADA Server",
            "PLC Controller",
            "Sensor Gateway",
            "Database"
        ]

        self.events = []
        self.max_events = 500

    def _now(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _packet_id(self):
        return f"PKT-{datetime.now().strftime('%H%M%S')}-{random.randint(1000, 9999)}"

    def _limit_history(self):
        self.events = self.events[:self.max_events]

    def generate_normal_traffic(self):
        protocol = random.choice([
            "Modbus TCP",
            "OPC UA",
            "IEC 60870-5-104"
        ])

        target = random.choice([
            "SCADA Server",
            "PLC Controller",
            "Sensor Gateway"
        ])

        event = {
            "packet_id": self._packet_id(),
            "time": self._now(),
            "source_ip": f"192.168.1.{random.randint(10, 50)}",
            "target": target,
            "protocol": protocol,
            "port": self.detect_port(protocol),
            "direction": "INTERNAL",
            "packet_size": random.randint(64, 512),
            "action": "Normal industrial communication",
            "status": "ALLOWED",
            "severity": "INFO"
        }

        self.events.insert(0, event)
        self._limit_history()

        return event

    def generate_attack_traffic(self, attack, blocked=False):
        attack_type = attack.get("attack_type", "UNKNOWN_ATTACK")
        protocol = attack.get("protocol") or self.detect_protocol(attack_type)

        event = {
            "packet_id": self._packet_id(),
            "time": self._now(),
            "source_ip": attack.get("source_ip", "UNKNOWN"),
            "target": attack.get("target", "UNKNOWN_TARGET"),
            "protocol": protocol,
            "port": self.detect_port(protocol),
            "direction": "EXTERNAL_TO_INTERNAL",
            "packet_size": random.randint(512, 4096),
            "action": attack_type,
            "status": "BLOCKED" if blocked else "SUSPICIOUS",
            "severity": attack.get("severity", "MEDIUM")
        }

        self.events.insert(0, event)
        self._limit_history()

        return event

    def detect_protocol(self, attack_type):
        if "Modbus" in attack_type:
            return "Modbus TCP"

        if "Database" in attack_type:
            return "SQLite"

        if "Replay" in attack_type:
            return "IEC 60870-5-104"

        if "DDoS" in attack_type:
            return "HTTP"

        if "PLC" in attack_type:
            return "Modbus TCP"

        if "Sensor" in attack_type:
            return "OPC UA"

        return "OPC UA"

    def detect_port(self, protocol):
        ports = {
            "Modbus TCP": 502,
            "OPC UA": 4840,
            "IEC 60870-5-104": 2404,
            "HTTP": 80,
            "HTTPS": 443,
            "SQLite": 0
        }

        return ports.get(protocol, 0)

    def get_events(self, limit=100):
        return self.events[:limit]

    def clear_events(self):
        self.events.clear()

    def get_statistics(self):
        total = len(self.events)

        allowed = sum(1 for e in self.events if e["status"] == "ALLOWED")
        blocked = sum(1 for e in self.events if e["status"] == "BLOCKED")
        suspicious = sum(1 for e in self.events if e["status"] == "SUSPICIOUS")

        protocols = {}

        for event in self.events:
            protocol = event["protocol"]
            protocols[protocol] = protocols.get(protocol, 0) + 1

        return {
            "total": total,
            "allowed": allowed,
            "blocked": blocked,
            "suspicious": suspicious,
            "protocols": protocols
        }