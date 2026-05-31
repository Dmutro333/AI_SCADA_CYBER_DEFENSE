from datetime import datetime

from database import add_event_log
from app_logger import get_logger, log_exception


class EventLogger:
    def __init__(self, username="system", role="System"):
        self.username = username
        self.role = role

        self.history = []
        self.file_loggers = {
            "AI_ANALYSIS": get_logger("ai"),
            "CYBER_ATTACK": get_logger("attacks"),
            "DEFENSE_ACTION": get_logger("soar"),
            "FIREWALL_EVENT": get_logger("soar"),
            "SENSOR_EVENT": get_logger("scada"),
            "EXCEPTION": get_logger("errors"),
        }
        self.system_logger = get_logger("system")
        self.max_history = 200

    def _add_local_history(self, event):
        self.history.insert(0, event)
        self.history = self.history[:self.max_history]

    def _log(self, event_type, description, severity="INFO", metadata=None):
        metadata = metadata or {}

        event = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": self.username,
            "role": self.role,
            "event_type": event_type,
            "description": description,
            "severity": severity,
            "metadata": metadata
        }

        try:
            add_event_log(
                self.username,
                self.role,
                event_type,
                description,
                severity
            )

        except Exception as error:
            event["database_error"] = str(error)

        try:
            logger = self.file_loggers.get(event_type, self.system_logger)
            logger.info("%s | %s | %s | %s", severity, self.username, event_type, description)
        except Exception as file_error:
            log_exception("event_logger_file_write", file_error)

        self._add_local_history(event)

        return event

    def log_info(self, description, metadata=None):
        return self._log(
            "SYSTEM_INFO",
            description,
            "INFO",
            metadata
        )

    def log_warning(self, description, metadata=None):
        return self._log(
            "WARNING",
            description,
            "WARNING",
            metadata
        )

    def log_critical(self, description, metadata=None):
        return self._log(
            "CRITICAL",
            description,
            "CRITICAL",
            metadata
        )

    def log_attack(self, description, metadata=None):
        return self._log(
            "CYBER_ATTACK",
            description,
            "HIGH",
            metadata
        )

    def log_defense(self, description, metadata=None):
        return self._log(
            "DEFENSE_ACTION",
            description,
            "MEDIUM",
            metadata
        )

    def log_ai(self, description, metadata=None):
        return self._log(
            "AI_ANALYSIS",
            description,
            "INFO",
            metadata
        )

    def log_ml(self, description, metadata=None):
        return self._log(
            "ML_EVENT",
            description,
            "INFO",
            metadata
        )

    def log_sensor(self, description, metadata=None):
        return self._log(
            "SENSOR_EVENT",
            description,
            "INFO",
            metadata
        )

    def log_firewall(self, description, metadata=None):
        return self._log(
            "FIREWALL_EVENT",
            description,
            "MEDIUM",
            metadata
        )

    def log_exception(self, exception, source="SYSTEM"):
        return self._log(
            "EXCEPTION",
            f"[{source}] {str(exception)}",
            "CRITICAL"
        )

    def get_history(self, limit=100):
        return self.history[:limit]

    def clear_history(self):
        self.history.clear()