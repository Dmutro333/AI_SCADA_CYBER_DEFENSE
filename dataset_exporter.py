import os
import csv
from datetime import datetime

from database import DB_PATH, get_connection


class DatasetExporter:
    def __init__(self):
        self.export_dir = "exports"
        self.db_path = DB_PATH
        os.makedirs(self.export_dir, exist_ok=True)

    def _export_query(self, filename_prefix, header, query):
        filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = os.path.join(self.export_dir, filename)

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()

        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)

        return {
            "status": "SUCCESS",
            "path": path,
            "filename": filename,
            "rows": len(rows),
        }

    def export_sensor_dataset(self):
        """Метод, який викликає scada_window.py. Повертає (path, count)."""
        result = self.export_sensor_data()
        if result.get("status") != "SUCCESS":
            raise RuntimeError(result.get("message", "Dataset export failed"))
        return result["path"], result["rows"]

    def export_sensor_data(self):
        try:
            return self._export_query(
                "sensor_dataset",
                [
                    "timestamp", "temperature", "pressure", "turbine_rpm",
                    "power_output", "vibration", "water_level", "load_percent",
                    "system_status",
                ],
                """
                SELECT timestamp, temperature, pressure, turbine_rpm, power_output,
                       vibration, water_level, load_percent, system_status
                FROM sensor_data
                ORDER BY id DESC
                """,
            )
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def export_attack_data(self):
        try:
            return self._export_query(
                "attack_dataset",
                [
                    "attack_time", "attack_type", "source_ip", "source",
                    "target", "severity", "description", "impact",
                ],
                """
                SELECT attack_time, attack_type, source_ip, source, target,
                       severity, description, impact
                FROM attacks
                ORDER BY id DESC
                """,
            )
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def export_events(self):
        try:
            return self._export_query(
                "events_export",
                ["event_time", "user", "role", "event_type", "description", "severity"],
                """
                SELECT event_time, user, role, event_type, description, severity
                FROM event_logs
                ORDER BY id DESC
                """,
            )
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}
