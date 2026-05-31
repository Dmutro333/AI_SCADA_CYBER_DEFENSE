from config import THRESHOLDS


class AlertRulesEngine:
    def evaluate(self, sensor_data, ai_result=None, risk_result=None):
        alerts = []

        sensor_data = sensor_data or {}

        temperature = sensor_data.get("temperature", 0)
        pressure = sensor_data.get("pressure", 0)
        turbine_rpm = sensor_data.get("turbine_rpm", 0)
        vibration = sensor_data.get("vibration", 0)
        water_level = sensor_data.get("water_level", 100)
        load_percent = sensor_data.get("load_percent", 0)
        status = sensor_data.get("system_status", "UNKNOWN")

        # Температура
        if temperature > THRESHOLDS["temperature_critical"]:
            alerts.append((
                "Критична температура",
                f"Температура {temperature} °C перевищила критичний поріг {THRESHOLDS['temperature_critical']} °C",
                "CRITICAL"
            ))
        elif temperature > THRESHOLDS["temperature_warning"]:
            alerts.append((
                "Висока температура",
                f"Температура {temperature} °C перевищила warning-поріг {THRESHOLDS['temperature_warning']} °C",
                "WARNING"
            ))

        # Тиск
        if pressure > THRESHOLDS["pressure_critical"]:
            alerts.append((
                "Критичний тиск",
                f"Тиск {pressure} МПа перевищив критичний поріг {THRESHOLDS['pressure_critical']} МПа",
                "CRITICAL"
            ))
        elif pressure > THRESHOLDS["pressure_warning"]:
            alerts.append((
                "Підвищений тиск",
                f"Тиск {pressure} МПа перевищив warning-поріг {THRESHOLDS['pressure_warning']} МПа",
                "WARNING"
            ))

        # Оберти турбіни
        if turbine_rpm > THRESHOLDS["rpm_critical"]:
            alerts.append((
                "Критичні оберти турбіни",
                f"Оберти {turbine_rpm} RPM перевищили критичний поріг {THRESHOLDS['rpm_critical']} RPM",
                "CRITICAL"
            ))
        elif turbine_rpm > THRESHOLDS["rpm_warning"]:
            alerts.append((
                "Підвищені оберти турбіни",
                f"Оберти {turbine_rpm} RPM перевищили warning-поріг {THRESHOLDS['rpm_warning']} RPM",
                "WARNING"
            ))

        # Вібрація
        if vibration > THRESHOLDS["vibration_critical"]:
            alerts.append((
                "Критична вібрація",
                f"Вібрація {vibration} mm/s перевищила критичний поріг {THRESHOLDS['vibration_critical']} mm/s",
                "CRITICAL"
            ))
        elif vibration > THRESHOLDS["vibration_warning"]:
            alerts.append((
                "Підвищена вібрація",
                f"Вібрація {vibration} mm/s перевищила warning-поріг {THRESHOLDS['vibration_warning']} mm/s",
                "WARNING"
            ))

        # Рівень води
        if water_level < THRESHOLDS["water_critical"]:
            alerts.append((
                "Критично низький рівень води",
                f"Рівень води {water_level}% нижче критичного порогу {THRESHOLDS['water_critical']}%",
                "CRITICAL"
            ))
        elif water_level < THRESHOLDS["water_warning"]:
            alerts.append((
                "Знижений рівень води",
                f"Рівень води {water_level}% нижче warning-порогу {THRESHOLDS['water_warning']}%",
                "WARNING"
            ))

        # Навантаження
        if load_percent > THRESHOLDS["load_critical"]:
            alerts.append((
                "Критичне навантаження",
                f"Навантаження {load_percent}% перевищило критичний поріг {THRESHOLDS['load_critical']}%",
                "CRITICAL"
            ))
        elif load_percent > THRESHOLDS["load_warning"]:
            alerts.append((
                "Високе навантаження",
                f"Навантаження {load_percent}% перевищило warning-поріг {THRESHOLDS['load_warning']}%",
                "WARNING"
            ))

        # Статуси Digital Twin
        if status in ["PLC_ATTACK", "FAKE_SENSOR_ATTACK"]:
            alerts.append((
                "Ознаки кібератаки",
                f"Digital Twin зафіксував стан: {status}",
                "CRITICAL"
            ))

        if status in ["COOLING_FAILURE", "OVERLOAD"]:
            alerts.append((
                "Аварійний сценарій Digital Twin",
                f"Зафіксовано аварійний режим: {status}",
                "CRITICAL"
            ))

        if status == "EMERGENCY_STOP":
            alerts.append((
                "Emergency Stop",
                "ТЕЦ переведено у режим аварійного зупинення",
                "CRITICAL"
            ))

        if status == "SAFE_MODE":
            alerts.append((
                "Safe Mode",
                "Система переведена у безпечний режим SAFE_MODE",
                "INFO"
            ))

        # AI
        if ai_result and ai_result.get("threat_level") in ["HIGH", "CRITICAL"]:
            alerts.append((
                "AI Threat Alert",
                f"AI визначив рівень загрози: {ai_result['threat_level']}",
                ai_result["threat_level"]
            ))

        # Risk
        if risk_result and risk_result.get("risk_level") in ["HIGH", "CRITICAL"]:
            alerts.append((
                "Risk Alert",
                f"Risk Engine визначив ризик: {risk_result['risk_level']}",
                risk_result["risk_level"]
            ))

        return alerts