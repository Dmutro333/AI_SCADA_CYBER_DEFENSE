from config import THRESHOLDS


class AIEngine:
    def __init__(self):
        self.last_result = None

    def analyze(self, sensor_data):
        score = 0
        reasons = []

        temperature = sensor_data.get("temperature", 0)
        pressure = sensor_data.get("pressure", 0)
        turbine_rpm = sensor_data.get("turbine_rpm", 0)
        power_output = sensor_data.get("power_output", 0)
        vibration = sensor_data.get("vibration", 0)
        water_level = sensor_data.get("water_level", 0)
        load_percent = sensor_data.get("load_percent", 0)
        status = sensor_data.get("system_status", "UNKNOWN")

        # Температура
        if temperature > THRESHOLDS["temperature_warning"]:
            score += 15
            reasons.append("Підвищена температура пари")

        if temperature > THRESHOLDS["temperature_critical"]:
            score += 20
            reasons.append("Критична температура пари")

        # Тиск
        if pressure > THRESHOLDS["pressure_warning"]:
            score += 15
            reasons.append("Підвищений тиск у системі")

        if pressure > THRESHOLDS["pressure_critical"]:
            score += 20
            reasons.append("Критичний тиск")

        # Оберти турбіни
        if turbine_rpm > THRESHOLDS["rpm_warning"]:
            score += 10
            reasons.append("Підвищені оберти турбіни")

        if turbine_rpm > THRESHOLDS["rpm_critical"]:
            score += 20
            reasons.append("Небезпечні оберти турбіни")

        # Вібрація
        if vibration > THRESHOLDS["vibration_warning"]:
            score += 15
            reasons.append("Підвищена вібрація")

        if vibration > THRESHOLDS["vibration_critical"]:
            score += 20
            reasons.append("Критична вібрація турбіни")

        # Рівень води
        if water_level < THRESHOLDS["water_warning"]:
            score += 15
            reasons.append("Знижений рівень води")

        if water_level < THRESHOLDS["water_critical"]:
            score += 20
            reasons.append("Критично низький рівень води")

        # Навантаження
        if load_percent > THRESHOLDS["load_warning"]:
            score += 10
            reasons.append("Високе навантаження ТЕЦ")

        if load_percent > THRESHOLDS["load_critical"]:
            score += 20
            reasons.append("Перевантаження ТЕЦ")

        # Кібератаки
        if status in ["PLC_ATTACK", "FAKE_SENSOR_ATTACK"]:
            score += 30
            reasons.append("Система зафіксувала ознаки кібератаки")

        # Аварійні сценарії Digital Twin
        if status in ["COOLING_FAILURE", "OVERLOAD"]:
            score += 25
            reasons.append("Digital Twin зафіксував аварійний сценарій")

        # Режими захисту
        if status == "SAFE_MODE":
            score = max(score - 20, 0)
            reasons.append("Система переведена у безпечний режим SAFE_MODE")

        if status == "EMERGENCY_STOP":
            score += 35
            reasons.append("Активовано аварійне зупинення EMERGENCY_STOP")

        # Ознака підміни датчиків
        if (
            temperature < 470
            and pressure < 11
            and water_level > 85
            and load_percent < 80
            and status not in ["SAFE_MODE", "EMERGENCY_STOP"]
        ):
            score += 25
            reasons.append(
                "Можлива підміна датчиків: показники виглядають занадто нормальними"
            )

        score = max(0, min(score, 100))

        if score < 25:
            threat_level = "LOW"
            recommendation = "Система працює у штатному режимі."
        elif score < 50:
            threat_level = "MEDIUM"
            recommendation = "Потрібен моніторинг параметрів та перевірка журналу подій."
        elif score < 75:
            threat_level = "HIGH"
            recommendation = "Рекомендовано обмежити навантаження та перевірити PLC/SCADA канал."
        else:
            threat_level = "CRITICAL"
            recommendation = "Негайно активувати режим захисту та ізолювати підозрілий сегмент."

        confidence = min(60 + score * 0.4, 99)

        if not reasons:
            reasons.append("Критичних відхилень не виявлено")

        self.last_result = {
            "score": round(score, 2),
            "confidence": round(confidence, 2),
            "threat_level": threat_level,
            "reasons": reasons,
            "recommendation": recommendation
        }

        return self.last_result