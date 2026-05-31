class RiskEngine:
    def calculate_risk(
        self,
        sensor_data,
        ai_result,
        attack=None,
        threat_intel=None,
        mitre=None,
        firewall_blocked=False
    ):
        risk = 0
        factors = []

        sensor_data = sensor_data or {}
        ai_result = ai_result or {}

        # AI Score
        ai_score = ai_result.get("score", 0)
        risk += ai_score
        factors.append(f"AI Score: {ai_score}")

        ai_level = ai_result.get("threat_level", "UNKNOWN")

        if ai_level == "CRITICAL":
            risk += 20
            factors.append("AI Threat Level: CRITICAL")
        elif ai_level == "HIGH":
            risk += 12
            factors.append("AI Threat Level: HIGH")
        elif ai_level == "MEDIUM":
            risk += 5
            factors.append("AI Threat Level: MEDIUM")

        # Стан технологічного процесу
        status = sensor_data.get("system_status", "UNKNOWN")

        critical_statuses = [
            "CRITICAL",
            "PLC_ATTACK",
            "FAKE_SENSOR_ATTACK",
            "COOLING_FAILURE",
            "OVERLOAD"
        ]

        if status in critical_statuses:
            risk += 20
            factors.append(f"Критичний технологічний статус: {status}")

        if status == "SAFE_MODE":
            risk -= 15
            factors.append("SAFE_MODE активовано — ризик частково знижено")

        if status == "EMERGENCY_STOP":
            risk += 10
            factors.append("Активовано Emergency Stop — аварійний стан контрольований")

        # Додаткові технологічні параметри
        temperature = sensor_data.get("temperature", 0)
        pressure = sensor_data.get("pressure", 0)
        vibration = sensor_data.get("vibration", 0)
        water_level = sensor_data.get("water_level", 100)
        load_percent = sensor_data.get("load_percent", 0)

        if temperature > 600:
            risk += 10
            factors.append("Температура перевищує критичний рівень")

        if pressure > 17:
            risk += 10
            factors.append("Тиск перевищує критичний рівень")

        if vibration > 4.0:
            risk += 10
            factors.append("Критична вібрація турбіни")

        if water_level < 40:
            risk += 10
            factors.append("Критично низький рівень води")

        if load_percent > 105:
            risk += 10
            factors.append("Перевантаження ТЕЦ")

        # Тип атаки
        if attack:
            severity = attack.get("severity", "MEDIUM")

            if severity == "CRITICAL":
                risk += 25
            elif severity == "HIGH":
                risk += 18
            elif severity == "MEDIUM":
                risk += 10
            elif severity == "LOW":
                risk += 5

            factors.append(f"Рівень атаки: {severity}")

            attack_type = attack.get("attack_type", "UNKNOWN")
            factors.append(f"Тип атаки: {attack_type}")

        # Threat Intelligence
        if threat_intel:
            final_risk = threat_intel.get("final_risk", "UNKNOWN")
            ti_score = threat_intel.get("risk_score", 0)

            if final_risk == "HIGH":
                risk += 20
                factors.append("Threat Intelligence: HIGH risk")
            elif final_risk == "MEDIUM":
                risk += 10
                factors.append("Threat Intelligence: MEDIUM risk")

            if ti_score:
                risk += min(ti_score * 0.15, 15)
                factors.append(f"Threat Intel Risk Score: {ti_score}")

            if threat_intel.get("ip_listed"):
                risk += 15
                factors.append("IP знайдено у blacklist")

            if threat_intel.get("country_suspicious"):
                risk += 7
                factors.append("Країна джерела має підвищений ризик")

        # MITRE ATT&CK for ICS
        if mitre:
            tactic = mitre.get("tactic", "")
            impact_level = mitre.get("impact_level", "UNKNOWN")

            if "Impair Process Control" in tactic:
                risk += 20
                factors.append("MITRE: Impair Process Control")

            if "Impact" in tactic:
                risk += 15
                factors.append("MITRE: Impact")

            if "Inhibit Response Function" in tactic:
                risk += 18
                factors.append("MITRE: Inhibit Response Function")

            if impact_level == "CRITICAL":
                risk += 15
                factors.append("MITRE Impact Level: CRITICAL")
            elif impact_level == "HIGH":
                risk += 10
                factors.append("MITRE Impact Level: HIGH")
            elif impact_level == "MEDIUM":
                risk += 5
                factors.append("MITRE Impact Level: MEDIUM")

        # Firewall
        if firewall_blocked:
            risk -= 15
            factors.append("Firewall заблокував IP — ризик знижено")
        elif attack:
            risk += 10
            factors.append("Firewall не заблокував атаку — ризик підвищено")

        risk = max(0, min(risk, 100))

        if risk < 25:
            level = "LOW"
            recommendation = "Достатньо стандартного моніторингу."
            category = "Низький операційний ризик"
        elif risk < 50:
            level = "MEDIUM"
            recommendation = "Потрібен посилений моніторинг і перевірка журналів."
            category = "Помірний кіберопераційний ризик"
        elif risk < 75:
            level = "HIGH"
            recommendation = "Рекомендовано активувати захисні дії та перевірити PLC/SCADA канал."
            category = "Високий ризик для технологічного процесу"
        else:
            level = "CRITICAL"
            recommendation = "Негайно активувати захист, ізолювати PLC-сегмент і перевести систему у Safe Mode."
            category = "Критичний ризик для OT/ICS"

        if not factors:
            factors.append("Факторів ризику не виявлено")

        return {
            "risk_score": round(risk, 2),
            "risk_level": level,
            "risk_category": category,
            "factors": factors,
            "recommendation": recommendation
        }