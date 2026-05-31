from datetime import datetime


class CorrelationEngine:
    def correlate(
        self,
        sensor_data=None,
        ai_result=None,
        attack=None,
        threat_intel=None,
        risk_result=None,
        defense_engine=None,
        mitre_result=None,
        firewall_blocked=False
    ):
        findings = []
        incident_score = 0
        incident_type = "OPERATIONAL_MONITORING"

        sensor_data = sensor_data or {}
        ai_result = ai_result or {}
        threat_intel = threat_intel or {}
        risk_result = risk_result or {}
        mitre_result = mitre_result or {}

        # 1. Кібератака
        if attack:
            attack_type = attack.get("attack_type", "UNKNOWN_ATTACK")
            severity = attack.get("severity", "MEDIUM")

            incident_score += 20
            findings.append(f"Зафіксовано кібератаку: {attack_type}")

            if severity == "CRITICAL":
                incident_score += 20
                findings.append("Рівень атаки: CRITICAL")
            elif severity == "HIGH":
                incident_score += 15
                findings.append("Рівень атаки: HIGH")
            elif severity == "MEDIUM":
                incident_score += 8
                findings.append("Рівень атаки: MEDIUM")

            incident_type = "CYBER_INCIDENT"

        # 2. Стан Digital Twin
        status = sensor_data.get("system_status", "UNKNOWN")

        if status not in ["NORMAL", "SAFE_MODE", "UNKNOWN"]:
            incident_score += 20
            findings.append(f"Аномальний технологічний стан: {status}")

            if attack:
                incident_type = "CYBER_PHYSICAL_INCIDENT"
            else:
                incident_type = "TECHNOLOGICAL_ANOMALY"

        if status == "SAFE_MODE":
            findings.append("Система перебуває у SAFE_MODE")

        if status == "EMERGENCY_STOP":
            incident_score += 15
            findings.append("Активовано аварійне зупинення EMERGENCY_STOP")
            incident_type = "EMERGENCY_EVENT"

        # 3. AI
        ai_level = ai_result.get("threat_level", "UNKNOWN")

        if ai_level in ["HIGH", "CRITICAL"]:
            incident_score += 25
            findings.append(f"AI визначив високий рівень загрози: {ai_level}")
        elif ai_level == "MEDIUM":
            incident_score += 10
            findings.append("AI визначив середній рівень загрози")

        # 4. Threat Intelligence
        if threat_intel:
            if threat_intel.get("final_risk") == "HIGH":
                incident_score += 15
                findings.append("Threat Intelligence підтвердив високий ризик джерела/атаки")

            if threat_intel.get("ip_listed"):
                incident_score += 10
                findings.append("IP-адреса знайдена у blacklist")

            if threat_intel.get("country_suspicious"):
                incident_score += 5
                findings.append("Країна джерела має підвищений ризик")

        # 5. Risk Engine
        risk_level = risk_result.get("risk_level", "UNKNOWN")

        if risk_level in ["HIGH", "CRITICAL"]:
            incident_score += 20
            findings.append(f"Risk Engine визначив ризик: {risk_level}")
        elif risk_level == "MEDIUM":
            incident_score += 8
            findings.append("Risk Engine визначив середній ризик")

        # 6. MITRE ATT&CK for ICS
        if mitre_result:
            tactic = mitre_result.get("tactic", "")
            impact_level = mitre_result.get("impact_level", "UNKNOWN")

            if tactic:
                findings.append(f"MITRE tactic: {tactic}")

            if impact_level == "CRITICAL":
                incident_score += 15
                findings.append("MITRE impact level: CRITICAL")
            elif impact_level == "HIGH":
                incident_score += 10
                findings.append("MITRE impact level: HIGH")

        # 7. Firewall
        if firewall_blocked:
            incident_score -= 10
            findings.append("Firewall заблокував джерело атаки — ризик частково знижено")
        elif attack:
            incident_score += 10
            findings.append("Firewall не заблокував атаку або був вимкнений")

        # 8. Defense Engine
        if defense_engine:
            if getattr(defense_engine, "safe_mode", False):
                findings.append("Захист активував SAFE_MODE")
                incident_score -= 5

            if getattr(defense_engine, "isolated_plc", False):
                findings.append("PLC-сегмент ізольовано")
                incident_score -= 5

            if getattr(defense_engine, "load_reduced", False):
                findings.append("Навантаження ТЕЦ знижено")
                incident_score -= 3

        incident_score = max(0, min(incident_score, 100))

        if incident_score < 30:
            incident_level = "LOW"
            recommendation = "Достатньо стандартного моніторингу."
        elif incident_score < 60:
            incident_level = "MEDIUM"
            recommendation = "Потрібна перевірка журналів, мережевого трафіку та стану PLC."
        elif incident_score < 85:
            incident_level = "HIGH"
            recommendation = "Рекомендовано активувати захист, перевірити PLC/SCADA канал і провести аналіз інциденту."
        else:
            incident_level = "CRITICAL"
            recommendation = "Негайно ізолювати PLC-сегмент, активувати Safe Mode та провести розслідування."

        confidence = min(60 + incident_score * 0.4, 99)

        if not findings:
            findings.append("Ознак комплексного інциденту не виявлено")

        return {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "incident_type": incident_type,
            "incident_level": incident_level,
            "incident_score": round(incident_score, 2),
            "confidence": round(confidence, 2),
            "findings": findings,
            "recommendation": recommendation
        }