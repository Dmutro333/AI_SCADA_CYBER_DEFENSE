class ThreatIntelligence:
    def __init__(self):
        self.blacklisted_ips = {
            "185.220.101.45": {
                "description": "TOR Exit Node / high-risk anonymizer",
                "tags": ["TOR", "ANONYMIZER", "HIGH_RISK"]
            },
            "45.155.205.233": {
                "description": "Known botnet infrastructure",
                "tags": ["BOTNET", "MALWARE_INFRA"]
            },
            "193.29.13.44": {
                "description": "APT-like infrastructure",
                "tags": ["APT", "ICS_TARGETING"]
            }
        }

        self.suspicious_attack_types = {
            "Modbus Command Injection": {
                "risk": "HIGH",
                "description": "Несанкціоновані команди до PLC є критичними для OT/ICS."
            },
            "Fake Sensor Data Injection": {
                "risk": "HIGH",
                "description": "Підміна телеметрії може приховати аварійний стан."
            },
            "PLC Manipulation": {
                "risk": "HIGH",
                "description": "Зміна логіки PLC може вплинути на фізичний процес."
            },
            "Database Attack": {
                "risk": "HIGH",
                "description": "Атака на БД може знищити або підмінити журнали подій."
            },
            "Replay Attack": {
                "risk": "MEDIUM",
                "description": "Повтор старих команд може порушити логіку керування."
            },
            "DDoS": {
                "risk": "MEDIUM",
                "description": "DDoS впливає на доступність SCADA/HMI."
            }
        }

        self.suspicious_countries = {
            "Unknown": "Невідоме походження джерела",
            "Russia": "Підвищений ризик для критичної інфраструктури України",
            "Belarus": "Підвищений ризик для критичної інфраструктури України"
        }

        self.apt_profiles = {
            "Industroyer-like": {
                "keywords": ["IEC", "Replay Attack", "PLC", "SCADA", "control"],
                "description": "Сценарій схожий на атаки проти енергетичної інфраструктури з фокусом на протоколи керування."
            },
            "Triton-like": {
                "keywords": ["PLC Manipulation", "logic_download", "unauthorized_task_change", "SAFE_MODE"],
                "description": "Ознаки втручання у логіку контролера або safety-related процес."
            },
            "Stuxnet-like": {
                "keywords": ["Fake Sensor", "telemetry_spoofing", "turbine", "vibration", "RPM"],
                "description": "Ознаки прихованої кіберфізичної маніпуляції з підміною телеметрії."
            },
            "BlackEnergy-like": {
                "keywords": ["DDoS", "SCADA", "Database Attack", "audit_log_tampering"],
                "description": "Ознаки комбінованої атаки на доступність, журнали та операторську інфраструктуру."
            }
        }

    def check_ip(self, ip):
        if ip in self.blacklisted_ips:
            item = self.blacklisted_ips[ip]

            return {
                "listed": True,
                "risk": "HIGH",
                "description": item["description"],
                "tags": item["tags"]
            }

        return {
            "listed": False,
            "risk": "UNKNOWN",
            "description": "IP не знайдено у локальній threat intelligence базі",
            "tags": []
        }

    def check_attack_type(self, attack_type):
        if attack_type in self.suspicious_attack_types:
            item = self.suspicious_attack_types[attack_type]

            return {
                "suspicious": True,
                "risk": item["risk"],
                "description": item["description"]
            }

        return {
            "suspicious": False,
            "risk": "LOW",
            "description": "Тип атаки не входить до критичних IOC, але потребує моніторингу."
        }

    def check_country(self, country):
        if country in self.suspicious_countries:
            return {
                "suspicious": True,
                "risk": "MEDIUM",
                "description": self.suspicious_countries[country]
            }

        return {
            "suspicious": False,
            "risk": "LOW",
            "description": "Країна джерела не входить до локального списку підвищеного ризику."
        }

    def compare_apt_similarity(self, attack):
        text = " ".join([
            str(attack.get("attack_type", "")),
            str(attack.get("target", "")),
            str(attack.get("target_component", "")),
            str(attack.get("protocol", "")),
            str(attack.get("description", "")),
            str(attack.get("impact", "")),
            " ".join(attack.get("network_indicators", [])),
            str(attack.get("process_effect", "")),
        ]).lower()

        best_name = "Generic ICS intrusion"
        best_score = 25
        best_description = "Загальний профіль OT/ICS інциденту без чіткої прив’язки до відомої кампанії."
        for name, profile in self.apt_profiles.items():
            hits = 0
            for keyword in profile["keywords"]:
                if keyword.lower() in text:
                    hits += 1
            score = min(95, int((hits / max(1, len(profile["keywords"]))) * 100))
            if score > best_score:
                best_name = name
                best_score = score
                best_description = profile["description"]
        return {"name": best_name, "score": best_score, "description": best_description}

    def analyze_attack(self, attack):
        source_ip = attack.get("source_ip", "UNKNOWN")
        attack_type = attack.get("attack_type", "UNKNOWN")
        country = attack.get("country", "Unknown")

        ip_result = self.check_ip(source_ip)
        type_result = self.check_attack_type(attack_type)
        country_result = self.check_country(country)

        risk_score = 0

        if ip_result["listed"]:
            risk_score += 40

        if type_result["suspicious"]:
            risk_score += 35

        if country_result["suspicious"]:
            risk_score += 15

        if attack.get("severity") == "CRITICAL":
            risk_score += 20
        elif attack.get("severity") == "HIGH":
            risk_score += 15
        elif attack.get("severity") == "MEDIUM":
            risk_score += 10

        risk_score = min(risk_score, 100)

        if risk_score >= 75:
            final_risk = "HIGH"
            recommendation = "Рекомендовано блокувати IP, перевірити PLC/SCADA канал та активувати посилений моніторинг."
        elif risk_score >= 40:
            final_risk = "MEDIUM"
            recommendation = "Рекомендовано моніторинг, перевірка журналів і контроль повторних спроб."
        else:
            final_risk = "LOW"
            recommendation = "Критичних IOC не виявлено, достатньо стандартного моніторингу."

        apt_similarity = self.compare_apt_similarity(attack)

        return {
            "source_ip": source_ip,
            "attack_type": attack_type,
            "country": country,
            "final_risk": final_risk,
            "risk_score": risk_score,

            "ip_listed": ip_result["listed"],
            "ip_description": ip_result["description"],
            "ip_tags": ip_result["tags"],

            "attack_suspicious": type_result["suspicious"],
            "attack_description": type_result["description"],

            "country_suspicious": country_result["suspicious"],
            "country_description": country_result["description"],

            "recommendation": recommendation,
            "apt_similarity": apt_similarity
        }