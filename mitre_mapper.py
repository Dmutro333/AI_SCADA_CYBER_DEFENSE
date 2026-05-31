class MITREMapper:
    def __init__(self):
        self.mapping = {
            "DDoS": {
                "tactic": "Impact",
                "technique": "Denial of Control / Denial of View",
                "technique_id": "ICS-T0813 / ICS-T0829",
                "impact_level": "HIGH",
                "description": "Порушення доступності SCADA/HMI або каналів керування.",
                "detection_hint": "Різке зростання кількості запитів до SCADA Server, затримки HMI, таймаути.",
                "mitigation": "Фільтрація трафіку, rate limiting, firewall/IPS, сегментація мережі."
            },
            "Modbus Command Injection": {
                "tactic": "Impair Process Control",
                "technique": "Unauthorized Command Message",
                "technique_id": "ICS-T0855",
                "impact_level": "CRITICAL",
                "description": "Надсилання несанкціонованих команд до PLC.",
                "detection_hint": "Поява нетипових Modbus function codes, write-команди до критичних регістрів.",
                "mitigation": "Whitelist дозволених команд, контроль PLC-регістрів, ізоляція PLC-сегмента."
            },
            "Fake Sensor Data Injection": {
                "tactic": "Impair Process Control",
                "technique": "Spoof Reporting Message",
                "technique_id": "ICS-T0856",
                "impact_level": "CRITICAL",
                "description": "Підміна телеметрії для приховування реального стану процесу.",
                "detection_hint": "Невідповідність між фізичною моделлю Digital Twin і показниками HMI.",
                "mitigation": "Перехресна перевірка телеметрії, Digital Twin, контроль джерела даних."
            },
            "Replay Attack": {
                "tactic": "Evasion / Impair Process Control",
                "technique": "Replay Communication",
                "technique_id": "ICS-T0830",
                "impact_level": "MEDIUM",
                "description": "Повтор раніше перехоплених легітимних команд або повідомлень.",
                "detection_hint": "Повторення однакових пакетів, часові аномалії, неактуальні команди.",
                "mitigation": "Timestamp validation, nonce/session control, контроль послідовності команд."
            },
            "PLC Manipulation": {
                "tactic": "Inhibit Response Function",
                "technique": "Modify Controller Tasking",
                "technique_id": "ICS-T0821",
                "impact_level": "CRITICAL",
                "description": "Зміна логіки або параметрів керування PLC.",
                "detection_hint": "Несподівані зміни стану PLC, аномальні команди, різка зміна технологічних параметрів.",
                "mitigation": "Контроль цілісності PLC-логіки, ізоляція контролера, резервна конфігурація."
            },

            "MITM Attack": {
                "tactic": "Evasion / Collection",
                "technique": "Man-in-the-Middle",
                "technique_id": "ICS-T0830 / ICS-T0842",
                "impact_level": "HIGH",
                "description": "Перехоплення або модифікація трафіку між SCADA та PLC.",
                "detection_hint": "ARP spoofing, duplicate MAC, нетиповий шлюз, затримки та розбіжності телеметрії.",
                "mitigation": "Сегментація, контроль ARP/MAC, whitelist вузлів, захищені канали зв'язку."
            },
            "Unauthorized Modbus Write": {
                "tactic": "Impair Process Control",
                "technique": "Unauthorized Command Message",
                "technique_id": "ICS-T0855",
                "impact_level": "CRITICAL",
                "description": "Запис у критичні Modbus-регістри без дозволу.",
                "detection_hint": "Function Code 16/06 до критичних регістрів з неавторизованого IP.",
                "mitigation": "Modbus whitelist, ізоляція PLC, блокування IP, перевірка уставок."
            },
            "Brute Force SCADA Login": {
                "tactic": "Initial Access",
                "technique": "Valid Accounts / Brute Force",
                "technique_id": "ICS-T0859",
                "impact_level": "MEDIUM",
                "description": "Спроба підібрати пароль до SCADA/HMI.",
                "detection_hint": "Багато невдалих входів, password spraying, спроби доступу до admin-ролі.",
                "mitigation": "Блокування IP, складні паролі, MFA, RBAC, журналювання входів."
            },
            "Coordinated Turbine Sabotage": {
                "tactic": "Impair Process Control / Inhibit Response Function / Impact",
                "technique": "Modify Controller Tasking + Spoof Reporting Message",
                "technique_id": "ICS-T0821 / ICS-T0856",
                "impact_level": "CRITICAL",
                "description": "Комбінований кіберфізичний сценарій проти контуру керування турбіною.",
                "detection_hint": "PLC write + підміна телеметрії + зростання вібрації/RPM/навантаження.",
                "mitigation": "SAFE_MODE, ізоляція PLC, зниження навантаження, ручна інженерна перевірка."
            },
            "Database Attack": {
                "tactic": "Collection / Impact",
                "technique": "Data Manipulation",
                "technique_id": "ICS-T0831",
                "impact_level": "HIGH",
                "description": "Спроба зміни або видалення журналів подій і сенсорних даних.",
                "detection_hint": "Нетипові запити до БД, спроби видалення/зміни журналів, порушення цілісності audit trail.",
                "mitigation": "Backup, контроль доступу до БД, audit trail, обмеження прав користувачів."
            }
        }

    def map_attack(self, attack_type):
        return self.mapping.get(attack_type, {
            "tactic": "Unknown",
            "technique": "Unknown",
            "technique_id": "Unknown",
            "impact_level": "UNKNOWN",
            "description": "Для цього типу атаки відповідність MITRE не визначена.",
            "detection_hint": "Потрібен ручний аналіз журналів та мережевого трафіку.",
            "mitigation": "Рекомендовано виконати базову перевірку системи та журналів."
        })

    def get_all_mappings(self):
        return self.mapping