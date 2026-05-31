import os
import json
import csv
from datetime import datetime


class IncidentReportGenerator:
    """Creates diploma-friendly incident reports in TXT, HTML, JSON and CSV formats."""

    def __init__(self):
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_report(self, sensor_data=None, ai_result=None, attack=None, defense_engine=None, risk_result=None, incident=None, **kwargs):
        return self.generate_incident_report(sensor_data, ai_result, attack, defense_engine, risk_result, incident, **kwargs)

    def export_report(self, *args, **kwargs):
        return self.generate_incident_report(*args, **kwargs)

    def _defense_status(self, defense_engine):
        if not defense_engine:
            return {"safe_mode": False, "isolated_plc": False, "load_reduced": False, "blocked_ips": []}
        return {
            "safe_mode": getattr(defense_engine, "safe_mode", False),
            "isolated_plc": getattr(defense_engine, "isolated_plc", False),
            "load_reduced": getattr(defense_engine, "load_reduced", False),
            "blocked_ips": getattr(defense_engine, "blocked_ips", []),
        }

    def generate_incident_report(self, sensor_data=None, ai_result=None, attack=None, defense_engine=None, risk_result=None, incident=None, timeline=None, soar_actions=None, live_analytics=None):
        ts_file = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        ts_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        base = os.path.join(self.report_dir, f"incident_report_{ts_file}")

        sensor_data = sensor_data or {}
        ai_result = ai_result or {}
        attack = attack or {}
        risk_result = risk_result or {}
        incident = incident or {}
        timeline = timeline or []
        soar_actions = soar_actions or []
        live_analytics = live_analytics or {}
        defense_status = self._defense_status(defense_engine)

        payload = {
            "generated_at": ts_human,
            "sensor_data": sensor_data,
            "attack": attack,
            "ai_result": ai_result,
            "risk_result": risk_result,
            "incident": incident,
            "defense_status": defense_status,
            "timeline": timeline,
            "soar_actions": soar_actions,
            "digital_twin": live_analytics,
        }

        txt_path = base + ".txt"
        html_path = base + ".html"
        json_path = base + ".json"
        csv_path = base + ".csv"

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(self._txt(payload))
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(self._html(payload))
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow(["section", "key", "value"])
            for section, obj in payload.items():
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        writer.writerow([section, k, v])
                else:
                    writer.writerow([section, "value", obj])
        return txt_path

    def _list_text(self, items):
        if not items:
            return "- немає даних"
        if isinstance(items, str):
            return "- " + items
        return "\n".join([f"- {x}" for x in items])

    def _txt(self, p):
        s = p["sensor_data"]; a = p["attack"]; ai = p["ai_result"]; r = p["risk_result"]; inc = p["incident"]; d = p["defense_status"]; la = p["digital_twin"]
        timeline_text = "\n".join([str(x) for x in p.get("timeline", [])[-10:]]) or "- немає"
        actions = []
        for x in p.get("soar_actions", [])[-10:]:
            if isinstance(x, dict):
                actions.append("; ".join(x.get("actions", [])))
            else:
                actions.append(str(x))
        actions_text = self._list_text(actions)
        return f"""
============================================================
AI SCADA CYBER DEFENSE SYSTEM — INCIDENT REPORT
============================================================
Дата і час формування: {p['generated_at']}

1. ПОТОЧНИЙ СТАН ТЕЦ / DIGITAL TWIN
Температура: {s.get('temperature','N/A')} °C
Тиск: {s.get('pressure','N/A')} МПа
Оберти турбіни: {s.get('turbine_rpm','N/A')} RPM
Генерація: {s.get('power_output','N/A')} MW
Вібрація: {s.get('vibration','N/A')} mm/s
Рівень води: {s.get('water_level','N/A')} %
Навантаження: {s.get('load_percent','N/A')} %
Статус системи: {s.get('system_status','UNKNOWN')}
Digital Twin anomaly score: {la.get('anomaly_score','N/A')}

2. ІНЦИДЕНТ
Рівень інциденту: {inc.get('incident_level','UNKNOWN')}
Оцінка інциденту: {inc.get('incident_score','N/A')}
Ознаки:
{self._list_text(inc.get('findings', []))}

3. АТАКА / MITRE ICS
Тип атаки: {a.get('attack_type','не зафіксовано')}
Джерело IP: {a.get('source_ip','N/A')}
Джерело: {a.get('source','N/A')}
Ціль: {a.get('target','N/A')}
Рівень: {a.get('severity','N/A')}
MITRE ICS: {a.get('mitre_technique','N/A')} {a.get('mitre_id','')}
Опис: {a.get('description','N/A')}
Вплив: {a.get('impact','N/A')}

4. AI АНАЛІЗ
AI Score: {ai.get('score','N/A')}
AI Confidence: {ai.get('confidence','N/A')}%
Threat Level: {ai.get('threat_level','N/A')}
Причини:
{self._list_text(ai.get('reasons', []))}
Рекомендація: {ai.get('recommendation','N/A')}

5. ОЦІНКА РИЗИКУ
Risk Score: {r.get('risk_score','N/A')}
Risk Level: {r.get('risk_level','N/A')}
Фактори:
{self._list_text(r.get('factors', []))}

6. ДІЇ ЗАХИСТУ / SOAR
SAFE MODE: {d.get('safe_mode')}
PLC ізольовано: {d.get('isolated_plc')}
Навантаження знижено: {d.get('load_reduced')}
Заблоковані IP: {', '.join(d.get('blocked_ips', [])) if d.get('blocked_ips') else 'немає'}
SOAR actions:
{actions_text}

7. EVENT TIMELINE
{timeline_text}

8. ВИСНОВОК
Система зафіксувала кіберфізичну подію, виконала AI-аналіз, кореляцію,
ризик-скоринг та сформувала рекомендації/дії реагування для OT/ICS середовища.
============================================================
END OF REPORT
============================================================
""".strip()

    def _badge(self, value):
        v = str(value).upper()
        color = "#22c55e"
        if "CRIT" in v or "HIGH" in v:
            color = "#ef4444"
        elif "WARN" in v or "MED" in v:
            color = "#facc15"
        return f'<span class="badge" style="color:{color};border-color:{color}">{value}</span>'

    def _kv(self, data):
        return "".join([f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data.items()])

    def _html(self, p):
        s = p["sensor_data"]; a = p["attack"]; ai = p["ai_result"]; r = p["risk_result"]; inc = p["incident"]; d = p["defense_status"]
        timeline = "\n".join([str(x) for x in p.get("timeline", [])[-20:]]) or "- немає"
        findings = self._list_text(inc.get('findings', []))
        ai_table = self._kv({'Threat Level': self._badge(ai.get('threat_level','N/A')), 'AI Score': ai.get('score','N/A'), 'Confidence': str(ai.get('confidence','N/A'))+'%', 'Recommendation': ai.get('recommendation','N/A')})
        risk_table = self._kv({'Risk Level': self._badge(r.get('risk_level','N/A')), 'Risk Score': r.get('risk_score','N/A'), 'Incident Level': self._badge(inc.get('incident_level','N/A')), 'Incident Score': inc.get('incident_score','N/A')})
        return f'''<!DOCTYPE html><html lang="uk"><head><meta charset="UTF-8"><title>AI SCADA Incident Report</title>
<style>
body{{margin:0;background:#020617;color:#e5e7eb;font-family:Arial, sans-serif}}.wrap{{padding:28px;max-width:1180px;margin:auto}}
h1{{color:#38bdf8}}h2{{color:#22c55e;border-bottom:1px solid #164e63;padding-bottom:6px}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
.card{{background:#0f172a;border:1px solid #164e63;border-radius:14px;padding:16px;box-shadow:0 0 20px rgba(56,189,248,.08)}}
table{{width:100%;border-collapse:collapse}}td{{border-bottom:1px solid #1e293b;padding:8px}}td:first-child{{color:#93c5fd;font-weight:bold;width:35%}}
.badge{{display:inline-block;padding:6px 10px;border:1px solid;border-radius:999px;font-weight:bold}}.small{{color:#94a3b8}}pre{{white-space:pre-wrap;background:#020617;border:1px solid #1e293b;padding:12px;border-radius:12px}}
@media print{{body{{background:white;color:black}}.card{{border:1px solid #aaa;box-shadow:none}}}}
</style></head><body><div class="wrap">
<h1>AI SCADA Cyber Defense System — Incident Report</h1><p class="small">Generated: {p['generated_at']}</p>
<div class="grid">
<div class="card"><h2>Plant / Digital Twin</h2><table>{self._kv(s)}</table></div>
<div class="card"><h2>AI Decision</h2><table>{ai_table}</table></div>
<div class="card"><h2>Attack / MITRE ICS</h2><table>{self._kv(a)}</table></div>
<div class="card"><h2>Risk & Incident</h2><table>{risk_table}</table></div>
<div class="card"><h2>SOAR Defense</h2><table>{self._kv(d)}</table></div>
<div class="card"><h2>Findings</h2><pre>{findings}</pre></div>
</div>
<div class="card" style="margin-top:18px"><h2>Timeline</h2><pre>{timeline}</pre></div>
</div></body></html>'''
