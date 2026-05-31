import os
import json
import random
from datetime import datetime
from string import Template


class AttackMapGenerator:
    """
    Real-world SOC / Cyber Command map generator for AI SCADA Cyber Defense Platform.
    Uses Leaflet + CartoDB dark tiles, so the browser needs Internet for the real map.
    """

    def __init__(self):
        self.map_dir = "maps"
        os.makedirs(self.map_dir, exist_ok=True)

    def generate_map(self, attacks=None):
        return self.generate_attack_map_html(attacks)

    def generate_attack_map(self, attacks=None):
        return self.generate_attack_map_html(attacks)

    def create_map(self, attacks=None):
        return self.generate_attack_map_html(attacks)

    def _safe(self, value, default="—"):
        if value is None:
            return default
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _severity_color(self, severity):
        return {
            "LOW": "#22c55e",
            "MEDIUM": "#eab308",
            "HIGH": "#f97316",
            "CRITICAL": "#ef4444",
            "WARNING": "#eab308",
        }.get(str(severity).upper(), "#38bdf8")

    def _coords(self, location):
        loc = str(location or "").lower()
        known = {
            "kyiv": (50.45, 30.52), "ukraine": (50.45, 30.52),
            "bucharest": (44.43, 26.10), "romania": (44.43, 26.10),
            "berlin": (52.52, 13.40), "germany": (52.52, 13.40),
            "warsaw": (52.23, 21.01), "poland": (52.23, 21.01),
            "singapore": (1.35, 103.82),
            "moscow": (55.75, 37.62), "russia": (55.75, 37.62),
            "beijing": (39.90, 116.40), "china": (39.90, 116.40),
            "new york": (40.71, -74.00), "usa": (38.90, -77.04), "united states": (38.90, -77.04),
            "amsterdam": (52.37, 4.90), "netherlands": (52.37, 4.90),
            "london": (51.51, -0.12), "uk": (51.51, -0.12), "united kingdom": (51.51, -0.12),
            "paris": (48.86, 2.35), "france": (48.86, 2.35),
            "istanbul": (41.01, 28.97), "turkey": (41.01, 28.97),
            "tokyo": (35.69, 139.69), "japan": (35.69, 139.69),
            "tehran": (35.69, 51.39), "iran": (35.69, 51.39),
            "pyongyang": (39.03, 125.75), "north korea": (39.03, 125.75),
            "seoul": (37.56, 126.97), "south korea": (37.56, 126.97),
            "stockholm": (59.33, 18.06), "sweden": (59.33, 18.06),
            "madrid": (40.42, -3.70), "spain": (40.42, -3.70),
            "rome": (41.90, 12.50), "italy": (41.90, 12.50),
        }
        for key, value in known.items():
            if key in loc:
                return value
        return 52.52, 13.40

    def _demo_background_attacks(self):
        pool = [
            ("Moscow, Russia", "91.203.144.12", "PLC Recon", "HIGH", "ICS-T0846"),
            ("Beijing, China", "103.77.14.88", "Modbus Probe", "MEDIUM", "ICS-T0861"),
            ("Tehran, Iran", "185.147.214.9", "OPC UA Scan", "MEDIUM", "ICS-T0888"),
            ("Singapore", "176.113.115.77", "Credential Attempt", "HIGH", "ICS-T0812"),
            ("Amsterdam, Netherlands", "45.155.205.233", "SCADA Session Abuse", "HIGH", "ICS-T0859"),
            ("London, United Kingdom", "51.89.22.17", "HMI Access Attempt", "MEDIUM", "ICS-T0820"),
            ("Tokyo, Japan", "139.59.12.101", "Telemetry Replay", "MEDIUM", "ICS-T0855"),
            ("New York, United States", "198.51.100.23", "Engineering Workstation Probe", "HIGH", "ICS-T0843"),
            ("Warsaw, Poland", "203.0.113.77", "PLC Logic Read", "MEDIUM", "ICS-T0807"),
            ("Berlin, Germany", "185.220.101.45", "Unauthorized Modbus Write", "CRITICAL", "ICS-T0821"),
        ]
        random.shuffle(pool)
        result = []
        for loc, ip, name, sev, mitre in pool[:7]:
            result.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "name": name,
                "attack_type": name,
                "severity": sev,
                "source_ip": ip,
                "source_location": loc,
                "target": "Kyiv / TPP",
                "mitre": mitre,
            })
        return result

    def generate_attack_map_html(self, attacks=None):
        attacks = attacks or []
        if not attacks:
            attacks = [{
                "time": datetime.now().strftime("%H:%M:%S"),
                "name": "PLC Manipulation",
                "attack_type": "PLC Manipulation",
                "severity": "CRITICAL",
                "source_ip": "185.220.101.45",
                "source_location": "Berlin, Germany",
                "country": "Germany",
                "city": "Berlin",
                "target": "PLC Logic",
                "mitre": "ICS-T0821",
            }]

        latest = attacks[-1]
        visual_attacks = self._demo_background_attacks()
        visual_attacks.append(latest)

        severity = self._safe(latest.get("severity", "CRITICAL")).upper()
        sev_color = self._severity_color(severity)
        attack_name = self._safe(latest.get("attack_type", latest.get("name", "Unknown attack")))
        src_ip = self._safe(latest.get("source_ip", "UNKNOWN"))
        src_loc = self._safe(latest.get("source_location", f"{latest.get('city','Unknown')}, {latest.get('country','Unknown')}"))
        target = self._safe(latest.get("target", "Critical Infrastructure"))
        mitre = self._safe(latest.get("mitre", latest.get("mitre_technique", "ICS-T0821")))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        total = max(len(attacks), len(visual_attacks))
        critical_count = sum(1 for a in visual_attacks if str(a.get("severity", "")).upper() == "CRITICAL")
        high_count = sum(1 for a in visual_attacks if str(a.get("severity", "")).upper() == "HIGH")

        routes = []
        for idx, a in enumerate(visual_attacks):
            loc = self._safe(a.get("source_location", "Berlin, Germany"))
            lat, lon = self._coords(loc)
            sev = self._safe(a.get("severity", "MEDIUM")).upper()
            routes.append({
                "lat": lat,
                "lon": lon,
                "location": loc,
                "ip": self._safe(a.get("source_ip", "UNKNOWN")),
                "attack": self._safe(a.get("attack_type", a.get("name", "Unknown"))),
                "severity": sev,
                "mitre": self._safe(a.get("mitre", "ICS-T0821")),
                "color": self._severity_color(sev),
                "main": idx == len(visual_attacks) - 1,
            })

        feed_rows = []
        for a in visual_attacks[-12:][::-1]:
            sev = self._safe(a.get("severity", "MEDIUM")).upper()
            feed_rows.append({
                "severity": sev,
                "time": self._safe(a.get("time", now)),
                "attack": self._safe(a.get("attack_type", a.get("name", "Unknown"))),
                "source": self._safe(a.get("source_ip", "UNKNOWN")),
                "location": self._safe(a.get("source_location", "Unknown")),
                "target": self._safe(a.get("target", "UNKNOWN")),
                "mitre": self._safe(a.get("mitre", "ICS-T0821")),
                "color": self._severity_color(sev),
            })

        src_lat, src_lon = self._coords(src_loc)
        payload = {
            "severity": severity,
            "severityColor": sev_color,
            "attack": attack_name,
            "sourceIp": src_ip,
            "sourceLocation": src_loc,
            "target": target,
            "mitre": mitre,
            "time": now,
            "total": total,
            "critical": critical_count,
            "high": high_count,
            "source": {"lat": src_lat, "lon": src_lon},
            "destination": {"lat": 50.45, "lon": 30.52, "name": "Kyiv / TPP Critical Infrastructure"},
            "feed": feed_rows,
            "routes": routes,
        }
        payload_js = json.dumps(payload, ensure_ascii=False)

        html_template = Template(r'''<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI SCADA Cyber Command Center Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>
html,body{margin:0;height:100%;background:#020617;font-family:"Segoe UI",Arial,sans-serif;overflow:hidden;color:#e5e7eb}#map{position:absolute;inset:0;background:#020617}.leaflet-control-attribution{display:none!important}.leaflet-container{background:#020617}.scanlines{position:absolute;inset:0;pointer-events:none;z-index:700;opacity:.10;background:repeating-linear-gradient(to bottom,rgba(255,255,255,0) 0,rgba(255,255,255,0) 2px,rgba(34,211,238,.16) 3px,rgba(255,255,255,0) 4px)}.gridOverlay{position:absolute;inset:0;pointer-events:none;z-index:650;background-image:linear-gradient(rgba(34,211,238,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(34,211,238,.045) 1px,transparent 1px);background-size:42px 42px}.header{position:absolute;top:18px;left:22px;right:22px;z-index:900;display:flex;justify-content:space-between}.brand{width:470px;padding:15px 18px;border:1px solid rgba(34,211,238,.45);background:rgba(2,6,23,.84);box-shadow:0 0 35px rgba(34,211,238,.14);backdrop-filter:blur(6px)}.brand h1{margin:0;color:#22d3ee;font-size:21px;letter-spacing:2.8px;font-weight:900;text-transform:uppercase}.brand p{margin:7px 0 0;color:#94a3b8;font-size:12px}.status{width:260px;padding:13px 16px;border:1px solid $sev_color;background:rgba(15,23,42,.88);box-shadow:0 0 35px rgba(239,68,68,.18)}.status small{display:block;color:#94a3b8;font-size:10px;text-transform:uppercase}.status b{color:$sev_color;font-size:24px;letter-spacing:2px}.leftRail{position:absolute;left:22px;top:116px;bottom:88px;width:285px;z-index:850;display:flex;flex-direction:column;gap:12px}.rightRail{position:absolute;right:22px;top:116px;bottom:88px;width:390px;z-index:850;display:flex;flex-direction:column;gap:12px}.panel{border:1px solid rgba(56,189,248,.35);background:rgba(2,6,23,.84);box-shadow:0 0 30px rgba(0,0,0,.45);padding:14px;backdrop-filter:blur(6px)}.panel h2{margin:0 0 12px;color:#22d3ee;font-size:13px;letter-spacing:1.8px;text-transform:uppercase}.panel h2:before{content:"■ ";color:#22d3ee}.threatMatrix{display:grid;grid-template-columns:repeat(3,1fr);gap:7px}.cell{height:43px;border:1px solid rgba(56,189,248,.22);background:rgba(15,23,42,.72);padding:7px}.cell b{display:block;color:#94a3b8;font-size:9px;text-transform:uppercase}.cell span{display:block;margin-top:4px;color:#22d3ee;font-weight:900;font-size:14px}.kv{display:grid;grid-template-columns:92px 1fr;gap:8px 10px;font-size:12px}.kv b{color:#64748b;text-transform:uppercase;font-size:10px}.kv span{color:#e2e8f0}.killStep{display:grid;grid-template-columns:26px 1fr;align-items:center;gap:9px;padding:8px 0;border-bottom:1px solid rgba(148,163,184,.14);font-size:12px}.killStep .n{width:22px;height:22px;display:grid;place-items:center;border:1px solid $sev_color;color:$sev_color;font-size:10px}.incidentBadge{border-left:4px solid $sev_color;padding:11px 13px;background:rgba(239,68,68,.10);margin-bottom:12px}.incidentBadge .sev{color:$sev_color;font-weight:900;font-size:23px;letter-spacing:2px}.feed{flex:1;overflow:hidden}.feedItem{border-left:3px solid $sev_color;padding:8px 10px;margin:7px 0;background:rgba(15,23,42,.70);font-size:11px}.feedTop{display:flex;justify-content:space-between;color:#94a3b8;font-size:10px}.feedTitle{margin-top:4px;font-weight:900;color:#fff}.feedMeta{margin-top:4px;color:#94a3b8}.bottom{position:absolute;left:22px;right:22px;bottom:16px;height:58px;z-index:900;display:grid;grid-template-columns:repeat(8,1fr);border:1px solid rgba(56,189,248,.38);background:rgba(2,6,23,.88);backdrop-filter:blur(6px)}.metric{padding:10px 14px;border-right:1px solid rgba(56,189,248,.18)}.metric b{display:block;color:#64748b;font-size:10px;text-transform:uppercase}.metric span{display:block;margin-top:4px;color:#22d3ee;font-weight:900;font-size:16px}.centerTitle{position:absolute;left:330px;right:440px;top:106px;z-index:800;text-align:center;color:#94a3b8;font-size:12px;letter-spacing:2px;text-transform:uppercase;pointer-events:none}.centerTitle b{color:#22d3ee}.legendHint{position:absolute;left:330px;bottom:92px;z-index:850;color:rgba(148,163,184,.52);font-size:10px;letter-spacing:1px;text-transform:uppercase}.attackLabel{color:#f87171;font-weight:900;text-shadow:0 0 8px #000}.targetLabel{color:#22c55e;font-weight:900;text-shadow:0 0 8px #000}.pulseSource{width:18px;height:18px;background:var(--c);border:2px solid #fff;border-radius:50%;box-shadow:0 0 22px var(--c);animation:pulse 1.1s infinite}.pulseTarget{width:22px;height:22px;background:#22c55e;border:2px solid #fff;border-radius:50%;box-shadow:0 0 28px #22c55e;animation:pulse 1.3s infinite}.packet{width:8px;height:8px;background:#fff;border-radius:50%;box-shadow:0 0 14px #fff}@keyframes pulse{50%{transform:scale(1.65);opacity:.65}}.leaflet-popup-content-wrapper,.leaflet-popup-tip{background:rgba(2,6,23,.94);color:#e5e7eb;border:1px solid rgba(34,211,238,.35)}
</style></head><body><div id="map"></div><div class="gridOverlay"></div><div class="scanlines"></div><div class="header"><div class="brand"><h1>Cyber Command Center Map</h1><p>AI SCADA Cyber Defense · Real-world SOC/GEOINT visualization · Multi-source OT/ICS attacks</p></div><div class="status"><small>Current threat</small><b>$severity</b></div></div><div class="centerTitle">Global cyber telemetry · <b>$src_loc → Kyiv / TPP</b></div><div class="legendHint">Real map tiles require Internet. Multi-source attack routes are simulated for SOC demonstration.</div><div class="leftRail"><div class="panel"><h2>AI Detection</h2><div class="threatMatrix"><div class="cell"><b>Confidence</b><span>$confidence</span></div><div class="cell"><b>Anomaly</b><span>$anomaly</span></div><div class="cell"><b>SOAR</b><span>READY</span></div><div class="cell"><b>Protocol</b><span>MODBUS</span></div><div class="cell"><b>Asset</b><span>PLC</span></div><div class="cell"><b>Risk</b><span style="color:$sev_color">$severity</span></div></div></div><div class="panel"><h2>OT Kill Chain</h2><div class="killStep"><span class="n">01</span><span>Recon / exposed SCADA service</span></div><div class="killStep"><span class="n">02</span><span>Engineering workstation access</span></div><div class="killStep"><span class="n">03</span><span>PLC task / Modbus manipulation</span></div><div class="killStep"><span class="n">04</span><span>Physical process impact</span></div><div class="killStep"><span class="n">05</span><span>SOAR containment / safe mode</span></div></div><div class="panel"><h2>Threat Intel</h2><div class="kv"><b>Profile</b><span>Industroyer / Triton-like</span><b>MITRE</b><span>$mitre</span><b>IOCs</b><span>plc_write, logic_download</span><b>Sector</b><span>Energy / OT</span></div></div></div><div class="rightRail"><div class="panel"><h2>Live Incident</h2><div class="incidentBadge"><div class="sev">$severity</div></div><div class="kv"><b>Attack</b><span>$attack_name</span><b>Source IP</b><span>$src_ip</span><b>Origin</b><span>$src_loc</span><b>Target</b><span>$target</span><b>MITRE</b><span>$mitre</span><b>Time</b><span>$now</span></div></div><div class="panel feed"><h2>Live Threat Feed</h2><div id="feed"></div></div><div class="panel"><h2>SOAR Recommendation</h2><div class="kv"><b>Action 1</b><span>Isolate PLC segment</span><b>Action 2</b><span>Block source network</span><b>Action 3</b><span>Reduce turbine load</span><b>Action 4</b><span>Enable safe mode</span></div></div></div><div class="bottom"><div class="metric"><b>Total events</b><span>$total</span></div><div class="metric"><b>Critical</b><span>$critical_count</span></div><div class="metric"><b>High</b><span>$high_count</span></div><div class="metric"><b>Packets/sec</b><span id="pps">0</span></div><div class="metric"><b>AI/SOC</b><span>ACTIVE</span></div><div class="metric"><b>SOAR</b><span>ARMED</span></div><div class="metric"><b>Target</b><span>KYIV / TPP</span></div><div class="metric"><b>ICS Risk</b><span style="color:$sev_color">$severity</span></div></div><script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script><script>
const DATA=__PAYLOAD_JS__;const map=L.map('map',{zoomControl:false,attributionControl:false,worldCopyJump:true,preferCanvas:true}).setView([35,25],3);L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:18,minZoom:2}).addTo(map);setTimeout(function(){map.flyToBounds(DATA.routes.map(r=>[r.lat,r.lon]).concat([[DATA.destination.lat,DATA.destination.lon]]),{paddingTopLeft:[320,110],paddingBottomRight:[410,95],maxZoom:4,duration:1.0});},500);function divIcon(cls,color){return L.divIcon({className:'',html:'<div class="'+cls+'" style="--c:'+color+'"></div>',iconSize:[22,22],iconAnchor:[11,11]});}const dst=[DATA.destination.lat,DATA.destination.lon];L.marker(dst,{icon:divIcon('pulseTarget','#22c55e')}).addTo(map).bindPopup('<b style="color:#22c55e">Kyiv / TPP Critical Infrastructure</b><br>Protected OT/ICS object');L.marker(dst,{icon:L.divIcon({className:'targetLabel',html:'Kyiv / TPP',iconSize:[200,20],iconAnchor:[-18,28]})}).addTo(map);const packets=[];DATA.routes.forEach(function(r,index){const src=[r.lat,r.lon];L.marker(src,{icon:divIcon('pulseSource',r.color)}).addTo(map).bindPopup('<b style="color:'+r.color+'">'+r.attack+'</b><br>Source: '+r.ip+'<br>Origin: '+r.location+'<br>MITRE: '+r.mitre);L.marker(src,{icon:L.divIcon({className:'attackLabel',html:r.location,iconSize:[230,20],iconAnchor:[-18,28]})}).addTo(map);L.polyline([src,dst],{color:r.color,weight:r.main?4:2,opacity:r.main?.95:.42,dashArray:'10,13'}).addTo(map);L.polyline([src,dst],{color:r.color,weight:r.main?13:7,opacity:r.main?.16:.08}).addTo(map);for(let i=0;i<(r.main?6:2);i++){packets.push({marker:L.marker(src,{icon:divIcon('packet','#ffffff')}).addTo(map),src:src,dst:dst,offset:i*.17+index*.04});}});[{name:'Russia / Eastern Threat Cluster',lat:55.75,lon:37.62,r:650000,c:'#ef4444'},{name:'East Asia Threat Cluster',lat:39.90,lon:116.40,r:800000,c:'#f97316'},{name:'Middle East Threat Cluster',lat:35.69,lon:51.39,r:560000,c:'#eab308'}].forEach(function(z){L.circle([z.lat,z.lon],{radius:z.r,color:z.c,weight:1,opacity:.28,fillColor:z.c,fillOpacity:.055}).addTo(map).bindPopup(z.name);});const radar=[];[35000,70000,110000,160000,230000,320000].forEach(function(r){radar.push(L.circle(dst,{radius:r,color:'#22c55e',weight:1,opacity:.28,fillOpacity:0}).addTo(map));});function interp(a,b,u){return[a[0]+(b[0]-a[0])*u,a[1]+(b[1]-a[1])*u];}let tick=0;function animate(){tick++;packets.forEach(function(p){const u=((tick/150)+p.offset)%1;p.marker.setLatLng(interp(p.src,p.dst,u));});radar.forEach(function(c,i){c.setStyle({opacity:.14+Math.abs(Math.sin((tick+i*16)/28))*.28});});document.getElementById('pps').textContent=String(1200+Math.floor(Math.abs(Math.sin(tick/24))*1800));requestAnimationFrame(animate);}function renderFeed(){const feed=document.getElementById('feed');let html='';DATA.feed.forEach(function(row){html+='<div class="feedItem" style="border-left-color:'+row.color+'"><div class="feedTop"><b style="color:'+row.color+'">'+row.severity+'</b><span>'+row.time+'</span></div><div class="feedTitle">'+row.attack+'</div><div class="feedMeta">'+row.location+' / '+row.source+' → '+row.target+'</div></div>';});feed.innerHTML=html;}renderFeed();animate();
</script></body></html>''')

        confidence = "99%" if severity == "CRITICAL" else "74%"
        anomaly = "0.92" if severity == "CRITICAL" else "0.41"
        html = html_template.safe_substitute(
            sev_color=sev_color,
            severity=severity,
            src_loc=src_loc,
            confidence=confidence,
            anomaly=anomaly,
            mitre=mitre,
            attack_name=attack_name,
            src_ip=src_ip,
            target=target,
            now=now,
            total=total,
            critical_count=critical_count,
            high_count=high_count,
        )
        html = html.replace("__PAYLOAD_JS__", payload_js)

        path = os.path.join(self.map_dir, "attack_map.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path
