"""
Network Traffic Analyzer Live Dashboard
Author: Kadari Eshwar | B.Tech ECE, JNTU Hyderabad
Run: python run.py
"""
from flask import Flask, jsonify, render_template_string
import random, threading, time
from datetime import datetime
from collections import Counter, deque

app = Flask(__name__)
PROTOCOLS=["TCP","UDP","HTTP","HTTPS","DNS","ICMP","ARP"]
IPS=["192.168.1.5","192.168.1.10","10.0.0.1","172.16.0.5","8.8.8.8","142.250.1.1","52.94.236.1"]
PORTS={80:"HTTP",443:"HTTPS",53:"DNS",22:"SSH",25:"SMTP",3306:"MySQL",8080:"HTTP-Alt"}
stats={"total":0,"bytes":0,"protocols":Counter(),"ips":Counter(),"ports":Counter(),"alerts":[]}
recent=deque(maxlen=50)

def simulate():
    while True:
        for _ in range(random.randint(3,8)):
            proto=random.choice(PROTOCOLS); src=random.choice(IPS)
            dst=random.choice(IPS); port=random.choice(list(PORTS.keys()))
            size=random.randint(64,1500)
            stats["total"]+=1; stats["bytes"]+=size
            stats["protocols"][proto]+=1; stats["ips"][src]+=1; stats["ports"][port]+=1
            recent.append({"time":datetime.now().strftime("%H:%M:%S"),"src":src,"dst":dst,
                           "proto":proto,"service":PORTS.get(port,"OTHER"),"size":size})
            if stats["ips"][src]>80 and stats["ips"][src]%20==0:
                a=f"⚠️ High traffic from {src}: {stats['ips'][src]} packets"
                if a not in stats["alerts"]: stats["alerts"].insert(0,a); stats["alerts"]=stats["alerts"][:5]
        time.sleep(1)

@app.route("/")
def home(): return render_template_string(HTML)

@app.route("/api/stats")
def get_stats():
    return jsonify({
        "total":stats["total"],"bytes":stats["bytes"],
        "protocols":[{"name":k,"count":v} for k,v in stats["protocols"].most_common(7)],
        "top_ips":[{"ip":k,"count":v} for k,v in stats["ips"].most_common(5)],
        "recent":list(recent)[-10:],"alerts":stats["alerts"],
    })

HTML="""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><meta http-equiv="refresh" content="3">
<title>Network Traffic Analyzer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0}
nav{background:#1e293b;padding:16px 28px;display:flex;justify-content:space-between;border-bottom:1px solid #334155;align-items:center}
.logo{font-size:18px;font-weight:700;color:#38bdf8}
.live{background:#38bdf822;color:#38bdf8;border:1px solid #38bdf8;padding:4px 12px;border-radius:20px;font-size:12px}
.main{padding:24px 28px;max-width:1300px;margin:0 auto}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.kpi{background:#1e293b;border-radius:12px;padding:18px;border:1px solid #334155}
.kpi .label{font-size:11px;color:#64748b;text-transform:uppercase}
.kpi .val{font-size:26px;font-weight:700;color:#38bdf8;margin:4px 0}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.card{background:#1e293b;border-radius:12px;padding:18px;border:1px solid #334155}
.card h3{font-size:12px;color:#64748b;text-transform:uppercase;margin-bottom:12px}
.bar-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.bar-label{width:80px;color:#94a3b8;font-size:12px;text-align:right}
.bar-bg{flex:1;background:#0f172a;border-radius:4px;height:14px}
.bar-fill{height:14px;border-radius:4px;background:#38bdf8}
.bar-count{width:40px;color:#e2e8f0;font-size:12px}
.alert{background:#7f1d1d;border:1px solid #ef4444;border-radius:6px;padding:8px 12px;font-size:12px;color:#fca5a5;margin-bottom:6px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{color:#64748b;padding:8px 10px;text-align:left;border-bottom:1px solid #334155}
td{padding:7px 10px;border-bottom:1px solid #1e293b}
tr:hover td{background:#263348}
footer{text-align:center;padding:14px;color:#475569;font-size:12px;margin-top:10px}
</style></head>
<body>
<nav>
  <div class="logo">🌐 Network Traffic Analyzer</div>
  <div class="live">● LIVE — auto refresh 3s</div>
</nav>
<div class="main">
  <div class="kpis">
    <div class="kpi"><div class="label">Total Packets</div><div class="val" id="total">—</div></div>
    <div class="kpi"><div class="label">Total Data</div><div class="val" id="bytes">—</div></div>
    <div class="kpi"><div class="label">Top Protocol</div><div class="val" id="top-proto">—</div></div>
    <div class="kpi"><div class="label">Alerts</div><div class="val" id="alert-count" style="color:#ef4444">0</div></div>
  </div>
  <div id="alerts-box"></div>
  <div class="grid2">
    <div class="card"><h3>📊 Protocol Breakdown</h3><div id="proto-bars"></div></div>
    <div class="card"><h3>🖥️ Top Source IPs</h3><div id="ip-bars"></div></div>
  </div>
  <div class="card">
    <h3>📦 Live Packet Feed</h3>
    <table><thead><tr><th>Time</th><th>Source IP</th><th>Destination</th><th>Protocol</th><th>Service</th><th>Size</th></tr></thead>
    <tbody id="packets"></tbody></table>
  </div>
  <p style="color:#64748b;font-size:12px;margin-top:12px">Built by <b style="color:#94a3b8">Kadari Eshwar</b> — B.Tech ECE, JNTU Hyderabad &nbsp;|&nbsp; CCNA concepts applied</p>
</div>
<footer>API: /api/stats</footer>
<script>
fetch('/api/stats').then(r=>r.json()).then(d=>{
  document.getElementById('total').textContent=d.total.toLocaleString();
  document.getElementById('bytes').textContent=(d.bytes/1024).toFixed(1)+'KB';
  document.getElementById('top-proto').textContent=d.protocols[0]?.name||'—';
  document.getElementById('alert-count').textContent=d.alerts.length;
  const mx=d.protocols[0]?.count||1;
  document.getElementById('proto-bars').innerHTML=d.protocols.map(p=>
    '<div class="bar-row"><div class="bar-label">'+p.name+'</div>'
    +'<div class="bar-bg"><div class="bar-fill" style="width:'+Math.round(p.count/mx*100)+'%"></div></div>'
    +'<div class="bar-count">'+p.count+'</div></div>').join('');
  const mi=d.top_ips[0]?.count||1;
  document.getElementById('ip-bars').innerHTML=d.top_ips.map(ip=>
    '<div class="bar-row"><div class="bar-label" style="width:110px;font-size:11px">'+ip.ip+'</div>'
    +'<div class="bar-bg"><div class="bar-fill" style="width:'+Math.round(ip.count/mi*100)+'%;background:#f472b6"></div></div>'
    +'<div class="bar-count">'+ip.count+'</div></div>').join('');
  document.getElementById('alerts-box').innerHTML=d.alerts.map(a=>'<div class="alert">'+a+'</div>').join('');
  document.getElementById('packets').innerHTML=[...d.recent].reverse().map(p=>
    '<tr><td>'+p.time+'</td><td>'+p.src+'</td><td>'+p.dst+'</td>'
    +'<td style="color:#38bdf8;font-weight:600">'+p.proto+'</td><td>'+p.service+'</td><td>'+p.size+'B</td></tr>').join('');
});
</script></body></html>"""

if __name__ == "__main__":
    threading.Thread(target=simulate, daemon=True).start()
    print("\n✅ Network simulation started!")
    print("🌐 Open http://localhost:5000 in your browser")
    print("   Auto-refreshes every 3 seconds")
    print("   Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
