import os
import sys
import json
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.firewall import unblock_ip

st.set_page_config(
    page_title="Team Vikaasa | Sentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

load_dotenv()

def setting(name, default=None):
    value = os.getenv(name)
    if value:
        return value
    try:
        return st.secrets.get(name, default)
    except (FileNotFoundError, KeyError, AttributeError):
        return default

SUPABASE_URL = setting("SUPABASE_URL")
SUPABASE_KEY = setting("SUPABASE_KEY")
TARGET_LAT = setting("SENTINEL_TARGET_LAT")
TARGET_LON = setting("SENTINEL_TARGET_LON")
TARGET_NAME = setting("SENTINEL_TARGET_NAME", "Protected Sentinel sensor")
TARGET_CONFIGURED = TARGET_LAT is not None and TARGET_LON is not None

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Sora:wght@400;500;600;700;800&display=swap');
:root { --ink: #090909; --panel: rgba(28, 28, 27, .82); --line: rgba(200, 169, 107, .24); --gold: #c8a96b; --silver: #aaa9a2; --red: #b94d59; --ivory: #f6f1e7; }
.stApp { background: radial-gradient(circle at 84% 4%, rgba(95, 77, 42, .2), transparent 27rem), #090909; color: var(--ivory); font-family: 'Sora', sans-serif; }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stSidebar"] { background: linear-gradient(180deg, #151514, #090909); border-right: 1px solid var(--line); }
[data-testid="stSidebar"] * { font-family: 'Sora', sans-serif; }
h1, h2, h3, h4, p, label { font-family: 'Sora', sans-serif; }
h1, h2, h3 { letter-spacing: -.045em; }
.hero-kicker { color: var(--gold); font: 500 11px 'DM Mono', monospace; letter-spacing: .16em; text-transform: uppercase; margin-bottom: 8px; }
.hero-title { font-size: clamp(2rem, 4vw, 3.8rem); line-height: .98; font-weight: 800; letter-spacing: -.07em; margin: 0; }
.hero-copy { color: #8ba9a7; max-width: 620px; margin: 14px 0 22px; font-size: 14px; }
.command-strip { display: flex; gap: 8px; align-items: center; color: #87aaa5; font: 10px 'DM Mono', monospace; text-transform: uppercase; letter-spacing: .1em; }
.command-strip b { color: var(--gold); font-weight: 500; } .command-strip i { width: 6px; height: 6px; border-radius: 50%; background: var(--gold); box-shadow: 0 0 12px var(--gold); }
div[data-testid="stMetric"] { background: linear-gradient(135deg, rgba(19, 46, 51, .72), rgba(8, 20, 25, .72)); border: 1px solid var(--line); border-radius: 5px; padding: 17px 18px; box-shadow: 0 18px 45px rgba(0,0,0,.15); }
div[data-testid="stMetricLabel"] { color: #7f9e9c !important; font: 500 10px 'DM Mono', monospace; letter-spacing: .08em; }
div[data-testid="stMetricValue"] { color: #e8fffa !important; font: 700 25px 'DM Mono', monospace; }
div[data-testid="stMetricDelta"] { font: 10px 'DM Mono', monospace; }
div[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 5px; overflow: hidden; }
.section-label { color: #84aaa5; font: 500 10px 'DM Mono', monospace; letter-spacing: .14em; text-transform: uppercase; border-bottom: 1px solid var(--line); padding-bottom: 10px; }
.product-note { color: #aaa9a2; font-size: 12px; line-height: 1.65; max-width: 720px; }
.setup-card { background: linear-gradient(135deg, rgba(34, 32, 27, .9), rgba(18, 18, 17, .86)); border: 1px solid rgba(200, 169, 107, .28); border-radius: 6px; padding: 15px 17px; margin: 10px 0 20px; }
.setup-card strong { color: var(--ivory); font-size: 13px; } .setup-card small { color: #aaa9a2; display: block; margin-top: 5px; line-height: 1.5; }
.status-pill { display: inline-block; margin-top: 10px; padding: 5px 8px; border: 1px solid rgba(200,169,107,.3); color: var(--gold); font: 10px 'DM Mono', monospace; letter-spacing: .08em; text-transform: uppercase; }
.side-brand { padding: 6px 0 18px; } .side-brand strong { color: var(--ivory); display: block; font-size: 20px; letter-spacing: -.06em; } .side-brand span { color: var(--gold); font: 10px 'DM Mono', monospace; letter-spacing: .1em; }
button[kind="secondary"] { border-color: rgba(200,169,107,.3); color: #e2c889; }
@media (max-width: 900px) {
    .hero-title { font-size: clamp(2rem, 8vw, 3.2rem); }
    .hero-copy { font-size: 13px; margin: 12px 0 17px; }
    .command-strip { flex-wrap: wrap; line-height: 1.7; }
    div[data-testid="stMetric"] { padding: 13px 12px; }
    div[data-testid="stMetricValue"] { font-size: 20px; }
}
@media (max-width: 640px) {
    [data-testid="stMainBlockContainer"] { padding: 1.25rem .8rem 2rem; }
    .hero-title { font-size: 2.35rem; }
    .hero-copy { font-size: 12px; }
    .setup-card { padding: 13px; }
    div[data-testid="stMetric"] { min-height: 86px; }
    div[data-testid="stMetricLabel"] { font-size: 9px; line-height: 1.3; }
    div[data-testid="stMetricValue"] { font-size: 18px; }
    .section-label { font-size: 9px; }
}
</style>
""", unsafe_allow_html=True)

supabase = None
if SUPABASE_URL and SUPABASE_KEY and "your-project" not in SUPABASE_URL:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        st.sidebar.warning(f"Supabase connection error: {e}")

def fetch_data():
    if supabase:
        try:
            res = supabase.table("alerts").select("*").order("created_at", desc=True).limit(200).execute()
            if res.data:
                df = pd.DataFrame(res.data)
                parsed_dates = pd.to_datetime(df["created_at"], format="ISO8601")
                df["created_at"] = parsed_dates.dt.strftime("%Y-%m-%d %H:%M:%S")
                return df
        except Exception as e:
            st.error(f"Database error: {e}")
    return pd.DataFrame()

def render_scene(frame):
        rows = frame.fillna("").to_dict(orient="records") if not frame.empty else []
        scene_data = json.dumps(rows, default=str).replace("</", "<\\/")
        html = f"""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');
            * {{ box-sizing: border-box; }} body {{ margin: 0; overflow: hidden; background: #061014; color: #d9f7ee; font-family: 'Space Grotesk', sans-serif; }}
            #scene {{ height: 575px; position: relative; overflow: hidden; background: radial-gradient(circle at 50% 52%, #123c3b 0, #092221 25%, #061014 70%); }}
            #scene canvas {{ display: block; }} #scene::before {{ content: ''; position: absolute; inset: 0; pointer-events: none; opacity: .18; background-image: linear-gradient(rgba(114,255,211,.15) 1px,transparent 1px),linear-gradient(90deg,rgba(114,255,211,.15) 1px,transparent 1px); background-size: 44px 44px; mask-image: radial-gradient(circle,black,transparent 72%); }}
            .hud {{ position: absolute; z-index: 2; pointer-events: none; text-transform: uppercase; letter-spacing: .12em; }} .eyebrow {{ top: 22px; left: 26px; color: #75ffd3; font: 500 11px 'DM Mono',monospace; }} .title {{ top: 41px; left: 24px; font-size: 25px; font-weight: 600; letter-spacing: -.04em; }}
            .status {{ top: 25px; right: 25px; color: #74ffb9; font: 500 11px 'DM Mono',monospace; display: flex; align-items: center; gap: 8px; }} .status i {{ width: 7px; height: 7px; border-radius: 50%; background: #74ffb9; box-shadow: 0 0 14px #74ffb9; animation: pulse 1.2s infinite; }}
            .legend {{ bottom: 21px; left: 25px; display: flex; gap: 18px; color: #8aa9a7; font: 10px 'DM Mono',monospace; }} .legend span::before {{ content: ''; display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 7px; background: var(--c); box-shadow: 0 0 8px var(--c); }} .legend span {{ --c: #75ffd3; }} .legend span:nth-child(2) {{ --c: #ff5577; }} .legend span:nth-child(3) {{ --c: #ffca6b; }}
            .readout {{ bottom: 20px; right: 25px; color: #678987; font: 10px 'DM Mono',monospace; text-align: right; line-height: 1.7; }} @keyframes pulse {{ 50% {{ opacity: .35; transform: scale(.7); }} }}
            .controls {{ position:absolute; z-index:5; top:70px; right:20px; display:flex; gap:6px; }} .controls button {{ border:1px solid rgba(200,169,107,.38); background:rgba(9,9,9,.82); color:#e2c889; padding:7px 9px; border-radius:3px; font:9px 'DM Mono',monospace; letter-spacing:.06em; cursor:pointer; }} .controls button:hover {{ background:rgba(200,169,107,.18); color:#f6f1e7; }}
            .sound-note {{ position:absolute; z-index:5; right:20px; bottom:48px; color:#aaa9a2; font:8px 'DM Mono',monospace; opacity:.78; }}
            .info-card {{ position:absolute; z-index:5; left:20px; top:78px; width:245px; padding:11px 13px; border-left:2px solid #c8a96b; background:rgba(9,9,9,.82); color:#aaa9a2; font:9px 'DM Mono',monospace; line-height:1.7; opacity:0; transform:translateY(-5px); transition:.25s ease; pointer-events:none; }} .info-card.visible {{ opacity:1; transform:translateY(0); }} .info-card strong {{ color:#f6f1e7; font-weight:500; }} .info-card b {{ color:#c8a96b; font-weight:500; }}
            @media (max-width: 620px) {{ .controls {{ top:58px; right:12px; }} .controls button {{ padding:6px 7px; font-size:8px; }} .info-card {{ left:12px; top:72px; width:calc(100% - 24px); font-size:8px; }} }}
        </style>
        <div id="scene"><div class="hud eyebrow">SENTINEL / PERIMETER MESH</div><div class="hud title">Threat orbit // live capture</div><div class="hud status"><i></i> telemetry link active</div><div class="hud legend"><span>protected core</span><span>hostile node</span><span>packet intercept</span></div><div class="hud readout">ROTATION: AUTO / 3D<br>LAST SYNC: {pd.Timestamp.now(tz="UTC").strftime("%H:%M:%S UTC")}</div></div>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
        <script>
            const alerts = {scene_data}; const host = document.getElementById('scene'); const scene = new THREE.Scene();
            const camera = new THREE.PerspectiveCamera(42, host.clientWidth / host.clientHeight, .1, 1000); camera.position.set(0, 8, 22);
            const renderer = new THREE.WebGLRenderer({{antialias:true,alpha:true}}); renderer.setPixelRatio(Math.min(devicePixelRatio,2)); renderer.setSize(host.clientWidth,host.clientHeight); host.prepend(renderer.domElement);
            const root = new THREE.Group(); scene.add(root); const colors = {{mint:0x75ffd3,red:0xff5577,amber:0xffca6b,cyan:0x62dfff,dim:0x1c6560}};
            const core = new THREE.Mesh(new THREE.IcosahedronGeometry(2.1,2),new THREE.MeshBasicMaterial({{color:colors.mint,wireframe:true,transparent:true,opacity:.58}})); root.add(core);
            const glow = new THREE.Mesh(new THREE.IcosahedronGeometry(1.55,2),new THREE.MeshBasicMaterial({{color:0x1ab6a2,transparent:true,opacity:.13}})); root.add(glow);
            [2.8,3.45,4.2].forEach((r,i)=>{{const ring=new THREE.Mesh(new THREE.TorusGeometry(r,.012+i*.008,8,100),new THREE.MeshBasicMaterial({{color:i===1?colors.cyan:colors.mint,transparent:true,opacity:.4-i*.07}})); ring.rotation.set(i*.65,i*.92,i*.2); root.add(ring);}});
            const grid = new THREE.GridHelper(40,40,colors.dim,0x0d2929); grid.position.y=-5; root.add(grid);
            const nodes=[], nodeRows=alerts.length?alerts.slice(0,18):[{{source_ip:'127.0.0.1',attack_type:'Awaiting telemetry',severity:'Low'}}];
            nodeRows.forEach((item,i)=>{{const a=i*2.399,r=6.2+(i%4)*.64,node=new THREE.Group(); node.position.set(Math.cos(a)*r,(i%3-1)*1.25,Math.sin(a)*r); const hostile=['critical','high'].includes(String(item.severity).toLowerCase()),color=hostile?colors.red:colors.amber; const orb=new THREE.Mesh(new THREE.OctahedronGeometry(.27+(i%3)*.06,1),new THREE.MeshBasicMaterial({{color,wireframe:true}})); node.add(orb,new THREE.Mesh(new THREE.SphereGeometry(.55,12,12),new THREE.MeshBasicMaterial({{color,transparent:true,opacity:.09}}))); root.add(node); nodes.push({{node,orb,color}});}});
            const packets=[]; nodes.forEach((n,i)=>{{if(i<12){{const g=new THREE.BufferGeometry().setFromPoints([n.node.position.clone(),new THREE.Vector3(0,0,0)]),line=new THREE.Line(g,new THREE.LineBasicMaterial({{color:n.color,transparent:true,opacity:.2}})); root.add(line); packets.push({{line,node:n,phase:i/12}});}}}});
            const sparks=new THREE.Points(new THREE.BufferGeometry(),new THREE.PointsMaterial({{color:colors.mint,size:.035,transparent:true,opacity:.72}})),positions=[]; for(let i=0;i<260;i++){{const a=Math.random()*Math.PI*2,r=4+Math.random()*10;positions.push(Math.cos(a)*r,(Math.random()-.5)*7,Math.sin(a)*r);}} sparks.geometry.setAttribute('position',new THREE.Float32BufferAttribute(positions,3)); root.add(sparks);
            let dragging=false,lastX=0,lastY=0; host.addEventListener('pointerdown',e=>{{dragging=true;lastX=e.clientX;lastY=e.clientY;}}); window.addEventListener('pointerup',()=>dragging=false); host.addEventListener('pointermove',e=>{{if(!dragging)return;root.rotation.y+=(e.clientX-lastX)*.008;root.rotation.x+=(e.clientY-lastY)*.005;lastX=e.clientX;lastY=e.clientY;}});
            function animate(t){{requestAnimationFrame(animate);const s=t*.001;if(!dragging)root.rotation.y+=.0018;core.rotation.x=s*.18;core.rotation.y=s*.31;glow.scale.setScalar(1+Math.sin(s*2.2)*.05);nodes.forEach((n,i)=>{{n.node.position.y+=Math.sin(s*1.3+i)*.002;n.orb.rotation.x+=.015;n.orb.rotation.y+=.022;}});packets.forEach((p,i)=>{{const q=(s*(.22+i*.012)+p.phase)%1,pos=p.node.node.position.clone().multiplyScalar(1-q);p.line.material.opacity=q>.72 ? .42 : .08;p.line.geometry.attributes.position.setXYZ(0,pos.x,pos.y,pos.z);p.line.geometry.attributes.position.needsUpdate=true;}});sparks.rotation.y=s*.025;renderer.render(scene,camera);}} animate(0); new ResizeObserver(()=>{{camera.aspect=host.clientWidth/host.clientHeight;camera.updateProjectionMatrix();renderer.setSize(host.clientWidth,host.clientHeight);}}).observe(host);
        </script>
        """
        components.html(html, height=575, scrolling=False)

def render_scene(frame):
        rows = frame.fillna("").to_dict(orient="records") if not frame.empty else []
        scene_data = json.dumps(rows, default=str).replace("</", "<\\/")
        html = f"""
        <style>
            @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');
            * {{ box-sizing: border-box; }} body {{ margin: 0; background: #071014; color: #d8eee9; font-family: 'Space Grotesk', sans-serif; }}
            #soc-map {{ height: 560px; position: relative; overflow: hidden; background: #091a20; }}
            #map {{ position: absolute; inset: 0; }} .leaflet-container {{ background: #091a20; font-family: 'DM Mono', monospace; }}
            .hud {{ position: absolute; z-index: 1000; pointer-events: none; text-transform: uppercase; letter-spacing: .12em; }}
            .eyebrow {{ top: 20px; left: 24px; color: #70f4cd; font: 500 10px 'DM Mono', monospace; }}
            .title {{ top: 38px; left: 22px; font-size: 24px; font-weight: 600; letter-spacing: -.04em; }}
            .status {{ top: 21px; right: 22px; color: #77ffc0; font: 500 10px 'DM Mono', monospace; }} .status i {{ display: inline-block; width: 7px; height: 7px; margin-right: 7px; border-radius: 50%; background: #77ffc0; box-shadow: 0 0 12px #77ffc0; animation: pulse 1.2s infinite; }}
            .target-label {{ color: #75ffd3; font: 500 10px 'DM Mono', monospace; text-shadow: 0 0 8px #000; white-space: nowrap; }}
            .response {{ position: absolute; z-index: 1001; right: 20px; bottom: 20px; width: 245px; padding: 13px; background: rgba(5,18,22,.9); border: 1px solid rgba(117,255,211,.28); box-shadow: 0 12px 30px rgba(0,0,0,.32); }}
            .response h4 {{ margin: 0 0 10px; color: #75ffd3; font: 500 10px 'DM Mono', monospace; letter-spacing: .12em; }} .response-row {{ display: flex; justify-content: space-between; gap: 12px; padding: 7px 0; border-top: 1px solid rgba(150,210,200,.12); font: 10px 'DM Mono', monospace; }} .response-row b {{ color: #ff718b; font-weight: 500; }} .response-row span {{ color: #8faeaa; text-align: right; }}
            .leaflet-control-attribution {{ background: rgba(5,18,22,.7) !important; color: #66827e !important; }} .leaflet-control-attribution a {{ color: #75cdb8 !important; }} @keyframes pulse {{ 50% {{ opacity: .3; transform: scale(.7); }} }}
        </style>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="" />
        <div id="soc-map"><div id="map"></div><div class="hud eyebrow">SENTINEL / GLOBAL TELEMETRY MAP</div><div class="hud title">Attack routes // live traffic</div><div class="hud status"><i></i> {len(rows)} routes being monitored</div><div class="response"><h4>IPS RESPONSE MATRIX</h4><div class="response-row"><b>CRITICAL</b><span>firewall block applied</span></div><div class="response-row"><b>HIGH</b><span>containment queued</span></div><div class="response-row"><b>MED / LOW</b><span>observe + rate limit</span></div></div></div>
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
        <script>
            const alerts = {scene_data};
            const map = L.map('map', {{ zoomControl: false, worldCopyJump: true, minZoom: 2 }}).setView([18, 8], 2);
            L.control.zoom({{ position: 'bottomleft' }}).addTo(map);
            L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{ maxZoom: 6, attribution: '&copy; OpenStreetMap &copy; CARTO' }}).addTo(map);
            const target = [20, 0];
            const targetIcon = L.divIcon({{ className: '', html: '<div style="width:16px;height:16px;border:2px solid #75ffd3;border-radius:50%;box-shadow:0 0 0 5px rgba(117,255,211,.16),0 0 20px #75ffd3;background:#0a2727"></div>', iconSize:[16,16], iconAnchor:[8,8] }});
            L.marker(target, {{ icon: targetIcon }}).addTo(map).bindTooltip('<span class="target-label">PROTECTED ASSET / SENTINEL CORE</span>', {{ permanent: true, direction: 'right', className: 'target-label' }});
            const fallback = [[51.5,-.1],[35.7,139.7],[-23.5,-46.6],[1.3,103.8],[40.7,-74],[48.8,2.3]];
            const routeRows = alerts.length ? alerts.slice(0, 30) : [{{source_ip:'awaiting telemetry',country:'No source',city:'Listening',severity:'Low',attack_type:'No active attack'}}];
            routeRows.forEach((item, index) => {{
                const lat = Number(item.latitude), lon = Number(item.longitude), source = Number.isFinite(lat) && Number.isFinite(lon) ? [lat, lon] : fallback[index % fallback.length];
                const severity = String(item.severity || 'Low').toLowerCase(); const hostile = severity === 'critical' || severity === 'high'; const color = hostile ? '#ff5577' : '#ffca6b';
                const marker = L.circleMarker(source, {{ radius: hostile ? 7 : 5, color, fillColor: color, fillOpacity: .9, weight: 1 }}).addTo(map);
                const response = severity === 'critical' ? 'FIREWALL BLOCKED' : severity === 'high' ? 'CONTAINMENT QUEUED' : 'MONITORING';
                marker.bindPopup('<b>' + (item.source_ip || 'Unknown source') + '</b><br>' + (item.city || 'Unknown city') + ', ' + (item.country || 'Unknown country') + '<br>' + (item.attack_type || 'Network event') + '<br><strong>' + response + '</strong>');
                const line = L.polyline([source, target], {{ color, weight: hostile ? 1.8 : 1, opacity: hostile ? .65 : .35, dashArray: '5 9', className: 'route-line' }}).addTo(map);
                const packet = L.circleMarker(source, {{ radius: 3, color: '#fff5d1', fillColor: '#fff5d1', fillOpacity: 1, weight: 0 }}).addTo(map);
                let progress = (index / routeRows.length) % 1;
                function animateRoute() {{ progress = (progress + .003 + index * .00005) % 1; const point = [source[0] + (target[0] - source[0]) * progress, source[1] + (target[1] - source[1]) * progress]; packet.setLatLng(point); requestAnimationFrame(animateRoute); }} animateRoute();
            }});
        </script>
        """
        components.html(html, height=560, scrolling=False)

def render_scene(frame):
        rows = frame.fillna("").to_dict(orient="records") if not frame.empty else []
        route_data = []
        for index, row in enumerate(rows[:24]):
                try:
                        lat = float(row.get("latitude"))
                        lon = float(row.get("longitude"))
                except (TypeError, ValueError):
                    continue
                route_data.append({
                        "lat": lat, "lon": lon, "ip": str(row.get("source_ip", "Unknown")),
                        "city": str(row.get("city", "Unknown")), "country": str(row.get("country", "Unknown")),
                    "severity": str(row.get("severity", "Low")), "attack": str(row.get("attack_type", "Network event")),
                    "destination_ip": str(row.get("destination_ip", "Unknown destination")),
                })
        route_data_json = json.dumps(route_data).replace("</", "<\\/")
        html = f"""
        <style>
            * {{ box-sizing: border-box; }} body {{ margin: 0; overflow: hidden; background: #050b18; color: #edf6ff; font-family: 'Sora', sans-serif; }}
            #orbit {{ height: 560px; min-height: 420px; position: relative; overflow: hidden; background: radial-gradient(circle at 50% 48%, #123b3d 0, #0a2228 25%, #071419 68%); border: 1px solid rgba(122,255,212,.18); border-radius: 5px; touch-action: none; }}
            #orbit canvas {{ display: block; }} #orbit:after {{ content: ''; position: absolute; inset: 0; pointer-events: none; background: linear-gradient(110deg, rgba(200,169,107,.07), transparent 33%, transparent 69%, rgba(246,241,231,.04)); }}
            .controls {{ position:absolute; z-index:5; top:70px; right:20px; display:flex; gap:6px; }} .controls button {{ border:1px solid rgba(200,169,107,.38); background:rgba(9,9,9,.82); color:#e2c889; padding:7px 9px; border-radius:3px; font:9px 'DM Mono',monospace; letter-spacing:.06em; cursor:pointer; }} .controls button:hover {{ background:rgba(200,169,107,.18); color:#f6f1e7; }}
            .info-card {{ position:absolute; z-index:5; left:20px; top:78px; width:245px; padding:11px 13px; border-left:2px solid #c8a96b; background:rgba(9,9,9,.82); color:#aaa9a2; font:9px 'DM Mono',monospace; line-height:1.7; opacity:0; transform:translateY(-5px); transition:.25s ease; pointer-events:none; }} .info-card.visible {{ opacity:1; transform:translateY(0); }} .info-card strong {{ color:#f6f1e7; font-weight:500; }} .info-card b {{ color:#c8a96b; font-weight:500; }}
            @media (max-width: 620px) {{ .controls {{ top:58px; right:12px; }} .controls button {{ padding:6px 7px; font-size:8px; }} .info-card {{ left:12px; top:72px; width:calc(100% - 24px); font-size:8px; }} }}
            .hud {{ position: absolute; z-index: 3; pointer-events: none; text-transform: uppercase; letter-spacing: .13em; }} .eyebrow {{ top: 20px; left: 22px; color: #c8a96b; font: 500 10px 'DM Mono', monospace; }} .title {{ top: 38px; left: 20px; color: #f6f1e7; font-size: 22px; font-weight: 700; letter-spacing: -.055em; }}
            .live {{ top: 21px; right: 22px; color: #e2c889; font: 500 10px 'DM Mono', monospace; }} .live i {{ display: inline-block; width: 6px; height: 6px; margin-right: 7px; border-radius: 50%; background: #c8a96b; box-shadow: 0 0 13px #c8a96b; animation: blink 1.2s infinite; }}
            .legend {{ bottom: 18px; left: 21px; display: flex; flex-wrap: wrap; gap: 14px; color: #aaa9a2; font: 9px 'DM Mono', monospace; }} .legend b {{ font-weight: 400; }} .legend b:before {{ content: ''; display: inline-block; width: 6px; height: 6px; margin-right: 6px; border-radius: 50%; background: var(--c); box-shadow: 0 0 8px var(--c); }} .legend b:nth-child(1) {{ --c: #b94d59; }} .legend b:nth-child(2) {{ --c: #c8a96b; }} .legend b:nth-child(3) {{ --c: #aaa9a2; }} .legend b:nth-child(4) {{ --c: #e2c889; }}
            .readout {{ bottom: 18px; right: 21px; color: #6e9290; font: 9px 'DM Mono', monospace; line-height: 1.8; text-align: right; }} @media (max-width: 620px) {{ #orbit {{ height: 440px; min-height: 360px; }} .eyebrow {{ top: 14px; left: 14px; font-size: 8px; }} .title {{ top: 32px; left: 14px; font-size: 17px; }} .live {{ top: 15px; right: 14px; font-size: 8px; }} .readout {{ display: none; }} .legend {{ bottom: 13px; left: 14px; gap: 7px; font-size: 8px; max-width: 78%; line-height: 1.6; }} }} @keyframes blink {{ 50% {{ opacity: .3; }} }}
        </style>
        <div id="orbit"><div class="hud eyebrow">TEAM VIKAASA / GLOBAL ATTACK SURFACE</div><div class="hud title">Live route intelligence</div><div class="hud live"><i></i>{len(route_data)} active routes</div><div class="controls"><button id="rotation-control">PAUSE ROTATION</button><button id="reset-control">RESET VIEW</button><button id="sound-control">SOUND OFF</button></div><div id="info-card" class="info-card"></div><div class="sound-note">AMBIENT EARTH / USER CONTROLLED</div><div class="hud legend"><b>attacker origin</b><b>protected asset</b><b>packet trajectory</b><b>intercept event</b></div><div class="hud readout">WEBGL TELEMETRY / 60 FPS<br>{'GPS COORDINATES VERIFIED' if TARGET_CONFIGURED else 'DESTINATION IP VERIFIED / SENSOR GPS UNSET'}<br>DRAG TO INSPECT / AUTO ORBIT</div></div>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
        <script>
            const routes = {route_data_json}, host = document.getElementById('orbit');
            const scene = new THREE.Scene(), camera = new THREE.PerspectiveCamera(34, host.clientWidth / host.clientHeight, .1, 1000); camera.position.set(0, .65, 7.1);
            let renderer=null, fallbackCanvas=null, fallbackContext=null, fallbackEarth=null; try {{ renderer = new THREE.WebGLRenderer({{ antialias: true, alpha: true }}); renderer.setPixelRatio(Math.min(devicePixelRatio, 2)); renderer.setSize(host.clientWidth, host.clientHeight); renderer.outputEncoding = THREE.sRGBEncoding; renderer.toneMapping = THREE.ACESFilmicToneMapping; renderer.toneMappingExposure = .82; host.prepend(renderer.domElement); }} catch(error) {{ fallbackCanvas=document.createElement('canvas'); fallbackCanvas.width=900; fallbackCanvas.height=560; fallbackCanvas.style.cssText='position:absolute;inset:0;width:100%;height:100%;'; fallbackContext=fallbackCanvas.getContext('2d'); host.prepend(fallbackCanvas); fallbackEarth=document.createElement('div'); fallbackEarth.style.cssText='position:absolute;left:50%;top:54%;width:min(52vw,330px);height:min(52vw,330px);transform:translate(-50%,-50%);border-radius:50%;background:radial-gradient(circle at 34% 28%,rgba(255,255,255,.8),transparent 12%),url(https://threejs.org/examples/textures/planets/earth_atmos_2048.jpg) center/cover;box-shadow:-22px 18px 38px rgba(0,0,0,.65),inset -28px -18px 42px rgba(0,0,0,.5),0 0 0 10px rgba(200,169,107,.08);filter:saturate(1.15) contrast(1.04);'; host.appendChild(fallbackEarth); }}
            const world = new THREE.Group(); scene.add(world); const R = 1.92, mint = 0xc8a96b, red = 0xb94d59, blue = 0xaaa9a2;
            const space = new THREE.Group(); scene.add(space);
            const starPositions=[]; for(let i=0;i<900;i++) {{ const radius=8+Math.random()*15, a=Math.random()*Math.PI*2, y=(Math.random()-.5)*18; starPositions.push(Math.cos(a)*radius,y,Math.sin(a)*radius); }}
            const stars = new THREE.Points(new THREE.BufferGeometry(), new THREE.PointsMaterial({{ color: 0xf6f1e7, size: .022, transparent: true, opacity: .72 }})); stars.geometry.setAttribute('position', new THREE.Float32BufferAttribute(starPositions,3)); space.add(stars);
            const dustPositions=[]; for(let i=0;i<160;i++) {{ const radius=4+Math.random()*10, a=Math.random()*Math.PI*2; dustPositions.push(Math.cos(a)*radius,(Math.random()-.5)*8,Math.sin(a)*radius); }}
            const dust = new THREE.Points(new THREE.BufferGeometry(), new THREE.PointsMaterial({{ color: 0x8a7650, size: .045, transparent: true, opacity: .28 }})); dust.geometry.setAttribute('position', new THREE.Float32BufferAttribute(dustPositions,3)); space.add(dust);
            const asteroids=[];
            for(let i=0;i<14;i++) {{ const rock=new THREE.Group(), size=.08+Math.random()*.19, angle=Math.random()*Math.PI*2, orbit=4.4+Math.random()*4.5; rock.position.set(Math.cos(angle)*orbit,(Math.random()-.5)*4,Math.sin(angle)*orbit); const body=new THREE.Mesh(new THREE.IcosahedronGeometry(size,2),new THREE.MeshStandardMaterial({{color:0x514a40,roughness:.94,metalness:.03}})); rock.add(body); for(let craterIndex=0;craterIndex<3;craterIndex++) {{ const crater=new THREE.Group(), craterSize=size*(.12+Math.random()*.1), normal=new THREE.Vector3(Math.random()-.5,Math.random()-.5,Math.random()-.5).normalize(), bowl=new THREE.Mesh(new THREE.SphereGeometry(craterSize,12,8),new THREE.MeshStandardMaterial({{color:0x211e1a,roughness:1}})), rim=new THREE.Mesh(new THREE.TorusGeometry(craterSize*1.1,craterSize*.18,8,16),new THREE.MeshStandardMaterial({{color:0x776956,roughness:1}})); crater.position.copy(normal.clone().multiplyScalar(size*.92)); crater.lookAt(new THREE.Vector3(0,0,0)); bowl.scale.set(1,1,.34); rim.scale.set(1,1,.5); crater.add(bowl,rim); rock.add(crater); }} space.add(rock); asteroids.push({{rock,angle,orbit,speed:.18+Math.random()*.25,spin:.3+Math.random()*.5}}); }}
            const meteors=[];
            for(let i=0;i<6;i++) {{
                const start=new THREE.Vector3(-7+Math.random()*14,2+Math.random()*5,-6-Math.random()*5);
                const direction=new THREE.Vector3(.8+Math.random()*.55,-.25-Math.random()*.35,.8+Math.random()*.65).normalize();
                const length=1.1+Math.random()*1.8, speed=.8+Math.random()*.8, meteor=new THREE.Group();
                const head=new THREE.Mesh(new THREE.SphereGeometry(.045+Math.random()*.025,12,8),new THREE.MeshBasicMaterial({{color:0xfff4d0,transparent:true,opacity:.95}})); meteor.add(head);
                const coreTail=new THREE.Mesh(new THREE.ConeGeometry(.018,.75,8,1,true),new THREE.MeshBasicMaterial({{color:0xe2b86e,transparent:true,opacity:.7,depthWrite:false}})); coreTail.position.copy(direction.clone().multiplyScalar(-.38)); coreTail.quaternion.setFromUnitVectors(new THREE.Vector3(0,1,0),direction.clone().negate()); meteor.add(coreTail);
                const halo=new THREE.Mesh(new THREE.SphereGeometry(.14,12,8),new THREE.MeshBasicMaterial({{color:0xd99d55,transparent:true,opacity:.1,depthWrite:false}})); meteor.add(halo);
                const tailPoints=[]; for(let tailIndex=0;tailIndex<7;tailIndex++) tailPoints.push(direction.clone().multiplyScalar(-tailIndex*.19)); const tail=new THREE.Line(new THREE.BufferGeometry().setFromPoints(tailPoints),new THREE.LineBasicMaterial({{color:0xc8a96b,transparent:true,opacity:.38,depthWrite:false}})); meteor.add(tail);
                meteor.userData={{start,end:start.clone().add(direction.clone().multiplyScalar(length)),head,coreTail,halo,tail,speed,progress:Math.random()*1.3}}; space.add(meteor); meteors.push(meteor);
            }}
            const loader = new THREE.TextureLoader();
            const earthColor = loader.load('https://threejs.org/examples/textures/planets/earth_atmos_2048.jpg');
            const earthNormal = loader.load('https://threejs.org/examples/textures/planets/earth_normal_2048.jpg');
            const earthSpecular = loader.load('https://threejs.org/examples/textures/planets/earth_specular_2048.jpg');
            const cloudTexture = loader.load('https://threejs.org/examples/textures/planets/earth_clouds_1024.png');
            const earth = new THREE.Mesh(new THREE.SphereGeometry(R, 96, 64), new THREE.MeshPhongMaterial({{ map: earthColor, color: 0xc8d0c8, normalMap: earthNormal, normalScale: new THREE.Vector2(.72,.72), specularMap: earthSpecular, specular: new THREE.Color(0x9b8460), shininess: 24 }})); world.add(earth);
            const clouds = new THREE.Mesh(new THREE.SphereGeometry(R + .035, 96, 64), new THREE.MeshPhongMaterial({{ map: cloudTexture, color: 0xf4efe4, transparent: true, opacity: .2, depthWrite: false, shininess: 4 }})); world.add(clouds);
            const atmosphere = new THREE.Mesh(new THREE.SphereGeometry(R + .13, 64, 40), new THREE.MeshBasicMaterial({{ color: 0xc8a96b, transparent: true, opacity: .075, side: THREE.BackSide }})); world.add(atmosphere);
            const grid = new THREE.Mesh(new THREE.SphereGeometry(R + .015, 32, 20), new THREE.MeshBasicMaterial({{ color: 0xe2c889, transparent: true, opacity: .045, wireframe: true }})); world.add(grid);
            scene.add(new THREE.HemisphereLight(0xcbd8e6, 0x17130d, .58)); const sun = new THREE.DirectionalLight(0xfff1d0, 1.45); sun.position.set(-4, 2, 5); scene.add(sun);
            function point(lat, lon, radius) {{ const p=(90-lat)*Math.PI/180, t=(lon+180)*Math.PI/180; return new THREE.Vector3(-(radius*Math.sin(p)*Math.cos(t)), radius*Math.cos(p), radius*Math.sin(p)*Math.sin(t)); }}
            function label(text, color) {{ const canvas=document.createElement('canvas'), ctx=canvas.getContext('2d'); canvas.width=1024; canvas.height=64; ctx.font='500 22px DM Mono'; ctx.fillStyle=color; ctx.fillText(text.slice(0,58), 10, 40); const sprite=new THREE.Sprite(new THREE.SpriteMaterial({{ map:new THREE.CanvasTexture(canvas), transparent:true, depthTest:false }})); sprite.scale.set(.9,.11,1); return sprite; }}
            const targetConfigured = {str(TARGET_CONFIGURED).lower()}, target = point(targetConfigured ? {TARGET_LAT or 0} : 0, targetConfigured ? {TARGET_LON or 0} : 0, R + .035);
            const destinationLabel = targetConfigured ? '{TARGET_NAME.upper()}' : 'PROTECTED SENSOR / DESTINATION IP';
            const targetDot = new THREE.Mesh(new THREE.SphereGeometry(.105, 16, 12), new THREE.MeshBasicMaterial({{ color: mint, depthTest: false }})); targetDot.position.copy(target); targetDot.userData.focusKey='destination'; world.add(targetDot);
            const interactiveTargets=[targetDot]; const targetLabel=label(destinationLabel, '#c8a96b'); targetLabel.position.copy(target.clone().multiplyScalar(1.16)); targetLabel.userData.focusKey='destination'; world.add(targetLabel); interactiveTargets.push(targetLabel);
            const halo = new THREE.Mesh(new THREE.RingGeometry(.17, .24, 32), new THREE.MeshBasicMaterial({{ color: mint, transparent: true, opacity: .8, side: THREE.DoubleSide, depthTest: false }})); halo.position.copy(target); halo.lookAt(camera.position); world.add(halo);
            const packets = [];
            routes.forEach((route, index) => {{ if (!target) return; const source = point(route.lat, route.lon, R + .035), hostile = ['critical','high'].includes(route.severity.toLowerCase()), color = hostile ? red : blue;
                const mid = source.clone().add(target).multiplyScalar(.5).normalize().multiplyScalar(R + .65 + source.distanceTo(target) * .18); const curve = new THREE.QuadraticBezierCurve3(source, mid, target); const points=curve.getPoints(64); const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), new THREE.LineBasicMaterial({{ color, transparent: true, opacity: hostile ? .86 : .48, depthTest: false }})); world.add(line);
                const glowLine = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), new THREE.LineBasicMaterial({{ color, transparent: true, opacity: .08, linewidth: 4, depthTest: false }})); world.add(glowLine);
                const marker = new THREE.Mesh(new THREE.SphereGeometry(hostile ? .09 : .065, 12, 8), new THREE.MeshBasicMaterial({{ color, depthTest: false }})); marker.position.copy(source); world.add(marker); const pulse = new THREE.Mesh(new THREE.RingGeometry(.12,.17,24), new THREE.MeshBasicMaterial({{ color, transparent:true, opacity:.7, side:THREE.DoubleSide, depthTest: false }})); pulse.position.copy(source); pulse.lookAt(camera.position); world.add(pulse);
                const sourceLabel=label((route.city || route.country || 'UNKNOWN').toUpperCase() + ' / ' + route.ip + '  →  ' + route.destination_ip, hostile ? '#d97880' : '#d7d2c8'); sourceLabel.position.copy(source.clone().multiplyScalar(1.12)); world.add(sourceLabel); interactiveTargets.push(marker, sourceLabel); marker.userData.route=route; marker.userData.focusKey=route.ip+'>'+route.destination_ip; sourceLabel.userData.route=route; sourceLabel.userData.focusKey=route.ip+'>'+route.destination_ip;
                const routePackets=[]; for(let packetIndex=0;packetIndex<3;packetIndex++) {{ const packet=new THREE.Mesh(new THREE.SphereGeometry(.045 + (packetIndex === 1 ? .018 : 0),10,8),new THREE.MeshBasicMaterial({{ color:packetIndex === 1 ? 0xffffff : color, depthTest: false }})); world.add(packet); routePackets.push(packet); }} packets.push({{ curve, routePackets, pulse, phase:index/Math.max(routes.length,1), speed:.19+index*.008 }});
            }});
            if (!routes.length) {{ const label = document.createElement('div'); label.textContent = 'LISTENING FOR ROUTES'; label.style.cssText = 'position:absolute;top:52%;left:50%;transform:translate(-50%,-50%);font:10px DM Mono,monospace;color:#8caaa6;letter-spacing:.15em;'; host.appendChild(label); }}
            let drag=false, moved=false, lastX=0, lastY=0, focus=null, autoRotate=true; const raycaster=new THREE.Raycaster(), pointer=new THREE.Vector2(), clock=new THREE.Clock(), defaultCamera=new THREE.Vector3(0,.65,7.1), focusPoint=new THREE.Vector3();
            const rotationControl=document.getElementById('rotation-control'), resetControl=document.getElementById('reset-control'), soundControl=document.getElementById('sound-control'), infoCard=document.getElementById('info-card');
            let audioContext=null, masterGain=null, ambientNodes=[], soundEnabled=false;
            function startAmbientSound() {{ if(audioContext) return; audioContext=new (window.AudioContext||window.webkitAudioContext)(); audioContext.resume(); masterGain=audioContext.createGain(); masterGain.gain.value=.0001; masterGain.connect(audioContext.destination); const notes=[55,82.41,110,164.81]; notes.forEach((frequency,index)=>{{ const oscillator=audioContext.createOscillator(), gain=audioContext.createGain(), filter=audioContext.createBiquadFilter(); oscillator.type=index===1?'sine':'triangle'; oscillator.frequency.value=frequency; filter.type='lowpass'; filter.frequency.value=520; gain.gain.value=index===0?.12:.065; oscillator.connect(filter); filter.connect(gain); gain.connect(masterGain); oscillator.start(); ambientNodes.push({{oscillator,gain}}); }}); const lfo=audioContext.createOscillator(), lfoGain=audioContext.createGain(); lfo.frequency.value=.045; lfoGain.gain.value=.025; lfo.connect(lfoGain); lfoGain.connect(masterGain.gain); lfo.start(); ambientNodes.push({{oscillator:lfo,gain:lfoGain}}); setSound(true); }}
            function setSound(enabled) {{ soundEnabled=enabled; if(!masterGain) return; audioContext.resume(); const now=audioContext.currentTime; masterGain.gain.cancelScheduledValues(now); masterGain.gain.linearRampToValueAtTime(enabled?.16:.0001,now+1.4); soundControl.textContent=enabled?'SOUND ON':'SOUND OFF'; }}
            soundControl.addEventListener('click', event => {{ event.stopPropagation(); if(!audioContext) startAmbientSound(); else setSound(!soundEnabled); }});
            host.addEventListener('pointerdown', event => {{ if(!audioContext && !event.target.closest('.controls')) startAmbientSound(); }});
            function clearFocus() {{ focus=null; infoCard.classList.remove('visible'); }}
            function resetView() {{ clearFocus(); world.rotation.set(0,0,0); camera.position.copy(defaultCamera); camera.lookAt(0,0,0); }}
            rotationControl.addEventListener('click', event => {{ event.stopPropagation(); autoRotate=!autoRotate; rotationControl.textContent=autoRotate?'PAUSE ROTATION':'RESUME ROTATION'; }});
            resetControl.addEventListener('click', event => {{ event.stopPropagation(); resetView(); }});
            host.addEventListener('wheel', event => {{ event.preventDefault(); camera.position.z=Math.max(3.3,Math.min(8.5,camera.position.z+event.deltaY*.0025)); }}, {{ passive:false }});
            host.addEventListener('pointerdown', event => {{ drag=true; moved=false; lastX=event.clientX; lastY=event.clientY; }});
            host.addEventListener('pointermove', event => {{ if (!drag) return; const dx=event.clientX-lastX, dy=event.clientY-lastY; if(Math.abs(dx)+Math.abs(dy)>3)moved=true; world.rotation.y+=dx*.006; world.rotation.x=Math.max(-.7,Math.min(.7,world.rotation.x+dy*.004)); lastX=event.clientX; lastY=event.clientY; }});
            host.addEventListener('pointerup', event => {{ if (!moved) {{ const interactionElement=renderer?renderer.domElement:fallbackCanvas, rect=interactionElement.getBoundingClientRect(); pointer.x=((event.clientX-rect.left)/rect.width)*2-1; pointer.y=-((event.clientY-rect.top)/rect.height)*2+1; raycaster.setFromCamera(pointer,camera); const hits=raycaster.intersectObjects(interactiveTargets,true); if(hits.length) {{ const selected=hits[0].object, selectedKey=selected.userData.focusKey; if(focus && focus.userData.focusKey===selectedKey) {{ clearFocus(); }} else {{ focus=selected; const route=focus.userData.route; infoCard.innerHTML=route ? '<strong>PACKET ROUTE</strong><br><b>FROM</b> '+route.ip+' / '+(route.city||route.country)+'<br><b>TO</b> '+route.destination_ip+' / protected sensor<br><b>EVENT</b> '+route.attack+'<br><b>RISK</b> '+route.severity : '<strong>PROTECTED DESTINATION</strong><br>Team Vikaasa sensor endpoint<br>Click again or use Reset View to return'; infoCard.classList.add('visible'); }} }} }} drag=false; }});
            host.addEventListener('dblclick', () => {{ resetView(); }});
            function animate(time) {{ requestAnimationFrame(animate); const delta=Math.min(clock.getDelta(),.05), s=clock.elapsedTime; if (!drag && !focus && autoRotate) world.rotation.y += delta*.055; stars.rotation.y=s*.003; dust.rotation.y=-s*.006; clouds.rotation.y += delta*.0022; sun.position.set(Math.cos(s*.035)*6, 2.2+Math.sin(s*.07)*.8, Math.sin(s*.035)*6); sun.intensity=1.35+Math.sin(s*.07)*.12; if(renderer) renderer.toneMappingExposure=.79+Math.sin(s*.07)*.035; asteroids.forEach((item,index) => {{ item.angle += item.speed*delta*.08; item.rock.position.x=Math.cos(item.angle)*item.orbit; item.rock.position.z=Math.sin(item.angle)*item.orbit; item.rock.rotation.x+=delta*item.spin; item.rock.rotation.y+=delta*item.spin*.7; }}); meteors.forEach(meteor => {{ const data=meteor.userData; data.progress=(data.progress+delta*data.speed*.12)%1; const travel=data.progress; meteor.position.copy(data.start).lerp(data.end,travel); const fade=Math.sin(Math.PI*travel); data.head.material.opacity=.35+.6*fade; data.coreTail.material.opacity=.12+.62*fade; data.halo.material.opacity=.025+.1*fade; data.tail.material.opacity=.08+.36*fade; }}); if (focus) {{ focus.getWorldPosition(focusPoint); const desired=focusPoint.clone().normalize().multiplyScalar(3.35); camera.position.lerp(desired,1-Math.pow(.001,delta)); camera.lookAt(focusPoint); }} else {{ camera.position.lerp(defaultCamera,1-Math.pow(.001,delta)); camera.lookAt(0,0,0); }} if (halo) halo.scale.setScalar(1 + Math.sin(s*3)*.26); if (targetDot) targetDot.scale.setScalar(1 + Math.sin(s*4)*.12); packets.forEach((item,index) => {{ item.routePackets.forEach((packet, packetIndex) => {{ const progress=(s*item.speed+item.phase-(packetIndex*.075))%1; packet.position.copy(item.curve.getPoint(progress<0?progress+1:progress)); packet.scale.setScalar(1 + Math.sin(s*9+packetIndex)*.12); }}); item.pulse.scale.setScalar(1 + ((s*1.4+index*.23)%1)*1.4); item.pulse.material.opacity=.72-((s*1.4+index*.23)%1)*.65; }}); if (fallbackEarth) {{ fallbackEarth.style.transform='translate(-50%,-50%) rotate('+(s*2)+'deg)'; return; }} renderer.render(scene,camera); }} animate(0);
            function resizeScene() {{ const compact=host.clientWidth < 620; camera.aspect=host.clientWidth/host.clientHeight; camera.fov=compact?42:36; camera.updateProjectionMatrix(); if(renderer) renderer.setSize(host.clientWidth,host.clientHeight); if(fallbackCanvas) {{ fallbackCanvas.width=host.clientWidth*2; fallbackCanvas.height=host.clientHeight*2; }} world.scale.setScalar(compact ? .9 : 1); space.scale.setScalar(compact ? .9 : 1); }}
            new ResizeObserver(resizeScene).observe(host); resizeScene();
        </script>
        """
        components.html(html, height=560, scrolling=False)

# Sidebar Controls
with st.sidebar:
    st.markdown('<div class="side-brand"><strong>TEAM VIKAASA<span style="color:#c8a96b">.</span></strong><span>SENTINEL SOC / THREAT OPERATIONS</span></div>', unsafe_allow_html=True)
    st.caption("A calm command center for detecting, understanding, and stopping network threats.")
    st.divider()

    severity_filter = st.multiselect(
        "Show threat levels",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )

    st.divider()
    with st.expander("Operator tools", expanded=False):
        st.caption("Use these controls when you need to reverse an automated protection action.")
        ip_to_unblock = st.text_input("Address to release", placeholder="203.0.113.42")
        if st.button("Release firewall block", use_container_width=True):
            if ip_to_unblock:
                unblock_ip(ip_to_unblock.strip())
                st.success(f"Release request sent for {ip_to_unblock.strip()}")

# Main SOC View
@st.fragment(run_every="3s")
def render_live_board():
    df = fetch_data()
    total_count = len(df)
    critical_count = len(df[df["severity"] == "Critical"]) if not df.empty and "severity" in df else 0
    high_count = len(df[df["severity"] == "High"]) if not df.empty and "severity" in df else 0
    unique_ips = df["source_ip"].nunique() if not df.empty and "source_ip" in df else 0

    st.markdown('<div class="hero-kicker">Team Vikaasa / security operations center</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-title">Know the route.<br><span style="color:#c8a96b">Stop the threat.</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-copy">A clear, live view of what is reaching your systems, where it comes from, and how Sentinel is responding.</div>', unsafe_allow_html=True)
    st.markdown('<div class="command-strip"><i></i><b>LIVE LINK</b> SUPABASE TELEMETRY <span>•</span> REFRESH 03 SEC <span>•</span> IPS POLICY ENFORCED</div>', unsafe_allow_html=True)
    connection_label = "Protection is connected" if supabase else "Connect your sensor to begin"
    connection_copy = "Your security events are flowing into this workspace." if supabase else "The dashboard is ready, but it needs a running Sentinel sensor and Supabase connection to show live events."
    st.markdown(f'<div class="setup-card"><strong>{connection_label}</strong><small>{connection_copy}</small><span class="status-pill">{"LIVE PROTECTION" if supabase else "SETUP REQUIRED"}</span></div>', unsafe_allow_html=True)
    st.write("")
    render_scene(df)

    cols = st.columns(4)
    cols[0].metric("INCIDENTS OBSERVED", total_count, "live window")
    cols[1].metric("CRITICAL SIGNALS", critical_count, "firewall policy")
    cols[2].metric("HIGH PRIORITY", high_count, "containment queue")
    cols[3].metric("UNIQUE ADVERSARIES", unique_ips, "source identities")

    filtered_df = df[df["severity"].isin(severity_filter)] if "severity" in df.columns and severity_filter else df
    log_col, evidence_col = st.columns([1.6, 1])
    with log_col:
        st.markdown('<div class="section-label">Recent protection activity</div>', unsafe_allow_html=True)
        if not filtered_df.empty:
            display_columns = [column for column in ["created_at", "source_ip", "country", "city", "attack_type", "target_ports_hit", "severity", "destination_ip"] if column in filtered_df.columns]
            friendly_names = {
                "created_at": "Time", "source_ip": "Source address", "country": "Country", "city": "City",
                "attack_type": "What we detected", "target_ports_hit": "Activity volume", "severity": "Risk", "destination_ip": "Protected destination",
            }
            st.dataframe(filtered_df[display_columns].rename(columns=friendly_names), use_container_width=True, hide_index=True, height=300)
        else:
            st.info("All clear. Sentinel is listening for unusual activity.")
    with evidence_col:
        st.markdown('<div class="section-label">Investigation files</div>', unsafe_allow_html=True)
        evidence_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), "evidence")
        pcap_files = [name for name in os.listdir(evidence_folder) if name.endswith(".pcap")] if os.path.exists(evidence_folder) else []
        if pcap_files:
            selected_pcap = st.selectbox("Select packet trace", pcap_files)
            with open(os.path.join(evidence_folder, selected_pcap), "rb") as evidence:
                st.download_button("Download PCAP", evidence, file_name=selected_pcap, mime="application/vnd.tcpdump.pcap", use_container_width=True)
        else:
            st.caption("No investigation files have been created yet.")
    if not df.empty:
        st.download_button("Export incident log", df.to_csv(index=False).encode("utf-8"), "sentinel_incident_report.csv", "text/csv")

render_live_board()