from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
import sqlite3, json, re, io, csv, ipaddress, os
import joblib
import numpy as np
from src.features import extract_url_features

ROOT = Path(__file__).resolve().parent
DB = ROOT / "smartshield.db"
MODEL_PATH = ROOT / "models" / "url_model.joblib"
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
MODEL = None
if MODEL_PATH.exists():
    try: MODEL = joblib.load(MODEL_PATH)
    except Exception: MODEL = None

def connect():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    with connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, mode TEXT,
            risk TEXT, score INTEGER, summary TEXT, preview TEXT, result TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS feedback(
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, category TEXT, message TEXT, email TEXT)""")
        c.execute("INSERT OR IGNORE INTO settings VALUES('save_history','true')")
        c.execute("INSERT OR IGNORE INTO settings VALUES('theme','dark')")

def get_setting(k, default=""):
    with connect() as c:
        r=c.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone()
    return r["value"] if r else default

def save_scan(mode, content, result):
    if get_setting("save_history","true") != "true": return
    with connect() as c:
        c.execute("INSERT INTO scans(created_at,mode,risk,score,summary,preview,result) VALUES(?,?,?,?,?,?,?)",
          (datetime.now(timezone.utc).isoformat(),mode,result["risk"],result["score"],result["summary"],str(content)[:180],json.dumps(result)))

def lexical_flags(url):
    p=urlparse(url if re.match(r"^https?://",url,re.I) else "http://"+url)
    host=p.hostname or ""
    flags=[]
    if not host: flags.append(("Malformed URL","The address could not be parsed.",16))
    if p.scheme=="http": flags.append(("Unencrypted scheme","HTTP does not encrypt the connection. HTTPS does not itself prove legitimacy.",7))
    if len(url)>90: flags.append(("Long URL","Long URLs can obscure the destination or contain excessive parameters.",7))
    try:
        ipaddress.ip_address(host); flags.append(("IP-based host","The address uses a raw IP instead of a domain name.",18))
    except Exception: pass
    if len(host.split("."))>=4: flags.append(("Multiple subdomains","Several subdomain labels may make the true domain harder to notice.",9))
    if "xn--" in host: flags.append(("Punycode hostname","Encoded internationalised domains can be used in look-alike attacks.",16))
    if "@" in url: flags.append(("At-sign in URL","An at-sign can make the displayed address confusing.",15))
    if host.count("-")>=3: flags.append(("Hyphen-heavy hostname","The hostname contains several hyphens.",6))
    if re.search(r"(login|verify|secure|account|update|wallet|bank|password|claim|bonus)",(host+p.path).lower()):
        flags.append(("Sensitive-action keywords","The address includes terms commonly used in account or reward lures.",8))
    return flags

def risk_result(score, flags, summary, model_info=None):
    score=max(0,min(100,int(score)))
    risk="HIGH" if score>=70 else "ELEVATED" if score>=40 else "GUARDED" if score>=18 else "LOW"
    return {"score":score,"risk":risk,"flags":[{"title":x[0],"detail":x[1],"weight":x[2]} for x in flags],
            "summary":summary,"model":model_info or {"name":"Heuristic fallback","status":"Not trained"},
            "actions": (["Do not open the link or reply. Do not share credentials or payment information.",
                         "Verify the organisation through its official app or a contact method you already trust.",
                         "Report the message or URL to the relevant provider/security team."] if risk=="HIGH" else
                        ["Pause before acting and verify the sender independently.",
                         "Do not enter passwords, OTPs, PINs or payment details through an unexpected link.",
                         "Use the organisation's official app or manually typed website address."] if risk in ("ELEVATED","GUARDED") else
                        ["No strong indicators were found by this model. This is not proof of safety.",
                         "Check the sender and domain carefully before sharing information."])}

def predict_url(url):
    url=str(url or "").strip()
    if not url: return None
    flags=lexical_flags(url)
    model_info={"name":"Lexical heuristic engine","status":"Fallback active"}
    score=min(100,sum(x[2] for x in flags))
    if MODEL is not None:
        try:
            feats=extract_url_features(url)
            proba=float(MODEL.predict_proba([feats])[0][1])
            pred=int(MODEL.predict([feats])[0])
            # 1 = phishing in our training pipeline
            score=int(round(proba*100))
            model_info={"name":"Random Forest URL classifier","status":"Trained model active",
                        "phishing_probability":round(proba,4),"prediction":"PHISHING" if pred==1 else "LEGITIMATE"}
        except Exception as e:
            model_info={"name":"Lexical heuristic engine","status":"Model unavailable; fallback used"}
    return risk_result(score,flags,"URL structure analysed locally. The destination website was not opened or contacted.",model_info)

def analyse_message(text):
    text=str(text or "")
    patterns=[
      ("Urgency and pressure",r"\b(urgent|immediately|act now|within \d+ hours?|final warning|suspended|blocked)\b",14,"The message attempts to create time pressure."),
      ("Credential / OTP request",r"\b(otp|password|passcode|pin|cvv|verification code|login details)\b",25,"It refers to credentials or one-time codes."),
      ("Payment / reward lure",r"\b(refund|prize|claim|gift card|transfer|upi|payment failed|cashback|lottery)\b",16,"It uses payment, refund or reward language."),
      ("Authority impersonation cues",r"\b(bank|tax department|police|courier|support team|customer care|government)\b",8,"A trusted organisation or authority is mentioned."),
      ("Threat / consequence",r"\b(account will be closed|legal action|penalty|arrest|deactivated)\b",15,"It threatens a negative consequence."),
      ("Hindi indicators",r"(खाता|बंद|तुरंत|ओटीपी|पासवर्ड|इनाम|भुगतान|जुर्माना|सत्यापित)",18,"Hindi-language urgency, account, credential or payment terms were found."),
      ("Kannada indicators",r"(ಖಾತೆ|ಮುಚ್ಚಲಾಗುತ್ತದೆ|ತಕ್ಷಣ|ಒಟಿಪಿ|ಪಾಸ್‌ವರ್ಡ್|ಬಹುಮಾನ|ಪಾವತಿ|ಪರಿಶೀಲಿಸಿ)",18,"Kannada-language account, urgency or credential terms were found."),
      ("Urdu indicators",r"(اکاؤنٹ|بند|فوری|او ٹی پی|پاس ورڈ|انعام|ادائیگی|تصدیق)",18,"Urdu-language account, urgency or credential terms were found."),
      ("Tamil indicators",r"(கணக்கு|முடக்க|உடனடியாக|ஓடிபி|கடவுச்சொல்|பரிசு|கட்டணம்|சரிபார்க்க)",18,"Tamil-language account, urgency or credential terms were found."),
      ("Telugu indicators",r"(ఖాతా|నిలిపివేయ|వెంటనే|ఓటీపీ|పాస్‌వర్డ్|బహుమతి|చెల్లింపు|ధృవీకరించ)",18,"Telugu-language account, urgency or credential terms were found."),
    ]
    flags=[]
    for title,pat,weight,detail in patterns:
        found=re.findall(pat,text,re.I)
        if found: flags.append((title,detail,weight))
    links=re.findall(r"(?:https?://|www\.)[^\s<>'\"]+",text,re.I)
    for link in links[:3]:
        for f in lexical_flags(link):
            flags.append((f[0],f[1],max(3,int(f[2]*.6))))
    if text.count("!")>=4: flags.append(("Excessive punctuation","Repeated exclamation marks can amplify pressure.",4))
    letters=[c for c in text if c.isalpha()]
    if len(letters)>30 and sum(c.isupper() for c in letters)/len(letters)>.4:
        flags.append(("Unusual capitalisation","A high uppercase ratio may be used to attract attention.",4))
    return risk_result(min(100,sum(f[2] for f in flags)),flags,
        "Message inspected for common social-engineering indicators. This is a screening aid, not a verdict.")

@app.get("/")
def index(): return render_template("index.html", theme=get_setting("theme","dark"))

@app.get("/api/health")
def health():
    return jsonify(status="operational",model="trained" if MODEL else "fallback",database="connected")

@app.post("/api/scan")
def scan():
    data=request.get_json(silent=True) or {}
    mode=data.get("mode","url"); content=str(data.get("content","")).strip()
    if not content: return jsonify(error="Enter content to analyse."),400
    if len(content)>12000: return jsonify(error="Input is too long. Maximum 12,000 characters."),413
    result=predict_url(content) if mode=="url" else analyse_message(content)
    result["mode"]=mode; result["timestamp"]=datetime.now(timezone.utc).isoformat()
    save_scan(mode,content,result)
    return jsonify(result)

@app.post("/api/ocr")
def ocr():
    f=request.files.get("image")
    if not f: return jsonify(error="Choose an image first."),400
    if f.mimetype not in ("image/png","image/jpeg","image/webp"): return jsonify(error="Use PNG, JPG or WEBP."),415
    try:
        from PIL import Image
        import pytesseract
        im=Image.open(io.BytesIO(f.read())).convert("RGB")
        text=pytesseract.image_to_string(im)[:12000]
        if not text.strip(): return jsonify(error="No readable text found in this screenshot."),422
        result=analyse_message(text); result["mode"]="screenshot"; result["extracted_text"]=text
        save_scan("screenshot",text,result); return jsonify(result)
    except ImportError: return jsonify(error="Install Pillow and pytesseract, plus the separate Tesseract OCR program. Alternatively paste the text into Message Scan."),501
    except Exception: return jsonify(error="Could not process this image. Try a clear PNG or JPG."),422

@app.get("/api/history")
def history():
    with connect() as c: rows=c.execute("SELECT id,created_at,mode,risk,score,summary,preview FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify(items=[dict(x) for x in rows])

@app.delete("/api/history")
def clear_history():
    with connect() as c: c.execute("DELETE FROM scans")
    return jsonify(status="cleared")

@app.get("/api/history/export")
def export_history():
    with connect() as c: rows=c.execute("SELECT id,created_at,mode,risk,score,summary,preview FROM scans ORDER BY id DESC").fetchall()
    out=io.StringIO(); w=csv.writer(out); w.writerow(["id","created_at","mode","risk","score","summary","preview"])
    w.writerows([tuple(r) for r in rows]); mem=io.BytesIO(out.getvalue().encode("utf-8-sig")); mem.seek(0)
    return send_file(mem,mimetype="text/csv",as_attachment=True,download_name="smartshield_scan_history.csv")

@app.get("/api/analytics")
def analytics():
    with connect() as c:
        rows=c.execute("SELECT risk,COUNT(*) n FROM scans GROUP BY risk").fetchall()
        daily=c.execute("SELECT substr(created_at,1,10) day,COUNT(*) n FROM scans GROUP BY day ORDER BY day DESC LIMIT 14").fetchall()
    metrics={"LOW":0,"GUARDED":0,"ELEVATED":0,"HIGH":0}
    for r in rows: metrics[r["risk"]]=r["n"]
    dataset={"name":"UCI PhiUSIIL Phishing URL Dataset","records":235795,"legitimate":134850,"phishing":100945,"features":54,
             "source":"https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset","label_note":"UCI label 1 = legitimate, 0 = phishing"}
    return jsonify(scans=metrics,daily=list(reversed([dict(x) for x in daily])),dataset=dataset,
                   model_status="trained" if MODEL else "not trained",model_metrics=load_metrics())

def load_metrics():
    p=ROOT/"reports"/"metrics.json"
    if p.exists():
        try: return json.loads(p.read_text())
        except Exception: pass
    return None

@app.get("/api/settings")
def settings():
    with connect() as c: rows=c.execute("SELECT key,value FROM settings").fetchall()
    return jsonify({r["key"]:r["value"] for r in rows})

@app.post("/api/settings")
def update_settings():
    d=request.get_json(silent=True) or {}
    with connect() as c:
        for k,v in d.items():
            if k=="save_history" and str(v).lower() in ("true","false"):
                c.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,str(v).lower()))
            if k=="theme" and v in ("dark","light"):
                c.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,v))
    return settings()

@app.post("/api/feedback")
def feedback():
    d=request.get_json(silent=True) or {}; msg=str(d.get("message","")).strip()
    if len(msg)<8: return jsonify(error="Please provide at least 8 characters."),400
    with connect() as c:
        c.execute("INSERT INTO feedback(created_at,category,message,email) VALUES(?,?,?,?)",
          (datetime.now(timezone.utc).isoformat(),str(d.get("category","General"))[:60],msg[:2000],str(d.get("email",""))[:120]))
    return jsonify(message="Feedback saved locally. Thank you.")

@app.get("/api/report/<int:scan_id>")
def report(scan_id):
    with connect() as c: row=c.execute("SELECT * FROM scans WHERE id=?",(scan_id,)).fetchone()
    if not row: return jsonify(error="Report not found."),404
    return jsonify(dict(row))

init_db()


# ---- Advanced investigation features ---------------------------------------
from email import policy
from email.parser import BytesParser
from urllib.request import Request as URLRequest, urlopen
from urllib.error import URLError, HTTPError

@app.post('/api/scan/email-file')
def scan_email_file():
    f=request.files.get('email_file')
    if not f: return jsonify(error='Choose an .eml file first.'),400
    if not f.filename.lower().endswith('.eml'): return jsonify(error='Only .eml email files are supported.'),415
    raw=f.read(2*1024*1024+1)
    if len(raw)>2*1024*1024: return jsonify(error='Email file exceeds 2 MB.'),413
    try:
        msg=BytesParser(policy=policy.default).parsebytes(raw)
        subject=str(msg.get('subject','(no subject)'))[:300]
        sender=str(msg.get('from','(unknown sender)'))[:300]
        reply_to=str(msg.get('reply-to',''))[:300]
        body=[]; links=[]; attachments=[]
        for part in msg.walk():
            if part.is_multipart(): continue
            filename=part.get_filename()
            if filename: attachments.append(filename[:160])
            if part.get_content_type()=='text/plain' and not filename:
                try: body.append(part.get_content())
                except Exception: pass
            if part.get_content_type()=='text/html' and not filename:
                try: body.append(re.sub(r'<[^>]+>',' ',part.get_content()))
                except Exception: pass
        text_body='\n'.join(body)[:12000]
        result=analyse_message('Subject: '+subject+'\nFrom: '+sender+'\nReply-To: '+reply_to+'\n'+text_body)
        if reply_to and sender and reply_to.lower()!=sender.lower():
            result['flags'].append({'title':'Reply-To differs from sender','detail':'The reply address differs from the visible sender address. Verify the sender independently.','weight':10})
            result['score']=min(100,result['score']+10)
            result['risk']='HIGH' if result['score']>=70 else 'ELEVATED' if result['score']>=40 else 'GUARDED' if result['score']>=18 else 'LOW'
        if attachments:
            result['flags'].append({'title':'Email attachments present','detail':'Attachments were listed but not opened or malware-scanned. Do not open unexpected files.','weight':5})
        result['email']={'subject':subject,'sender':sender,'reply_to':reply_to,'attachments':attachments}
        result['mode']='email-file'; result['summary']='Email headers and readable body text inspected. Attachments were not executed or scanned.'
        result['timestamp']=datetime.now(timezone.utc).isoformat()
        save_scan('email-file',subject+' | '+sender+' | '+text_body,result)
        return jsonify(result)
    except Exception: return jsonify(error='Could not parse this email file. Try a valid RFC 822 .eml file.'),422

@app.post('/api/scan/qr')
def scan_qr():
    f=request.files.get('qr_image')
    if not f: return jsonify(error='Choose a QR-code image first.'),400
    if f.mimetype not in ('image/png','image/jpeg','image/webp'): return jsonify(error='Use PNG, JPG or WEBP.'),415
    try:
        import cv2
        import numpy as np
        data=np.frombuffer(f.read(),np.uint8); image=cv2.imdecode(data,cv2.IMREAD_COLOR)
        if image is None: return jsonify(error='Could not read that image.'),422
        decoded,points,_=cv2.QRCodeDetector().detectAndDecode(image)
        if not decoded: return jsonify(error='No readable QR code was detected.'),422
        if re.match(r'^https?://',decoded,re.I): result=predict_url(decoded)
        else: result=analyse_message(decoded)
        result['mode']='qr-code'; result['decoded_content']=decoded[:2000]
        result['summary']='QR code decoded locally. The embedded destination was not opened.'
        result['timestamp']=datetime.now(timezone.utc).isoformat(); save_scan('qr-code',decoded,result)
        return jsonify(result)
    except ImportError: return jsonify(error='QR scanning needs OpenCV. Install it with: python -m pip install opencv-python-headless'),501
    except Exception: return jsonify(error='QR image could not be processed.'),422

@app.post('/api/threat-intel')
def threat_intel():
    d=request.get_json(silent=True) or {}; target=str(d.get('url','')).strip()
    if not target or len(target)>2048: return jsonify(error='Enter a URL up to 2,048 characters.'),400
    key=os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY','').strip()
    if not key: return jsonify(configured=False,error='Threat-intelligence lookup is not configured. Set GOOGLE_SAFE_BROWSING_API_KEY in your environment; no URL was sent.'),503
    import urllib.parse
    endpoint='https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+urllib.parse.quote(key)
    payload={'client':{'clientId':'smartshield-ai','clientVersion':'1.0'},'threatInfo':{'threatTypes':['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],'platformTypes':['ANY_PLATFORM'],'threatEntryTypes':['URL'],'threatEntries':[{'url':target}]}}
    try:
        req=URLRequest(endpoint,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'},method='POST')
        with urlopen(req,timeout=8) as resp: data=json.loads(resp.read().decode())
        matches=data.get('matches',[])
        return jsonify(configured=True,checked=True,listed=bool(matches),matches=[{'threat_type':m.get('threatType'),'platform':m.get('platformType')} for m in matches],note='Google Safe Browsing result. Absence of a match does not prove a URL is safe.')
    except HTTPError as e: return jsonify(error='Threat provider returned HTTP '+str(e.code)+'. Check the API key and quota.'),502
    except (URLError,TimeoutError): return jsonify(error='Threat-intelligence provider could not be reached.'),502

@app.get('/api/admin/summary')
def admin_summary():
    # This prototype binds to localhost. Keep this endpoint local-only.
    if request.remote_addr not in ('127.0.0.1','::1'): return jsonify(error='Local administrator endpoint only.'),403
    with connect() as c:
        total=c.execute('SELECT COUNT(*) n FROM scans').fetchone()['n']
        high=c.execute("SELECT COUNT(*) n FROM scans WHERE risk='HIGH'").fetchone()['n']
        modes=[dict(r) for r in c.execute('SELECT mode,COUNT(*) count FROM scans GROUP BY mode ORDER BY count DESC')]
        recent=[dict(r) for r in c.execute('SELECT id,created_at,mode,risk,score,summary FROM scans ORDER BY id DESC LIMIT 10')]
        feedback_count=c.execute('SELECT COUNT(*) n FROM feedback').fetchone()['n']
    return jsonify(total_scans=total,high_risk=high,feedback_count=feedback_count,modes=modes,recent=recent,model_status='trained' if MODEL else 'heuristic fallback',scope='Local prototype database only')

@app.get('/api/report/<int:scan_id>/pdf')
def report_pdf(scan_id):
    with connect() as c: row=c.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
    if not row: return jsonify(error='Report not found.'),404
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
        from reportlab.lib.units import mm
        result=json.loads(row['result'] or '{}'); mem=io.BytesIO(); doc=SimpleDocTemplate(mem,pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=18*mm,bottomMargin=18*mm)
        styles=getSampleStyleSheet(); story=[Paragraph('SmartShield AI — Security Analysis Report',styles['Title']),Spacer(1,8)]
        story.append(Paragraph('Educational screening report · '+str(row['created_at']),styles['Normal'])); story.append(Spacer(1,12))
        data=[['Scan ID',str(row['id'])],['Type',str(row['mode'])],['Risk',str(row['risk'])],['Score',str(row['score'])+'/100'],['Summary',str(row['summary'])]]
        t=Table(data,colWidths=[35*mm,135*mm]); t.setStyle(TableStyle([('BACKGROUND',(0,0),(0,-1),colors.HexColor('#e8eef6')),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#ccd5e0')),('VALIGN',(0,0),(-1,-1),'TOP'),('PADDING',(0,0),(-1,-1),7)])); story.extend([t,Spacer(1,12),Paragraph('Detected indicators',styles['Heading2'])])
        flags=result.get('flags',[])
        if flags:
            for flag in flags: story.append(Paragraph('<b>'+str(flag.get('title','Indicator'))+'</b> — '+str(flag.get('detail','')),styles['BodyText'])); story.append(Spacer(1,5))
        else: story.append(Paragraph('No configured warning indicators were found. This is not proof of safety.',styles['BodyText']))
        story.extend([Spacer(1,10),Paragraph('Recommended actions',styles['Heading2'])])
        for action in result.get('actions',[]): story.append(Paragraph('• '+str(action),styles['BodyText']))
        story.extend([Spacer(1,12),Paragraph('Limitations: This report is an educational screening aid, not a guarantee, forensic conclusion, or calibrated probability. Verify unexpected requests independently.',styles['Italic'])])
        doc.build(story); mem.seek(0); return send_file(mem,mimetype='application/pdf',as_attachment=True,download_name=f'smartshield-report-{scan_id}.pdf')
    except ImportError: return jsonify(error='PDF reporting needs ReportLab. Install with: python -m pip install reportlab'),501



if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
