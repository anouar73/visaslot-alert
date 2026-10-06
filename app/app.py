import os, sqlite3, hashlib, hmac, secrets, smtplib
from pathlib import Path
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Form, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

BASE = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv('DB_PATH', BASE.parent / 'data.db'))
SECRET_KEY = os.getenv('SECRET_KEY', 'change-me-in-production')
MONITOR_SECRET = os.getenv('MONITOR_SECRET', 'change-me-monitor')
BASE_URL = os.getenv('BASE_URL', 'http://localhost:8000')

app = FastAPI(title='VisaSlot Alert')
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=os.getenv('HTTPS_ONLY','0')=='1', same_site='lax')
app.mount('/static', StaticFiles(directory=BASE/'static'), name='static')
templates = Jinja2Templates(directory=str(BASE/'templates'))

def now(): return datetime.now(timezone.utc).isoformat()

def db():
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    return c

def init_db():
    c=db(); c.executescript('''
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      center TEXT NOT NULL,
      procedure TEXT NOT NULL,
      notify_email INTEGER NOT NULL DEFAULT 1,
      notify_whatsapp INTEGER NOT NULL DEFAULT 1,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS detections(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      center TEXT NOT NULL,
      procedure TEXT NOT NULL,
      slot_text TEXT NOT NULL,
      source_url TEXT,
      detected_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notification_log(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      detection_id INTEGER,
      channel TEXT NOT NULL,
      success INTEGER NOT NULL,
      detail TEXT,
      created_at TEXT NOT NULL
    );
    '''); c.commit(); c.close()
init_db()

def hash_password(password:str)->str:
    salt=secrets.token_bytes(16)
    dk=hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
    return f'{salt.hex()}${dk.hex()}'

def verify_password(password:str, stored:str)->bool:
    try:
        salt_hex, hash_hex = stored.split('$',1)
        calc=hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), 200_000).hex()
        return hmac.compare_digest(calc, hash_hex)
    except Exception: return False

def current_user(request:Request):
    uid=request.session.get('uid')
    if not uid: return None
    c=db(); u=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone(); c.close(); return u

def send_email(to_email:str, subject:str, body:str)->tuple[bool,str]:
    host=os.getenv('SMTP_HOST'); port=int(os.getenv('SMTP_PORT','587'))
    user=os.getenv('SMTP_USERNAME'); pwd=os.getenv('SMTP_PASSWORD'); sender=os.getenv('SMTP_FROM',user or '')
    if not host or not sender: return False,'SMTP non configuré'
    msg=EmailMessage(); msg['Subject']=subject; msg['From']=sender; msg['To']=to_email; msg.set_content(body)
    try:
        with smtplib.SMTP(host,port,timeout=20) as s:
            s.starttls()
            if user and pwd: s.login(user,pwd)
            s.send_message(msg)
        return True,'ok'
    except Exception as e: return False,str(e)[:250]

def send_whatsapp(phone:str, center:str, procedure:str, slot_text:str)->tuple[bool,str]:
    token=os.getenv('WHATSAPP_TOKEN'); pid=os.getenv('WHATSAPP_PHONE_NUMBER_ID')
    template=os.getenv('WHATSAPP_TEMPLATE_NAME','visa_slot_alert'); lang=os.getenv('WHATSAPP_TEMPLATE_LANG','fr')
    version=os.getenv('WHATSAPP_GRAPH_VERSION','v23.0')
    if not token or not pid or not phone: return False,'WhatsApp non configuré'
    payload={
      'messaging_product':'whatsapp','to':phone,'type':'template',
      'template':{'name':template,'language':{'code':lang},'components':[{'type':'body','parameters':[
        {'type':'text','text':center},{'type':'text','text':procedure},{'type':'text','text':slot_text}
      ]}]}
    }
    try:
        r=httpx.post(f'https://graph.facebook.com/{version}/{pid}/messages',headers={'Authorization':f'Bearer {token}'},json=payload,timeout=20)
        return r.is_success, (r.text[:250] if not r.is_success else 'ok')
    except Exception as e: return False,str(e)[:250]

@app.get('/', response_class=HTMLResponse)
def home(request:Request):
    return templates.TemplateResponse('index.html', {'request':request,'user':current_user(request)})

@app.get('/register', response_class=HTMLResponse)
def register_page(request:Request):
    return templates.TemplateResponse('register.html', {'request':request,'error':None})

@app.post('/register')
def register(request:Request, name:str=Form(...), email:str=Form(...), phone:str=Form(''), password:str=Form(...)):
    email=email.strip().lower()
    if len(password)<8:
        return templates.TemplateResponse('register.html', {'request':request,'error':'Mot de passe : 8 caractères minimum.'}, status_code=400)
    c=db()
    try:
        cur=c.execute('INSERT INTO users(name,email,phone,password_hash,created_at) VALUES(?,?,?,?,?)',(name.strip(),email,phone.strip(),hash_password(password),now()))
        c.commit(); request.session['uid']=cur.lastrowid
    except sqlite3.IntegrityError:
        c.close(); return templates.TemplateResponse('register.html', {'request':request,'error':'Cette adresse email existe déjà.'}, status_code=400)
    c.close(); return RedirectResponse('/dashboard',303)

@app.get('/login', response_class=HTMLResponse)
def login_page(request:Request):
    return templates.TemplateResponse('login.html', {'request':request,'error':None})

@app.post('/login')
def login(request:Request, email:str=Form(...), password:str=Form(...)):
    c=db(); u=c.execute('SELECT * FROM users WHERE email=?',(email.strip().lower(),)).fetchone(); c.close()
    if not u or not verify_password(password,u['password_hash']):
        return templates.TemplateResponse('login.html', {'request':request,'error':'Email ou mot de passe incorrect.'}, status_code=400)
    request.session['uid']=u['id']; return RedirectResponse('/dashboard',303)

@app.post('/logout')
def logout(request:Request):
    request.session.clear(); return RedirectResponse('/',303)

@app.get('/dashboard', response_class=HTMLResponse)
def dashboard(request:Request):
    u=current_user(request)
    if not u: return RedirectResponse('/login',303)
    c=db()
    alerts=c.execute('SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC',(u['id'],)).fetchall()
    detections=c.execute('''SELECT d.* FROM detections d JOIN alerts a ON lower(a.center)=lower(d.center) AND lower(a.procedure)=lower(d.procedure)
                            WHERE a.user_id=? ORDER BY d.id DESC LIMIT 25''',(u['id'],)).fetchall()
    logs=c.execute('SELECT * FROM notification_log WHERE user_id=? ORDER BY id DESC LIMIT 20',(u['id'],)).fetchall(); c.close()
    return templates.TemplateResponse('dashboard.html', {'request':request,'user':u,'alerts':alerts,'detections':detections,'logs':logs})

@app.post('/alerts')
def create_alert(request:Request, center:str=Form(...), procedure:str=Form(...), notify_email:Optional[str]=Form(None), notify_whatsapp:Optional[str]=Form(None)):
    u=current_user(request)
    if not u: return RedirectResponse('/login',303)
    c=db(); c.execute('INSERT INTO alerts(user_id,center,procedure,notify_email,notify_whatsapp,active,created_at) VALUES(?,?,?,?,?,1,?)',
        (u['id'],center.strip(),procedure.strip(),1 if notify_email else 0,1 if notify_whatsapp else 0,now())); c.commit(); c.close()
    return RedirectResponse('/dashboard',303)

@app.post('/alerts/{alert_id}/toggle')
def toggle_alert(alert_id:int, request:Request):
    u=current_user(request)
    if not u: return RedirectResponse('/login',303)
    c=db(); row=c.execute('SELECT active FROM alerts WHERE id=? AND user_id=?',(alert_id,u['id'])).fetchone()
    if row: c.execute('UPDATE alerts SET active=? WHERE id=?',(0 if row['active'] else 1,alert_id)); c.commit()
    c.close(); return RedirectResponse('/dashboard',303)

@app.post('/alerts/{alert_id}/delete')
def delete_alert(alert_id:int, request:Request):
    u=current_user(request)
    if not u: return RedirectResponse('/login',303)
    c=db(); c.execute('DELETE FROM alerts WHERE id=? AND user_id=?',(alert_id,u['id'])); c.commit(); c.close(); return RedirectResponse('/dashboard',303)

@app.post('/api/detections')
async def ingest_detection(payload:dict, x_monitor_secret:Optional[str]=Header(None)):
    if x_monitor_secret != MONITOR_SECRET: raise HTTPException(401,'secret invalide')
    center=str(payload.get('center','')).strip(); procedure=str(payload.get('procedure','')).strip(); slot=str(payload.get('slot_text','')).strip(); source=payload.get('source_url')
    if not center or not procedure or not slot: raise HTTPException(400,'données incomplètes')
    c=db(); cur=c.execute('INSERT INTO detections(center,procedure,slot_text,source_url,detected_at) VALUES(?,?,?,?,?)',(center,procedure,slot,source,now())); did=cur.lastrowid
    subs=c.execute('''SELECT a.*,u.email,u.phone,u.name FROM alerts a JOIN users u ON u.id=a.user_id
                      WHERE a.active=1 AND lower(a.center)=lower(?) AND lower(a.procedure)=lower(?)''',(center,procedure)).fetchall(); c.commit()
    subject=f'Créneau détecté — {center}'
    body=f'Bonjour,\n\nUn créneau correspondant à votre alerte a été détecté.\n\nCentre : {center}\nDémarche : {procedure}\nDétail : {slot}\nLien : {source or BASE_URL}\n\nRéservez manuellement sur le site officiel.'
    sent={'email':0,'whatsapp':0}
    for s in subs:
        if s['notify_email']:
            ok,detail=send_email(s['email'],subject,body); sent['email']+=1 if ok else 0
            c.execute('INSERT INTO notification_log(user_id,detection_id,channel,success,detail,created_at) VALUES(?,?,?,?,?,?)',(s['user_id'],did,'email',1 if ok else 0,detail,now()))
        if s['notify_whatsapp']:
            ok,detail=send_whatsapp(s['phone'],center,procedure,slot); sent['whatsapp']+=1 if ok else 0
            c.execute('INSERT INTO notification_log(user_id,detection_id,channel,success,detail,created_at) VALUES(?,?,?,?,?,?)',(s['user_id'],did,'whatsapp',1 if ok else 0,detail,now()))
    c.commit(); c.close()
    return {'ok':True,'detection_id':did,'matched':len(subs),'sent':sent}

@app.post('/api/test-email')
def test_email(request:Request):
    u=current_user(request)
    if not u: raise HTTPException(401)
    ok,detail=send_email(u['email'],'Test VisaSlot Alert','Ceci est un email de test de VisaSlot Alert. Votre canal email est correctement configuré.' )
    return JSONResponse({'ok':ok,'detail':detail}, status_code=200 if ok else 500)

@app.get('/health')
def health(): return {'ok':True,'time':now()}
