import os
import re
import math
import secrets
import string
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "wordlist.txt")

def load_wordlist():
    try:
        with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()

WORDLIST = load_wordlist()

def get_tips(password, analysis):
    tips_en, tips_ar = [], []
    if analysis["length"] < 8:
        tips_en.append("Use at least 8 characters — longer is always better.")
        tips_ar.append("استخدم 8 أحرف على الأقل — كلما كانت أطول كانت أفضل.")
    if analysis["length"] < 12:
        tips_en.append("Aim for 12+ characters for strong security.")
        tips_ar.append("استهدف 12 حرفاً أو أكثر لأمان قوي.")
    if not analysis["has_upper"]:
        tips_en.append("Add uppercase letters (A–Z) to increase complexity.")
        tips_ar.append("أضف أحرفاً كبيرة (A–Z) لزيادة التعقيد.")
    if not analysis["has_lower"]:
        tips_en.append("Include lowercase letters (a–z) for variety.")
        tips_ar.append("أضف أحرفاً صغيرة (a–z) لمزيد من التنوع.")
    if not analysis["has_digit"]:
        tips_en.append("Mix in numbers (0–9) to strengthen the password.")
        tips_ar.append("أضف أرقاماً (0–9) لتقوية كلمة المرور.")
    if not analysis["has_symbol"]:
        tips_en.append("Add symbols like !@#$%^& for maximum strength.")
        tips_ar.append("أضف رموزاً مثل !@#$%^& لأقصى قوة.")
    if re.search(r'(.)\1{2,}', password):
        tips_en.append("Avoid repeating the same character (e.g. 'aaa').")
        tips_ar.append("تجنب تكرار نفس الحرف (مثل 'aaa').")
    seqs = ["123","234","345","456","567","678","789","abc","bcd","cde","qwerty","asdf"]
    if any(s in password.lower() for s in seqs):
        tips_en.append("Avoid sequential patterns like '123' or 'abc'.")
        tips_ar.append("تجنب الأنماط المتسلسلة مثل '123' أو 'abc'.")
    walks = ["qwerty","asdfgh","zxcvbn","qazwsx","1qaz","2wsx"]
    if any(w in password.lower() for w in walks):
        tips_en.append("Avoid keyboard patterns like 'qwerty' or 'asdfgh'.")
        tips_ar.append("تجنب أنماط لوحة المفاتيح مثل 'qwerty'.")
    if not tips_en:
        tips_en.append("Great job! Your password looks solid.")
        tips_ar.append("عمل رائع! كلمة مرورك تبدو قوية.")
    return {"en": tips_en, "ar": tips_ar}

def analyse_password(password):
    length     = len(password)
    has_lower  = bool(re.search(r'[a-z]', password))
    has_upper  = bool(re.search(r'[A-Z]', password))
    has_digit  = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))
    pool = (26 if has_lower else 0) + (26 if has_upper else 0) + \
           (10 if has_digit else 0) + (32 if has_symbol else 0)
    pool    = max(pool, 1)
    entropy = length * math.log2(pool)
    checks  = sum([has_lower, has_upper, has_digit, has_symbol])
    raw     = min(100, int(entropy * 100 / 128))
    if length < 8 or entropy < 40:
        strength, color, score = "Weak",        "#ef4444", min(raw, 30)
    elif entropy < 60 or checks < 3:
        strength, color, score = "Medium",      "#f59e0b", min(raw, 65)
    elif entropy < 80:
        strength, color, score = "Strong",      "#10b981", min(raw, 85)
    else:
        strength, color, score = "Very Strong", "#06b6d4", min(100, raw)
    ar_map    = {"Weak":"ضعيفة","Medium":"متوسطة","Strong":"قوية","Very Strong":"قوية جداً"}
    emoji_map = {"Weak":"😡","Medium":"😐","Strong":"💪","Very Strong":"🔐"}
    return {
        "strength": strength, "strength_ar": ar_map[strength],
        "emoji": emoji_map[strength], "color": color, "score": score,
        "entropy": round(entropy,1), "length": length,
        "has_lower": has_lower, "has_upper": has_upper,
        "has_digit": has_digit, "has_symbol": has_symbol, "checks": checks,
    }

ATTACK_SPEED = 1_000_000_000

def estimate_crack_time(entropy):
    combos  = 2 ** min(entropy, 256)
    seconds = combos / (2 * ATTACK_SPEED)
    if seconds < 1:       return {"en":"Less than a second","ar":"أقل من ثانية","tier":"instant"}
    elif seconds < 60:    return {"en":f"{int(seconds)} seconds","ar":f"{int(seconds)} ثانية","tier":"seconds"}
    elif seconds < 3600:  m=int(seconds/60);   return {"en":f"{m} minutes","ar":f"{m} دقيقة","tier":"minutes"}
    elif seconds < 86400: h=int(seconds/3600); return {"en":f"{h} hours","ar":f"{h} ساعة","tier":"hours"}
    elif seconds < 31_536_000: d=int(seconds/86400); return {"en":f"{d} days","ar":f"{d} يوم","tier":"days"}
    elif seconds < 3_153_600_000: y=int(seconds/31_536_000); return {"en":f"{y} years","ar":f"{y} سنة","tier":"years"}
    else: return {"en":"Centuries+","ar":"قرون+","tier":"centuries"}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/generate", methods=["POST"])
def generate_password():
    data     = request.get_json(silent=True) or {}
    length   = max(8, min(64, int(data.get("length", 16))))
    pool     = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    sym_pool = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    chars    = [secrets.choice(string.ascii_lowercase),
                secrets.choice(string.ascii_uppercase),
                secrets.choice(string.digits),
                secrets.choice(sym_pool)] + \
               [secrets.choice(pool) for _ in range(length - 4)]
    # Cryptographically secure shuffle via Fisher-Yates with secrets
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    password = "".join(chars)
    analysis = analyse_password(password)
    return jsonify({"password": password, "analysis": analysis,
                    "tips": get_tips(password, analysis),
                    "crack_estimate": estimate_crack_time(analysis["entropy"])})

@app.route("/api/check", methods=["POST"])
def check_password():
    data     = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    if len(password) > 512:
        return jsonify({"error": "Password too long (max 512 characters)"}), 400
    in_wordlist = password.lower() in WORDLIST
    analysis    = analyse_password(password)
    return jsonify({**analysis,
                    "in_wordlist": in_wordlist,
                    "tips": get_tips(password, analysis),
                    "crack_estimate": estimate_crack_time(analysis["entropy"])})

@app.route("/api/crack", methods=["POST"])
def crack_simulation():
    data     = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    if len(password) > 512:
        return jsonify({"error": "Password too long (max 512 characters)"}), 400
    in_wordlist = password.lower() in WORDLIST
    analysis    = analyse_password(password)
    crack       = estimate_crack_time(analysis["entropy"])
    if in_wordlist:
        rt,dg,dur = "cracked","critical",1.5
        me,ma = "❌ CRACKED! Found in common password database instantly.", "❌ تم الاختراق! وُجدت في قاعدة بيانات كلمات المرور الشائعة فوراً."
    elif analysis["strength"] == "Weak":
        rt,dg,dur = "cracked","critical",3.0
        me,ma = "❌ CRACKED! Weak password — brute-forced in seconds.", "❌ تم الاختراق! كلمة مرور ضعيفة — تم كسرها بالقوة في ثوانٍ."
    elif analysis["strength"] == "Medium":
        rt,dg,dur = "warning","warning",5.0
        me,ma = "⚠️ AT RISK. A determined attacker could crack this.", "⚠️ في خطر. يمكن لمهاجم متصمم اختراق هذه الكلمة."
    else:
        rt,dg,dur = "safe","safe",6.5
        me,ma = "✅ SECURE. This password would take an extremely long time to crack.", "✅ آمنة. ستستغرق هذه الكلمة وقتاً طويلاً جداً لاختراقها."
    return jsonify({"in_wordlist":in_wordlist,"result_type":rt,"danger_level":dg,
                    "sim_duration":dur,"message_en":me,"message_ar":ma,
                    "crack_estimate":crack,"analysis":analysis})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
