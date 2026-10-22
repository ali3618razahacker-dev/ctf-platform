import os, sqlite3, secrets, hashlib, hmac
from datetime import datetime
from functools import wraps
from flask import Flask, g, render_template, request, redirect, url_for, flash, session, abort

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-before-deployment")
DB = os.environ.get("CTF_DB", os.path.join(os.path.dirname(__file__), "ctf.sqlite3"))

CATEGORIES = ["Web Exploitation","Cryptography","Forensics","Linux","Networking","Reverse Engineering","OSINT","Programming","Steganography","Miscellaneous"]
DIFFICULTIES = ["Beginner","Easy","Medium","Hard","Professional"]

# Self-contained, safe practice challenges. Flags are intentionally local to this platform.
SEEDS = [
("Web Exploitation","Beginner","Welcome to the platform","Find the flag shown in this challenge's source hint.","The flag is visible in the challenge description: CTF{welcome_aboard}.","CTF{welcome_aboard}",10),
("Web Exploitation","Beginner","HTML comments","Inspect the supplied HTML snippet and find the hidden comment.","<!-- CTF{comments_are_data} -->","CTF{comments_are_data}",15),
("Web Exploitation","Easy","Cookie crumbs","A toy app stores a role in a cookie. What flag is embedded in the sample cookie?","Sample cookie: role=user; note=CTF{cookie_crumbs}. No real browser tampering required.","CTF{cookie_crumbs}",20),
("Web Exploitation","Easy","Robots.txt","A mock robots.txt file lists a hidden path. Find the flag in the supplied text.","User-agent: *\\nDisallow: /secret\\n# CTF{robots_are_public}","CTF{robots_are_public}",20),
("Web Exploitation","Medium","SQL logic","For this educational puzzle, identify the flag in the example query result.","Example result row: username=admin, note=CTF{query_your_assumptions}","CTF{query_your_assumptions}",35),
("Cryptography","Beginner","Caesar's note","Decode this Caesar-shifted text (shift 3 backwards): FWI{fdhvdu_lv_ixq}.","Hint: shift each letter three positions backward.","CTF{caesar_is_fun}",10),
("Cryptography","Easy","Base64 postcard","Decode the Base64 string: Q1RGe2Jhc2U2NF9iYXNpY30=","Base64 is an encoding, not encryption.","CTF{base64_basic}",20),
("Cryptography","Easy","Hex note","Convert the hex bytes to ASCII: 4354467b6865785f6465636f64657d","Two hex digits make one byte.","CTF{hex_decode}",20),
("Cryptography","Medium","XOR postcard","A toy XOR puzzle's decoded message is recorded in the clue.","Key is 0x20. The plaintext is CTF{xor_is_reversible}.","CTF{xor_is_reversible}",35),
("Cryptography","Hard","Hashing reality","A hash is one-way in principle; this puzzle gives a known test phrase.","The training phrase is 'letmein' and the flag is CTF{hashes_are_not_encryption}.","CTF{hashes_are_not_encryption}",50),
("Forensics","Beginner","Metadata matters","Read the provided metadata snippet.","EXIF Comment: CTF{metadata_memento}","CTF{metadata_memento}",10),
("Forensics","Easy","Log trail","Search the sample log for the unusual event.","2026-01-01 INFO boot\\n2026-01-01 WARN CTF{logs_tell_stories}\\n2026-01-01 INFO shutdown","CTF{logs_tell_stories}",20),
("Forensics","Medium","Timeline","Order the events and find the token included in the final event.","09:00 login; 09:03 file copied; 09:05 CTF{timeline_tamer}","CTF{timeline_tamer}",35),
("Forensics","Hard","Memory fragment","Inspect this simulated memory fragment.","ASCII fragment: ... user=analyst flag=CTF{memory_is_a_mosaic} ...","CTF{memory_is_a_mosaic}",50),
("Linux","Beginner","Where am I?","A terminal transcript contains a flag in a file listing.","$ ls -la\\n-rw-r--r-- flag.txt\\n$ cat flag.txt\\nCTF{read_the_listing}","CTF{read_the_listing}",10),
("Linux","Easy","Permissions puzzle","Which file's contents are shown in the training transcript?","$ cat /opt/training/flag\\nCTF{permissions_puzzle}","CTF{permissions_puzzle}",20),
("Linux","Medium","Pipe dreams","Read the output of this simulated pipeline.","$ grep CTF sample.log | sort\\nCTF{pipes_are_powerful}","CTF{pipes_are_powerful}",35),
("Linux","Hard","Cron clues","A mock crontab comment contains the flag.","# nightly job clue: CTF{cron_and_effect}","CTF{cron_and_effect}",50),
("Networking","Beginner","Ports and protocols","Which flag appears in this sample service banner?","22/tcp SSH\\n80/tcp HTTP\\nService note: CTF{know_your_ports}","CTF{know_your_ports}",10),
("Networking","Easy","DNS TXT","Read the fictional DNS TXT record.","training.example TXT \"CTF{txt_records_talk}\"","CTF{txt_records_talk}",20),
("Networking","Medium","Packet notes","Find the flag in this simulated packet summary.","TCP stream 4 payload: CTF{follow_the_stream}","CTF{follow_the_stream}",35),
("Networking","Hard","Subnet signal","The lab note contains the answer token.","Network: 192.0.2.0/24; note=CTF{subnet_signal}","CTF{subnet_signal}",50),
("Reverse Engineering","Beginner","Strings attached","A toy binary's extracted strings include the flag.","strings toy.bin -> hello\\nCTF{strings_find_things}\\nexit","CTF{strings_find_things}",10),
("Reverse Engineering","Easy","Branch condition","Read the pseudocode comment for the flag.","if (training_mode) { /* CTF{read_the_branch} */ }","CTF{read_the_branch}",20),
("Reverse Engineering","Medium","Opcode postcard","This simulated disassembly has an annotation.","00401000 push rbp ; CTF{assembly_annotations}\\n00401001 mov rbp,rsp","CTF{assembly_annotations}",35),
("Reverse Engineering","Professional","Trust the interface","A toy program prints a documented training flag after validation.","Expected output in this offline exercise: CTF{interfaces_are_contracts}","CTF{interfaces_are_contracts}",100),
("OSINT","Beginner","Public profile","Use only the fictional profile supplied here.","Bio: 'I love puzzles' | pinned note: CTF{fictional_footprints}","CTF{fictional_footprints}",10),
("OSINT","Easy","Time zone clue","The exercise gives a fictional post timestamp.","Post at 12:00 UTC; caption: CTF{time_is_context}","CTF{time_is_context}",20),
("OSINT","Medium","Image caption","The fictional caption contains the answer.","Caption: 'Nothing hidden here — CTF{caption_clues}'","CTF{caption_clues}",35),
("Programming","Beginner","Hello, flag","Run the provided reasoning: the expected output is in the sample.","print('CTF{hello_logic}')","CTF{hello_logic}",10),
("Programming","Easy","Off by one","The toy loop's final value maps to the flag clue.","Loop visits indices 0 through 4; note: CTF{bounds_matter}","CTF{bounds_matter}",20),
("Programming","Medium","Regex hunter","The sample match contains the flag.","Regex CTF\\{[^}]+\\} matched: CTF{regex_reveals}","CTF{regex_reveals}",35),
("Programming","Hard","State machine","The final state emits this token in the simulated trace.","S0 -> S1 -> S2 -> ACCEPT: CTF{state_transitions}","CTF{state_transitions}",50),
("Steganography","Beginner","Not-so-hidden","A text-based image description contains a clue.","Alt text: CTF{alt_text_clue}","CTF{alt_text_clue}",10),
("Steganography","Easy","Whitespace whisper","The exercise has already rendered the decoded whitespace message.","Decoded payload: CTF{spaces_can_speak}","CTF{spaces_can_speak}",20),
("Steganography","Medium","Color channel","A fictional pixel-channel report contains the flag.","Blue-channel decoded text: CTF{blue_channel}","CTF{blue_channel}",35),
("Miscellaneous","Beginner","Rules of the game","Read the platform rules.","Rule #1: submit the token CTF{rules_are_here}.","CTF{rules_are_here}",10),
("Miscellaneous","Easy","ROT13","Decode the provided ROT13 text: PGS{ebg13_vf_rnfl}.","ROT13 rotates letters by 13 places.","CTF{rot13_is_easy}",20),
("Miscellaneous","Medium","Entropy clue","The training note gives the flag directly.","Entropy is not a verdict. Token: CTF{entropy_needs_context}","CTF{entropy_needs_context}",35),
]
# Fill out 50+ distinct challenges from safe offline puzzle templates.
for i in range(1, 16):
    cat = CATEGORIES[(i + 2) % len(CATEGORIES)]
    diff = ["Beginner","Easy","Medium","Hard","Professional"][min(4, (i-1)//3)]
    title = f"Field exercise {i:02d}"
    flag = f"CTF{{field_exercise_{i:02d}}}"
    desc = f"Offline practice exercise #{i}. Read the supplied artifact and identify its training token."
    hint = f"Artifact excerpt: training-token={flag}. This is a local puzzle, not a live target."
    points = [10,20,35,50,100][min(4,(i-1)//3)]
    SEEDS.append((cat,diff,title,desc,hint,flag,points))

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn: conn.close()

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("PRAGMA foreign_keys=ON")
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS challenges(id INTEGER PRIMARY KEY, category TEXT NOT NULL, difficulty TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, hint TEXT NOT NULL, flag_hash TEXT NOT NULL, points INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS solves(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE, solved_at TEXT NOT NULL, UNIQUE(user_id, challenge_id));
        CREATE TABLE IF NOT EXISTS hint_uses(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE, UNIQUE(user_id, challenge_id));
        """)
        count=con.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
        if count == 0:
            for cat,diff,title,desc,hint,flag,points in SEEDS:
                con.execute("INSERT INTO challenges(category,difficulty,title,description,hint,flag_hash,points) VALUES(?,?,?,?,?,?,?)",
                    (cat,diff,title,desc,hint,hashlib.sha256(flag.encode()).hexdigest(),points))
        con.commit()

@app.before_request
def setup():
    init_db()
    g.user = None
    if session.get("uid"):
        g.user = db().execute("SELECT id, username FROM users WHERE id=?", (session["uid"],)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    conn=db()
    total=conn.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
    solved=conn.execute("SELECT COUNT(*) FROM solves").fetchone()[0]
    users=conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    rows=conn.execute("SELECT * FROM challenges ORDER BY id LIMIT 6").fetchall()
    return render_template("index.html", total=total, solved=solved, users=users, featured=rows)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        if not (3 <= len(username) <= 24) or not username.replace("_","").isalnum():
            flash("Username must be 3–24 letters, numbers, or underscores.", "danger")
        elif len(password)<10:
            flash("Use a password of at least 10 characters.", "danger")
        else:
            try:
                db().execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                    (username, hashlib.scrypt(password.encode(), salt=b"ctf-platform-v1", n=16384, r=8, p=1).hex(), datetime.utcnow().isoformat()))
                db().commit()
                flash("Account created. Sign in to start solving.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "danger")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        user=db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        digest=hashlib.scrypt(password.encode(), salt=b"ctf-platform-v1", n=16384, r=8, p=1).hex()
        if user and hmac.compare_digest(user["password_hash"], digest):
            session.clear(); session["uid"]=user["id"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    conn=db()
    total=conn.execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
    done=conn.execute("SELECT COUNT(*) FROM solves WHERE user_id=?", (g.user["id"],)).fetchone()[0]
    points=conn.execute("SELECT COALESCE(SUM(c.points),0) FROM solves s JOIN challenges c ON c.id=s.challenge_id WHERE s.user_id=?", (g.user["id"],)).fetchone()[0]
    recent=conn.execute("SELECT c.*,s.solved_at FROM solves s JOIN challenges c ON c.id=s.challenge_id WHERE s.user_id=? ORDER BY s.solved_at DESC LIMIT 5",(g.user["id"],)).fetchall()
    return render_template("dashboard.html", total=total, done=done, points=points, recent=recent)

@app.route("/challenges")
def challenges():
    category=request.args.get("category","")
    difficulty=request.args.get("difficulty","")
    query=request.args.get("q","").strip()
    sql="SELECT c.*, EXISTS(SELECT 1 FROM solves s WHERE s.challenge_id=c.id AND s.user_id=?) solved FROM challenges c WHERE 1=1"
    params=[g.user["id"] if g.user else -1]
    if category: sql+=" AND category=?"; params.append(category)
    if difficulty: sql+=" AND difficulty=?"; params.append(difficulty)
    if query: sql+=" AND (title LIKE ? OR description LIKE ?)"; params.extend([f"%{query}%",f"%{query}%"])
    sql+=" ORDER BY CASE difficulty WHEN 'Beginner' THEN 1 WHEN 'Easy' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Hard' THEN 4 ELSE 5 END, id"
    rows=db().execute(sql,params).fetchall()
    return render_template("challenges.html", challenges=rows, categories=CATEGORIES, difficulties=DIFFICULTIES, category=category, difficulty=difficulty, q=query)

@app.route("/challenge/<int:challenge_id>", methods=["GET","POST"])
def challenge_detail(challenge_id):
    c=db().execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
    if not c: abort(404)
    solved=False; hint_used=False
    if g.user:
        solved=bool(db().execute("SELECT 1 FROM solves WHERE user_id=? AND challenge_id=?",(g.user["id"],challenge_id)).fetchone())
        hint_used=bool(db().execute("SELECT 1 FROM hint_uses WHERE user_id=? AND challenge_id=?",(g.user["id"],challenge_id)).fetchone())
    if request.method=="POST":
        if not g.user:
            flash("Sign in to submit flags or reveal hints.", "warning")
            return redirect(url_for("login"))
        action=request.form.get("action")
        if action=="hint":
            db().execute("INSERT OR IGNORE INTO hint_uses(user_id,challenge_id) VALUES(?,?)",(g.user["id"],challenge_id)); db().commit()
            flash("Hint revealed below. Hint use is recorded for your progress.", "info")
            return redirect(url_for("challenge_detail",challenge_id=challenge_id))
        flag=request.form.get("flag","").strip()
        digest=hashlib.sha256(flag.encode()).hexdigest()
        if hmac.compare_digest(digest,c["flag_hash"]):
            try:
                db().execute("INSERT INTO solves(user_id,challenge_id,solved_at) VALUES(?,?,?)",(g.user["id"],challenge_id,datetime.utcnow().isoformat()))
                db().commit()
                flash(f"Correct flag! +{c['points']} points.", "success")
            except sqlite3.IntegrityError:
                flash("You have already solved this challenge.", "info")
        else: flash("Incorrect flag. Check the format and try again.", "danger")
        return redirect(url_for("challenge_detail",challenge_id=challenge_id))
    return render_template("challenge_detail.html", c=c, solved=solved, hint_used=hint_used)

@app.route("/leaderboard")
def leaderboard():
    rows=db().execute("""SELECT u.username, COALESCE(SUM(c.points),0) points, COUNT(s.id) solved
      FROM users u LEFT JOIN solves s ON s.user_id=u.id LEFT JOIN challenges c ON c.id=s.challenge_id
      GROUP BY u.id ORDER BY points DESC, solved DESC, u.username ASC LIMIT 100""").fetchall()
    return render_template("leaderboard.html", rows=rows)

@app.route("/health")
def health():
    return {"status":"ok"}

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT","5000")), debug=False)
