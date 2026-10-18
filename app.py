import os
import re
import sqlite3
import ipaddress

from datetime import datetime
from functools import wraps
from urllib.parse import urlsplit

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==================================================
# FLASK CONFIGURATION
# ==================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "cyber-nexa-dev-key-change-before-deployment"
)

DATABASE = os.path.join(
    app.root_path,
    "cyber_nexa.db"
)


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db():
    conn = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    return conn


# ==================================================
# DATABASE TABLES
# ==================================================

def init_db():
    with get_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subject TEXT,
                email_text TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)


# ==================================================
# LOGIN PROTECTION
# ==================================================

def login_required(view_function):

    @wraps(view_function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash(
                "Please login to continue.",
                "error"
            )

            return redirect(url_for("login"))

        return view_function(*args, **kwargs)

    return wrapper


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():
    return render_template("index.html")


# ==================================================
# SIGNUP
# ==================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not all([
            username,
            email,
            password,
            confirm_password
        ]):
            flash(
                "Please fill in all fields.",
                "error"
            )

            return render_template("signup.html")

        if len(username) > 50:
            flash(
                "Username must be 50 characters or fewer.",
                "error"
            )

            return render_template("signup.html")

        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        ):
            flash(
                "Enter a valid email address.",
                "error"
            )

            return render_template("signup.html")

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )

            return render_template("signup.html")

        if password != confirm_password:
            flash(
                "Passwords do not match.",
                "error"
            )

            return render_template("signup.html")

        try:

            with get_db() as conn:
                conn.execute("""
                    INSERT INTO users (
                        username,
                        email,
                        password_hash
                    )
                    VALUES (?, ?, ?)
                """, (
                    username,
                    email,
                    generate_password_hash(password)
                ))

            flash(
                "Account created successfully. Please login.",
                "success"
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash(
                "This email is already registered.",
                "error"
            )

        except sqlite3.Error:

            app.logger.exception(
                "Signup database error."
            )

            flash(
                "Unable to create account right now.",
                "error"
            )

    return render_template("signup.html")


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        if not email or not password:

            flash(
                "Enter your email and password.",
                "error"
            )

            return render_template("login.html")

        try:

            with get_db() as conn:
                user = conn.execute("""
                    SELECT
                        id,
                        username,
                        email,
                        password_hash
                    FROM users
                    WHERE email = ?
                """, (email,)).fetchone()

        except sqlite3.Error:

            app.logger.exception(
                "Login database error."
            )

            flash(
                "Unable to login right now.",
                "error"
            )

            return render_template("login.html")

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            try:

                with get_db() as conn:
                    conn.execute("""
                        INSERT INTO login_history (
                            user_id
                        )
                        VALUES (?)
                    """, (
                        user["id"],
                    ))

            except sqlite3.Error:

                app.logger.exception(
                    "Unable to save login history."
                )

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Incorrect email or password.",
            "error"
        )

    return render_template("login.html")


# ==================================================
# URL ANALYSIS
# ==================================================

def analyze_url(url):

    score = 0
    reasons = []

    try:

        parsed = urlsplit(url)
        hostname = parsed.hostname

        if (
            parsed.scheme not in ("http", "https")
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return {
                "prediction": "INVALID",
                "risk_score": 0,
                "reasons": [
                    "Invalid URL format."
                ]
            }

        hostname = hostname.lower()

        if parsed.scheme != "https":
            score += 15

            reasons.append(
                "HTTPS is not being used."
            )

        try:

            ipaddress.ip_address(hostname)
            score += 30

            reasons.append(
                "The hostname is an IP address."
            )

        except ValueError:
            pass

        if "@" in url:
            score += 20

            reasons.append(
                "The URL contains an @ symbol."
            )

        suspicious_words = [
            "verify-account",
            "login-secure",
            "password-reset",
            "account-verify",
            "free-prize",
            "claim-reward"
        ]

        matched_words = [
            word for word in suspicious_words
            if word in url.lower()
        ]

        if matched_words:

            score += 25

            reasons.append(
                "Suspicious keywords: "
                + ", ".join(matched_words)
            )

        if len(url) > 100:

            score += 10

            reasons.append(
                "The URL is unusually long."
            )

        if hostname.count(".") >= 4:

            score += 15

            reasons.append(
                "The hostname contains many subdomains."
            )

        score = min(score, 100)

        if score >= 60:
            prediction = "HIGH RISK"

        elif score >= 30:
            prediction = "SUSPICIOUS"

        else:
            prediction = "LOW RISK"

        if not reasons:

            reasons.append(
                "No suspicious patterns from the current rules were detected."
            )

        return {
            "prediction": prediction,
            "risk_score": score,
            "reasons": reasons
        }

    except ValueError:

        return {
            "prediction": "INVALID",
            "risk_score": 0,
            "reasons": [
                "Unable to parse the URL."
            ]
        }


# ==================================================
# EMAIL ANALYSIS
# ==================================================

def analyze_email(email_text):

    score = 0
    reasons = []

    text = email_text.lower()

    urgent_phrases = [
        "account suspended",
        "verify your account",
        "urgent action required",
        "password expires",
        "claim your reward",
        "you have won",
        "confirm your password",
        "send your otp",
        "bank account blocked"
    ]

    matched_phrases = [
        phrase for phrase in urgent_phrases
        if phrase in text
    ]

    if matched_phrases:

        score += min(
            len(matched_phrases) * 20,
            60
        )

        reasons.append(
            "Suspicious phrases: "
            + ", ".join(matched_phrases)
        )

    sensitive_words = [
        "otp",
        "one-time password",
        "bank password",
        "credit card number"
    ]

    if any(
        word in text
        for word in sensitive_words
    ):

        score += 25

        reasons.append(
            "The message refers to sensitive credentials or financial information."
        )

    if re.search(
        r"https?://(?:bit\.ly|tinyurl\.com|t\.co|is\.gd)/\S+",
        text
    ):

        score += 20

        reasons.append(
            "A shortened link was found."
        )

    score = min(score, 100)

    if score >= 60:
        prediction = "HIGH RISK"

    elif score >= 30:
        prediction = "SUSPICIOUS"

    else:
        prediction = "LOW RISK"

    if not reasons:

        reasons.append(
            "No suspicious patterns from the current rules were detected."
        )

    return {
        "prediction": prediction,
        "risk_score": score,
        "reasons": reasons
    }


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user_id = session["user_id"]

    try:

        with get_db() as conn:

            url_total = conn.execute("""
                SELECT COUNT(*) AS total
                FROM url_scans
                WHERE user_id = ?
            """, (
                user_id,
            )).fetchone()["total"]

            email_total = conn.execute("""
                SELECT COUNT(*) AS total
                FROM email_scans
                WHERE user_id = ?
            """, (
                user_id,
            )).fetchone()["total"]

            url_threats = conn.execute("""
                SELECT COUNT(*) AS total
                FROM url_scans
                WHERE user_id = ?
                AND prediction IN (
                    'HIGH RISK',
                    'SUSPICIOUS'
                )
            """, (
                user_id,
            )).fetchone()["total"]

            email_threats = conn.execute("""
                SELECT COUNT(*) AS total
                FROM email_scans
                WHERE user_id = ?
                AND prediction IN (
                    'HIGH RISK',
                    'SUSPICIOUS'
                )
            """, (
                user_id,
            )).fetchone()["total"]

            recent_urls = conn.execute("""
                SELECT
                    url,
                    prediction,
                    risk_score,
                    created_at
                FROM url_scans
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 5
            """, (
                user_id,
            )).fetchall()

        total_scans = url_total + email_total
        threats_total = url_threats + email_threats

        if total_scans == 0:
            security_score = 100

        else:
            security_score = round(
                100 * (total_scans - threats_total)
                / total_scans
            )

        security_score = max(
            0,
            min(100, security_score)
        )

        return render_template(
            "dashboard.html",
            username=session.get("username", "User"),
            url_total=url_total,
            email_total=email_total,
            threats_total=threats_total,
            recent_urls=recent_urls,
            total_scans=total_scans,
            security_score=security_score
        )

    except sqlite3.Error:

        app.logger.exception(
            "Dashboard database error."
        )

        flash(
            "Unable to load dashboard statistics.",
            "error"
        )

        return render_template(
            "dashboard.html",
            username=session.get("username", "User"),
            url_total=0,
            email_total=0,
            threats_total=0,
            recent_urls=[],
            total_scans=0,
            security_score=0
        )


# ==================================================
# URL SCANNER
# ==================================================

@app.route(
    "/url-scanner",
    methods=["GET", "POST"]
)
@login_required
def url_scanner():

    result = None
    scanned_url = ""

    if request.method == "POST":

        scanned_url = request.form.get(
            "url", ""
        ).strip()

        if len(scanned_url) > 2048:

            flash(
                "URL must be 2048 characters or fewer.",
                "error"
            )

        elif not scanned_url:

            flash(
                "Please enter a URL.",
                "error"
            )

        else:

            try:

                parsed = urlsplit(scanned_url)

                if (
                    parsed.scheme not in ("http", "https")
                    or not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                ):

                    flash(
                        "Enter a valid HTTP or HTTPS URL.",
                        "error"
                    )

                else:

                    result = analyze_url(scanned_url)

                    with get_db() as conn:

                        conn.execute("""
                            INSERT INTO url_scans (
                                user_id,
                                url,
                                prediction,
                                risk_score,
                                reasons
                            )
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            session["user_id"],
                            scanned_url,
                            result["prediction"],
                            result["risk_score"],
                            "; ".join(result["reasons"])
                        ))

            except (sqlite3.Error, ValueError):

                app.logger.exception(
                    "URL scan failed."
                )

                result = None

                flash(
                    "Unable to analyze or save the URL.",
                    "error"
                )

    return render_template(
        "url_scanner.html",
        result=result,
        scanned_url=scanned_url,
        username=session.get("username", "User")
    )


# ==================================================
# EMAIL SCANNER
# ==================================================

@app.route(
    "/email-scanner",
    methods=["GET", "POST"]
)
@login_required
def email_scanner():

    result = None
    email_text = ""
    subject = ""

    if request.method == "POST":

        subject = request.form.get(
            "subject", ""
        ).strip()

        email_text = request.form.get(
            "email_text", ""
        ).strip()

        if not email_text:

            flash(
                "Please enter the email message.",
                "error"
            )

        elif len(email_text) > 10000:

            flash(
                "Email text must be 10000 characters or fewer.",
                "error"
            )

        else:

            result = analyze_email(
                subject + "\n" + email_text
            )

            try:

                with get_db() as conn:

                    conn.execute("""
                        INSERT INTO email_scans (
                            user_id,
                            subject,
                            email_text,
                            prediction,
                            risk_score,
                            reasons
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        session["user_id"],
                        subject,
                        email_text,
                        result["prediction"],
                        result["risk_score"],
                        "; ".join(result["reasons"])
                    ))

            except sqlite3.Error:

                app.logger.exception(
                    "Email scan save failed."
                )

                flash(
                    "Analysis completed, but saving failed.",
                    "error"
                )

    return render_template(
        "email_scanner.html",
        result=result,
        subject=subject,
        email_text=email_text,
        username=session.get("username", "User")
    )


# ==================================================
# DETECTION HISTORY
# ==================================================

@app.route("/history")
@login_required
def history():

    user_id = session["user_id"]

    try:

        with get_db() as conn:

            url_history = conn.execute("""
                SELECT
                    'URL' AS scan_type,
                    url AS item,
                    prediction,
                    risk_score,
                    created_at
                FROM url_scans
                WHERE user_id = ?
            """, (
                user_id,
            )).fetchall()

            email_history = conn.execute("""
                SELECT
                    'EMAIL' AS scan_type,
                    COALESCE(
                        NULLIF(subject, ''),
                        'Email scan'
                    ) AS item,
                    prediction,
                    risk_score,
                    created_at
                FROM email_scans
                WHERE user_id = ?
            """, (
                user_id,
            )).fetchall()

        all_history = sorted(
            list(url_history) + list(email_history),
            key=lambda row: row["created_at"] or "",
            reverse=True
        )

        records = [
            {
                "type": row["scan_type"],
                "target": row["item"],
                "prediction": row["prediction"],
                "risk_score": row["risk_score"],
                "created_at": row["created_at"]
            }
            for row in all_history
        ]

        return render_template(
            "history.html",
            history=all_history,
            records=records
        )

    except sqlite3.Error:

        app.logger.exception(
            "History database error."
        )

        flash(
            "Unable to load detection history.",
            "error"
        )

        return render_template(
            "history.html",
            history=[],
            records=[]
        )


# ==================================================
# STATISTICS
# ==================================================

@app.route("/statistics")
@login_required
def statistics():

    user_id = session["user_id"]

    try:

        with get_db() as conn:

            url_total = conn.execute("""
                SELECT COUNT(*) AS total
                FROM url_scans
                WHERE user_id = ?
            """, (
                user_id,
            )).fetchone()["total"]

            email_total = conn.execute("""
                SELECT COUNT(*) AS total
                FROM email_scans
                WHERE user_id = ?
            """, (
                user_id,
            )).fetchone()["total"]

            url_threats = conn.execute("""
                SELECT COUNT(*) AS total
                FROM url_scans
                WHERE user_id = ?
                AND prediction IN (
                    'HIGH RISK',
                    'SUSPICIOUS'
                )
            """, (
                user_id,
            )).fetchone()["total"]

            email_threats = conn.execute("""
                SELECT COUNT(*) AS total
                FROM email_scans
                WHERE user_id = ?
                AND prediction IN (
                    'HIGH RISK',
                    'SUSPICIOUS'
                )
            """, (
                user_id,
            )).fetchone()["total"]

        total_scans = url_total + email_total
        total_threats = url_threats + email_threats

        if total_scans == 0:
            security_score = 100

        else:
            security_score = round(
                100 * (total_scans - total_threats)
                / total_scans
            )

        return render_template(
            "statistics.html",
            url_total=url_total,
            email_total=email_total,
            total_scans=total_scans,
            total_threats=total_threats,
            threats_total=total_threats,
            url_threats=url_threats,
            email_threats=email_threats,
            security_score=security_score
        )

    except sqlite3.Error:

        app.logger.exception(
            "Statistics database error."
        )

        flash(
            "Unable to load statistics.",
            "error"
        )

        return render_template(
            "statistics.html",
            url_total=0,
            email_total=0,
            total_scans=0,
            total_threats=0,
            threats_total=0,
            url_threats=0,
            email_threats=0,
            security_score=0
        )


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("home"))


# ==================================================
# START APPLICATION
# ==================================================

init_db()

if __name__ == "__main__":
    app.run(debug=True)