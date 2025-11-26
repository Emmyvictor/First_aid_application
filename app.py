from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import secrets
import json
import os
from sqlalchemy import TypeDecorator, Text
from dotenv import load_dotenv
import resend  # ADDED: Resend replaces SMTP

load_dotenv()


app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///firstaid.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Overwrite with .env values
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

# ---------------------------
# REMOVE SMTP (Flask-Mail)
# ---------------------------
# No SMTP configuration needed
# mail = Mail(app)

# ---------------------------
# RESEND SETUP
# ---------------------------
resend.api_key = os.getenv("RESEND_API_KEY")


db = SQLAlchemy(app)


# ---------------------------
# Custom JSON column type
# ---------------------------
class JSONEncodedList(TypeDecorator):
    impl = Text

    def process_bind_param(self, value, dialect):
        if value is None:
            return "[]"
        if isinstance(value, list):
            try:
                return json.dumps(value, ensure_ascii=False)
            except Exception:
                return json.dumps([str(x) for x in value], ensure_ascii=False)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return value
            except Exception:
                return json.dumps([value], ensure_ascii=False)
        return json.dumps(value, ensure_ascii=False)

    def process_result_value(self, value, dialect):
        if not value:
            return []
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except Exception:
            return [value]


# ---------------------------
# MODELS
# ---------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    activities = db.relationship("Activity", backref="user", lazy=True)


class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)


class EmergencyGuide(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    steps = db.Column(JSONEncodedList, nullable=False)
    symptoms = db.Column(JSONEncodedList)
    warnings = db.Column(JSONEncodedList)
    tips = db.Column(JSONEncodedList)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)


# ---------------------------
# HELPERS
# ---------------------------
def safe_load_list(json_text):
    if not json_text:
        return []
    if isinstance(json_text, list):
        return json_text
    if isinstance(json_text, str):
        try:
            parsed = json.loads(json_text)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except Exception:
            if "\n" in json_text:
                return [s.strip() for s in json_text.splitlines() if s.strip()]
            if "," in json_text:
                return [s.strip() for s in json_text.split(",") if s.strip()]
            return [json_text.strip()] if json_text.strip() else []
    try:
        return list(json_text)
    except Exception:
        return [str(json_text)]


# ---------------------------
# EMAIL (RESEND VERSION)
# ---------------------------
def send_verification_email(user):
    try:
        token = secrets.token_urlsafe(32)
        user.verification_token = token
        db.session.commit()

        verification_url = url_for("verify_email", token=token, _external=True)

        resend.Emails.send(
            {
                "from": "First Aid App <onboarding@resend.dev>",
                "to": user.email,
                "subject": "Verify Your Email",
                "html": f"""
                <p>Hello {user.username},</p>
                <p>Please verify your email by clicking below:</p>
                <a href="{verification_url}"
                   style="padding:10px 20px; background:#d32f2f; color:white; border-radius:6px; text-decoration:none;">
                   Verify Email
                </a>
                <p>If the button doesn’t work, copy this link:</p>
                <p>{verification_url}</p>
            """,
            }
        )
        return True
    except Exception as e:
        print("✗ Resend Email error:", e)
        return False


def log_activity(user_id, action, details=None):
    try:
        activity = Activity(user_id=user_id, action=action, details=details)
        db.session.add(activity)
        db.session.commit()
    except Exception:
        db.session.rollback()


# ---------------------------
# DECORATORS
# ---------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or not user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return decorated


# ---------------------------
# ROUTES
# ---------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(username=username).first():
            flash("Username taken.", "danger")
            return redirect(url_for("signup"))

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
        )
        db.session.add(user)
        db.session.commit()

        send_verification_email(user)

        flash("Account created! Verification email sent.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash("Please verify your email first.", "warning")
                return redirect(url_for("login"))

            session["user_id"] = user.id
            session["username"] = user.username
            session["is_admin"] = user.is_admin

            user.last_login = datetime.utcnow()
            db.session.commit()

            log_activity(user.id, "login")
            return redirect(url_for("dashboard"))

        flash("Invalid credentials.", "danger")

    return render_template("login.html")


@app.route("/verify/<token>")
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash("Email verified!", "success")
    else:
        flash("Invalid or expired link.", "danger")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    guides = EmergencyGuide.query.all()
    categories = [
        c[0] for c in db.session.query(EmergencyGuide.category).distinct().all()
    ]

    guides_data = []
    for g in guides:
        guides_data.append(
            {
                "id": g.id,
                "title": g.title,
                "category": g.category,
                "description": g.description,
                "views": g.views,
                "steps": safe_load_list(g.steps),
                "symptoms": safe_load_list(g.symptoms),
                "warnings": safe_load_list(g.warnings),
                "tips": safe_load_list(g.tips),
            }
        )

    recent_activities = (
        Activity.query.filter_by(user_id=session["user_id"])
        .order_by(Activity.timestamp.desc())
        .limit(5)
        .all()
    )

    return render_template(
        "dashboard.html",
        guides=guides_data,
        categories=categories,
        recent_activities=recent_activities,
    )


@app.route("/guide/<int:guide_id>")
@login_required
def view_guide(guide_id):
    guide = EmergencyGuide.query.get_or_404(guide_id)
    guide.views = (guide.views or 0) + 1
    db.session.commit()

    steps = safe_load_list(guide.steps)
    symptoms = safe_load_list(guide.symptoms)
    warnings = safe_load_list(guide.warnings)
    tips = safe_load_list(guide.tips)

    log_activity(session["user_id"], "view_guide", f"Viewed: {guide.title}")

    return render_template(
        "guide.html",
        guide=guide,
        steps=steps,
        symptoms=symptoms,
        warnings=warnings,
        tips=tips,
    )


@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    category = request.args.get("category", "")

    guides_q = EmergencyGuide.query
    if query:
        guides_q = guides_q.filter(
            (EmergencyGuide.title.contains(query))
            | (EmergencyGuide.description.contains(query))
        )
    if category:
        guides_q = guides_q.filter_by(category=category)

    results = guides_q.all()
    return jsonify(
        [
            {
                "id": g.id,
                "title": g.title,
                "category": g.category,
                "description": g.description[:200] + "...",
            }
            for g in results
        ]
    )


@app.route("/admin")
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    verified_users = User.query.filter_by(is_verified=True).count()
    total_guides = EmergencyGuide.query.count()
    total_activities = Activity.query.count()
    total_views = db.session.query(db.func.sum(EmergencyGuide.views)).scalar() or 0

    recent_activities = (
        Activity.query.order_by(Activity.timestamp.desc()).limit(20).all()
    )

    for a in recent_activities:
        user = User.query.get(a.user_id)
        a.username = user.username if user else "Unknown"

    users = User.query.order_by(User.created_at.desc()).all()

    stats = {
        "total_users": total_users,
        "verified_users": verified_users,
        "total_guides": total_guides,
        "total_activities": total_activities,
        "total_views": total_views,
    }

    return render_template(
        "admin.html", stats=stats, activities=recent_activities, users=users
    )


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_activity(session["user_id"], "logout")
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------
# DB init & normalization
# ---------------------------
def init_db():
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(email="admin@firstaid.com").first():
            admin = User(
                username="admin",
                email="admin@firstaid.com",
                password=generate_password_hash("admin123"),
                is_verified=True,
                is_admin=True,
            )
            db.session.add(admin)

        if EmergencyGuide.query.count() == 0:
            guides = [
                {
                    "title": "Epileptic Seizure",
                    "category": "Neurological",
                    "description": "A seizure is a sudden, uncontrolled electrical disturbance in the brain.",
                    "steps": [
                        "Stay calm and time the seizure",
                        "Protect the person from injury",
                        "Turn them on their side",
                        "Do NOT restrain them",
                        "Call emergency services if lasts more than 5 minutes",
                    ],
                    "symptoms": [
                        "Uncontrolled jerking",
                        "Loss of consciousness",
                        "Confusion afterward",
                    ],
                    "warnings": [
                        "Never put anything in their mouth",
                        "Do not hold them down",
                    ],
                    "tips": [
                        "Time the seizure",
                        "Stay calm",
                    ],
                },
                {
                    "title": "Choking",
                    "category": "Respiratory",
                    "description": "Choking occurs when an object blocks the airway.",
                    "steps": [
                        "Ask if they are choking",
                        "Perform Heimlich maneuver",
                        "Call emergency services if unconscious",
                    ],
                    "symptoms": [
                        "Inability to speak",
                        "Turning blue",
                        "Clutching throat",
                    ],
                    "warnings": ["Do not perform Heimlich on infants"],
                    "tips": ["Act quickly", "Encourage coughing"],
                },
            ]

            for g in guides:
                guide = EmergencyGuide(
                    title=g["title"],
                    category=g["category"],
                    description=g["description"],
                    steps=g["steps"],
                    symptoms=g["symptoms"],
                    warnings=g["warnings"],
                    tips=g["tips"],
                )
                db.session.add(guide)

        db.session.commit()
        print("Database initialized successfully!")


def normalize_db():
    with app.app_context():
        guides = EmergencyGuide.query.all()
        changed = 0
        for g in guides:
            s = safe_load_list(g.steps)
            sy = safe_load_list(g.symptoms)
            w = safe_load_list(g.warnings)
            t = safe_load_list(g.tips)

            if g.steps != s:
                g.steps = s
                changed += 1
            if g.symptoms != sy:
                g.symptoms = sy
                changed += 1
            if g.warnings != w:
                g.warnings = w
                changed += 1
            if g.tips != t:
                g.tips = t
                changed += 1

            if changed:
                db.session.add(g)
        if changed:
            db.session.commit()
        print(f"Normalization complete. Modified {changed} fields across guides.")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
