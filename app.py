import os
import secrets
import resend
import threading
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret")

# -------------------------
# DATABASE CONFIG (Render)
# -------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------
# RESEND CONFIG
# -------------------------
resend.api_key = os.getenv("RESEND_API_KEY")


# -------------------------
# DATABASE MODELS
# -------------------------


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Guide(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# -------------------------
# EMAIL SENDER
# -------------------------


def send_email(to, subject, html):
    """Send email asynchronously using Resend."""

    def task():
        try:
            resend.Emails.send(
                {
                    "from": "FirstAid App <onboarding@resend.dev>",
                    "to": to,
                    "subject": subject,
                    "html": html,
                }
            )
            print("Email sent successfully to", to)
        except Exception as e:
            print("Email send failed:", e)

    threading.Thread(target=task).start()


def send_verification_email(user):
    """Send verification email and generate token."""
    try:
        token = secrets.token_urlsafe(32)
        user.verification_token = token
        db.session.commit()

        verification_url = url_for("verify_email", token=token, _external=True)

        html = f"""
        <h2>Welcome, {user.username}!</h2>
        <p>Please verify your account by clicking below:</p>
        <a href="{verification_url}"
           style="padding: 10px 20px; background: #007BFF; color: white; border-radius: 5px; text-decoration: none;">
           Verify Email
        </a>
        """

        send_email(user.email, "Verify your First Aid Account", html)
        return True

    except Exception as e:
        print("Verification email failed:", e)
        return False


# -------------------------
# ROUTES
# -------------------------


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("Email already registered.", "danger")
            return redirect("/signup")

        hashed_pw = generate_password_hash(password)

        user = User(username=username, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()

        send_verification_email(user)

        flash("Account created! Check your email for verification.", "success")
        return redirect("/login")

    return render_template("signup.html")


@app.route("/verify/<token>")
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()

    if not user:
        return "Invalid or expired verification link."

    user.is_verified = True
    user.verification_token = None
    db.session.commit()

    return render_template("verified.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash("Invalid login details", "danger")
            return redirect("/login")

        if not user.is_verified:
            flash("Please verify your email first.", "warning")
            return redirect("/login")

        session["user_id"] = user.id
        return redirect("/dashboard")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    guides = Guide.query.order_by(Guide.created_at.desc()).all()
    return render_template("dashboard.html", guides=guides)


@app.route("/guide/<int:id>")
def guide(id):
    g = Guide.query.get(id)
    return render_template("guide.html", guide=g)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]

        g = Guide(title=title, content=content)
        db.session.add(g)
        db.session.commit()

        flash("Guide added!", "success")
        return redirect("/admin")

    return render_template("admin.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# -------------------------
# RUN LOCAL
# -------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
