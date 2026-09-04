"""
Application factory — Windows Recycle Bin Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Wires together every module: database, auth, dashboard, logs, alerts,
incident management, analytics, reports, settings.
"""
import os
from flask import Flask
from flask_login import LoginManager

from app.database import db, User
from app.auth import auth_bp
from app.dashboard import dashboard_bp
from app.logs.routes import logs_bp
from app.alerts.routes import alerts_bp
from app.incident_management.routes import incidents_bp
from app.analytics.routes import analytics_bp
from app.reports.routes import reports_bp
from app.settings.routes import settings_bp

login_manager = LoginManager()
login_manager.login_view = "auth.login"


def create_app(db_path=None, secret_key=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = secret_key or os.environ.get("WRBA_SECRET_KEY", "dev-secret-change-me")

    default_db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance", "wrba.db")
    os.makedirs(os.path.dirname(default_db), exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = db_path or f"sqlite:///{default_db}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)

    with app.app_context():
        db.create_all()

    @app.context_processor
    def inject_branding():
        return {
            "app_name": "Windows Recycle Bin Analyzer",
            "author_name": "Karanam Shrivasta",
            "github_url": "https://github.com/mrshrivasta",
            "linkedin_url": "https://www.linkedin.com/in/karanam-shrivasta",
        }

    @app.errorhandler(404)
    def not_found(e):
        return "404 — Page not found. Windows Recycle Bin Analyzer. Developed by Karanam Shrivasta.", 404

    return app
