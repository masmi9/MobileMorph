import os
from flask import Flask
from flask_wtf import CSRFProtect
from dashboard.extensions import db
from dashboard.routes import main

csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    # Secret key for session and flash messages
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback_dev_key")
    csrf.init_app(app)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///morph.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    app.register_blueprint(main)

    with app.app_context():
        db.create_all()

    return app
