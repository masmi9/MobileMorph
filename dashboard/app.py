from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dashboard.routes import main

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'morphsecretkey'  # Change in production
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///morph.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    app.register_blueprint(main)

    return app
