from dashboard.extensions import db
from datetime import datetime

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120))
    platform = db.Column(db.String(10))  # 'apk' or 'ipa'
    scan_type = db.Column(db.String(20))  # static, dynamic, exploit, etc.
    findings = db.Column(db.Text)  # Serialized JSON or log
    created_at = db.Column(db.DateTime, default=datetime.utcnow, server_default=db.func.now())

class IOCEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255))
    source_file = db.Column(db.String(120))
    threat_score = db.Column(db.Integer)
    vt_data = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
