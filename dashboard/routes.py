import os
import json
import uuid
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from dashboard.extensions import db
from dashboard.models import ScanResult, IOCEntry
from dashboard.progress_tracker import get_progress, update_progress
from static import apk_static_analysis as apk
from static import ipa_static_analysis as ipa
from static import secrets_scanner as secrets
from utils.paths import get_output_folder
from report.report_generator import ReportGenerator

main = Blueprint("main", __name__)

@main.route('/')
def index():
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    return render_template('index.html', scans=scans)

@main.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if not file:
            flash("No file uploaded.", "danger")
            return redirect(url_for("main.upload_file"))

        filename = secure_filename(file.filename)
        filepath = os.path.join("uploads", filename)
        os.makedirs("uploads", exist_ok=True)
        file.save(filepath)

        file_id = str(uuid.uuid4())
        update_progress(file_id, 5)  # Start at 5%

        downloads_folder = get_output_folder()
        findings = {}

        if filename.endswith('.apk'):
            base_name, results = apk.run_static_analysis(filepath, file_id)
        elif filename.endswith('.ipa'):
            base_name, results = ipa.run_static_analysis(filepath)
        else:
            flash("Unsupported file type. Please upload an APK or IPA.", "danger")
            return redirect(url_for("main.upload_file"))

        update_progress(file_id, 95)  # Near completion

        # Generate report
        report = ReportGenerator(base_name, downloads_folder, mode="static")
        report.generate_static_report(findings=results)

        # Save to DB
        result = ScanResult(
            filename=filename,
            platform='apk' if filename.endswith('.apk') else 'ipa',
            scan_type='static',
            findings=json.dumps(results)
        )
        db.session.add(result)
        db.session.commit()

        update_progress(file_id, 100)  # Done
        flash('File uploaded and analyzed successfully.', 'success')
        return redirect(url_for("main.index"))

    return render_template('upload.html')

@main.route('/results/<int:scan_id>')
def show_results(scan_id):
    result = ScanResult.query.get_or_404(scan_id)
    try:
        parsed = json.loads(result.findings)
    except Exception:
        parsed = result.findings
    return render_template('results.html', result=result, parsed=parsed)

@main.route('/iocs')
def show_iocs():
    iocs = IOCEntry.query.order_by(IOCEntry.created_at.desc()).all()
    return render_template('iocs.html', iocs=iocs)

@main.route('/progress/<file_id>')
def progress_status(file_id):
    return jsonify({"progress": get_progress(file_id)})

@main.route('/delete/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    result = ScanResult.query.get_or_404(scan_id)
    try:
        # Optionally delete report file from disk
        report_file = os.path.join('static', 'reports', f"{result.filename.replace('.apk','').replace('.ipa','')}_findings.json")
        if os.path.exists(report_file):
            os.remove(report_file)

        db.session.delete(result)
        db.session.commit()
        flash("Scan deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting scan: {e}", "danger")

    return redirect(url_for('main.index'))
