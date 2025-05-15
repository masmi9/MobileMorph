import os
from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from dashboard.models import db, ScanResult, IOCEntry
from static import apk_static_analysis as apk
from static import ipa_static_analysis as ipa
from static import secrets_scanner as secrets
from utils.paths import get_output_folder
from report.report_generator import ReportGenerator
import json

main = Blueprint("main", __name__)
# Run static analysis after upload
downloads_folder = get_output_folder()
findings = {}

@main.route('/')
def index():
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    return render_template('index.html', scans=scans)

@main.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join("uploads", filename)
            os.makedirs("uploads", exist_ok=True)
            file.save(filepath)

            downloads_folder = get_output_folder()
            findings = {}

            # Run static analysis
            if filename.endswith('.apk'):
                base_name, results = apk.run_static_analysis(filepath)
                strings_file = os.path.join(downloads_folder, f"{base_name}_strings.txt")
                secrets_result = secrets.scan_for_secrets(strings_file)
                findings = {
                    "Secrets Scan Results": secrets_result,
                    "Static Analysis Logs": f"Decompiled APK and strings dumped at {strings_file}"
                }

            elif filename.endswith('.ipa'):
                base_name = ipa.run_static_analysis(filepath)
                strings_file = os.path.join(downloads_folder, f"{base_name}_strings.txt")
                secrets_result = secrets.scan_for_secrets(strings_file)
                findings = {
                    "Secrets Scan Results": secrets_result,
                    "Static Analysis Logs": f"Decompiled IPA and strings dumped at {strings_file}"
                }

            else:
                flash("Unsupported file type. Please upload an APK or IPA.", "danger")
                return redirect(url_for("main.upload_file"))

            # Generate report (optional)
            report = ReportGenerator(base_name, downloads_folder, mode="static")
            report.generate_static_report(findings=findings)

            # Save to database
            result = ScanResult(
                filename=filename,
                platform='apk' if filename.endswith('.apk') else 'ipa',
                scan_type='static',
                findings=json.dumps(findings)
            )
            db.session.add(result)
            db.session.commit()

            flash('File uploaded and analysis placeholder saved.', 'success')
            return redirect(url_for('main.index'))
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
