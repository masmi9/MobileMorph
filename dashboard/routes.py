import os
import json
import uuid
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from dashboard.extensions import db
from dashboard.models import ScanResult, IOCEntry
from dashboard.progress_tracker import get_progress, update_progress
from static import apk_static_analysis as apk
from dyna import OWASPTestSuiteDrozer, ensure_drozer_agent_ready
from static import ipa_static_analysis as ipa
from static import secrets_scanner as secrets
from utils.paths import get_output_folder
from report.report_generator import ReportGenerator
from utils import logger
import markdown
from datetime import datetime
from main import get_package_name_from_apk

main = Blueprint("main", __name__)

@main.route('/')
def index():
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    return render_template('index.html', scans=scans)

@main.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file_id = request.args.get("file_id", str(uuid.uuid4()))  # capture incoming ID
        file = request.files['file']
        if not file:
            flash("No file uploaded.", "danger")
            return redirect(url_for("main.upload_file"))

        filename = secure_filename(file.filename)
        filepath = os.path.join("uploads", filename)
        os.makedirs("uploads", exist_ok=True)
        file.save(filepath)

        update_progress(file_id, 5)  # Start at 5%

        downloads_folder = get_output_folder()
        findings = {}

        if filename.endswith('.apk'):
            base_name, results = apk.run_static_analysis(filepath, file_id)
        elif filename.endswith('.ipa'):
            base_name, results = ipa.run_static_analysis(filepath, file_id)
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
    # Extracted base_name by stripping file extension
    base_name = result.filename.replace('.apk', '').replace('.ipa', '')
    # Optionally include the rendered Markdown
    dynamic_html = None
    report_path = "report.md"
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            md_content = f.read()
            dynamic_html = markdown.markdown(md_content, extensions=["fenced_code", "tables"])

    return render_template('results.html', result=result, parsed=parsed, base_name=base_name, dynamic_html=dynamic_html)

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

@main.route('/dynamic/latest')
def run_dynamic_on_latest():
    latest_scan = ScanResult.query.order_by(ScanResult.created_at.desc()).first()
    if not latest_scan:
        flash("No uploaded file found for dynamic analysis.", "warning")
        return redirect(url_for("main.index"))

    file_path = os.path.join("uploads", latest_scan.filename)
    if not os.path.exists(file_path):
        flash(f"Uploaded file {latest_scan.filename} not found.", "danger")
        return redirect(url_for("main.index"))

    try:
        if latest_scan.filename.endswith(".apk"):
            logger.info(f"Running dynamic analysis for APK: {latest_scan.filename}")
            ensure_drozer_agent_ready()
            # Pull package name from static scan JSON (if exists)
            try:
                findings_dict = json.loads(latest_scan.findings)
                pkg_name = get_package_name_from_apk(file_path)
                if not pkg_name:
                    flash("Could not extract package name from APK. Aborting.", "danger")
                    return redirect(url_for("main.index"))
            except Exception:
                findings_dict = {}
                pkg_name = ""
            # Run Dynamic Analysis
            suite = OWASPTestSuiteDrozer(file_path, pkg_name)
            suite.full_test_suite()
            # Read the raw markdown report
            with open("report.md", "r", encoding="utf-8") as f:
                md_content = f.read()
            # Convert Markdown -> HTML
            dynamic_results = markdown.markdown(md_content, extensions=["fenced_code", "tables"])
            # Save as dynamic scan in DB
            dynamic_scan = ScanResult(
                filename = latest_scan.filename,
                platform = latest_scan.platform,
                scan_type = "dynamic",
                findings = json.dumps({"report_markdown": md_content}),
                created_at = datetime.utcnow()
            )
            db.session.add(dynamic_scan)
            db.session.commit()

            flash(f"Dynamic analysis completed for {latest_scan.filename}.", "success")
            return render_template("dynamic_results.html", results=dynamic_results, filename=latest_scan.filename)
        else:
            flash("Unsupported file type for dynamic analysis.", "danger")
            return redirect(url_for("main.index"))
    except Exception as e:
        logger.warning(f"Dynamic analysis failed: {e}")
        flash(f"Error during dynamic analysis: {e}", "danger")
        return redirect(url_for("main.index"))

@main.route('/view-source/')
def view_source_missing():
    flash("APK name missing in URL.", "warning")
    return redirect(url_for("main.index"))

@main.route('/view-source/<apk_name>')
def view_source_page(apk_name):
    return render_template('source_viewer.html', apk_name=apk_name)

@main.route('/api/source/list')
def list_source_files():
    apk = request.args.get("apk")
    source_path = os.path.join("extracted", apk, "source")
    file_list = []
    for root, _, files in os.walk(source_path):
        for f in files:
            if f.endswith(".java") or f.endswith(".smali"):
                rel = os.path.relpath(os.path.join(root, f), source_path)
                file_list.append(rel)
    return jsonify(file_list)

@main.route('/api/source/view')
def view_source_content():
    apk = request.args.get("apk")
    file_path = request.args.get("path")
    full_path = os.path.join("extracted", apk, "source", file_path)
    if not os.path.isfile(full_path):
        return jsonify({"error": "File not found"}), 404
    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    return jsonify({"content": content})