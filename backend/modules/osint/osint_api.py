from flask import Blueprint, request, jsonify
from threading import Lock, Thread
import uuid
import json
import os
from datetime import datetime

osint_blueprint = Blueprint('osint', __name__)

OSINT_JOB_MAX_LOGS = 5000
_osint_jobs = {}
_osint_jobs_lock = Lock()

def _utc_now():
    return datetime.utcnow().isoformat() + "Z"

def _create_osint_job(target, recursive=False, max_depth=2, job_type="legacy_search", payload=None):
    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "job_type": job_type,
        "target": target,
        "recursive": recursive,
        "max_depth": max_depth,
        "payload": payload or {},
        "status": "queued",
        "phase": "queued",
        "created_at": _utc_now(),
        "started_at": None,
        "completed_at": None,
        "error": None,
        "cancel_requested": False,
        "pause_requested": False,
        "logs": [],
        "result": None,
        "progress": {
            "phase": "queued",
            "total_sites": 0,
            "sites_enabled": 0,
            "sites_suppressed": 0,
            "completed": 0,
            "total": 0,
            "current_site": "",
            "latest_found_site": "",
            "latest_confidence_level": "",
            "latest_confidence_score": 0,
            "found_count": 0,
            "actionable_findings": 0,
            "manual_review_count": 0,
            "error_count": 0,
        },
    }
    with _osint_jobs_lock:
        _osint_jobs[job_id] = job
    return job

def _append_osint_log(job_id, payload):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job:
            return
        entry = {
            "seq": len(job["logs"]) + 1,
            "timestamp": _utc_now(),
            "level": payload.get("level", "info"),
            "message": payload.get("message", ""),
        }
        for key, value in payload.items():
            if key not in entry:
                entry[key] = value
        job["logs"].append(entry)
        if len(job["logs"]) > OSINT_JOB_MAX_LOGS:
            job["logs"] = job["logs"][-OSINT_JOB_MAX_LOGS:]
        if payload.get("phase"):
            job["phase"] = payload["phase"]

def _update_osint_progress(job_id, fields):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job:
            return
        job["progress"].update(fields)
        if fields.get("phase"):
            job["phase"] = fields["phase"]

def _finish_osint_job(job_id, status, result=None, error=None):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job:
            return
        job["status"] = status
        job["completed_at"] = _utc_now()
        job["result"] = result
        job["error"] = error

def _get_osint_job(job_id):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job:
            return None
        return json.loads(json.dumps(job))


def _job_response(job_id):
    job = _get_osint_job(job_id)
    if not job:
        return jsonify({"success": False, "error": "Not found"}), 404
    return jsonify({"success": True, "data": job})


def _investigation_results(investigation):
    results = investigation.get("results")
    if isinstance(results, list):
        return results

    flattened = []
    for tier_data in (investigation.get("results_by_tier") or {}).values():
        if isinstance(tier_data, list):
            flattened.extend(tier_data)
    return flattened


def _actionable_findings(investigation):
    findings = investigation.get("actionable_findings")
    if isinstance(findings, list):
        return findings

    normalized = []
    for result in _investigation_results(investigation):
        if result.get("confidence_level") not in ("Confirmed", "High Confidence"):
            continue

        item = dict(result)
        if not item.get("site") and item.get("site_name"):
            item["site"] = item["site_name"]

        metadata = dict(item.get("metadata") or {})
        if item.get("display_name") and not metadata.get("display_name"):
            metadata["display_name"] = item["display_name"]
        if item.get("bio") and not metadata.get("bio"):
            metadata["bio"] = item["bio"]
        if metadata:
            item["metadata"] = metadata

        normalized.append(item)

    return normalized


def _investigation_profile(investigation):
    return investigation.get("subject_profile") or investigation.get("profile") or {}


def _investigation_summary(investigation):
    summary = investigation.get("summary")
    if isinstance(summary, dict):
        return summary

    return {
        "confirmed": investigation.get("confirmed_count", 0),
        "high_confidence": investigation.get("high_confidence_count", 0),
        "medium_confidence": investigation.get("medium_confidence_count", 0),
        "manual_review_count": investigation.get("manual_review_count", 0),
        "total_checked": investigation.get("total_sites_checked", 0),
    }

def _should_stop_osint_job(job_id):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job:
            return True
        return bool(job.get("cancel_requested"))

def _should_pause_osint_job(job_id):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job:
            return False
        return bool(job.get("pause_requested"))

def _run_osint_job(job_id):
    try:
        from modules.osint.osint_checker import full_osint_search, recursive_osint_search

        job_snapshot = _get_osint_job(job_id)
        if not job_snapshot: return

        with _osint_jobs_lock:
            job = _osint_jobs.get(job_id)
            job["status"] = "running"
            job["started_at"] = _utc_now()

        def logger(payload): _append_osint_log(job_id, payload)
        def progress(fields): _update_osint_progress(job_id, fields)

        if job_snapshot["recursive"]:
            result = recursive_osint_search(job_snapshot["target"], max_depth=job_snapshot["max_depth"], logger=logger, progress_cb=progress)
        else:
            result = full_osint_search(job_snapshot["target"], logger=logger, progress_cb=progress)

        _finish_osint_job(job_id, "completed", result=result)
    except Exception as e:
        _finish_osint_job(job_id, "failed", error=str(e))

@osint_blueprint.route('/search', methods=['POST'])
def osint_search():
    from modules.osint.osint_checker import full_osint_search
    target = request.json.get('target', '').strip()
    if not target: return jsonify({"success": False, "error": "No target"}), 400
    try:
        results = full_osint_search(target)
        return jsonify({"success": True, "data": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@osint_blueprint.route('/search/start', methods=['POST'])
def osint_search_start():
    payload = request.get_json(silent=True) or {}
    target = str(payload.get('target', '')).strip()
    if not target: return jsonify({"success": False, "error": "No target"}), 400

    job = _create_osint_job(target, recursive=bool(payload.get('recursive')), max_depth=int(payload.get('max_depth', 2)))
    Thread(target=_run_osint_job, args=(job["job_id"],), daemon=True).start()
    return jsonify({"success": True, "data": {"job_id": job["job_id"]}})

@osint_blueprint.route('/search/status/<job_id>', methods=['GET'])
def osint_search_status(job_id):
    return _job_response(job_id)

@osint_blueprint.route('/search/result/<job_id>', methods=['GET'])
def osint_search_result(job_id):
    return _job_response(job_id)

@osint_blueprint.route('/search/cancel/<job_id>', methods=['POST'])
def osint_search_cancel(job_id):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job: return jsonify({"success": False, "error": "Not found"}), 404
        job["cancel_requested"] = True
    return jsonify({"success": True})

@osint_blueprint.route('/search/recursive', methods=['POST'])
def osint_search_recursive():
    from modules.osint.osint_checker import recursive_osint_search
    payload = request.get_json(silent=True) or {}
    target = str(payload.get('target', '')).strip()
    if not target: return jsonify({"success": False, "error": "No target"}), 400
    max_depth = int(payload.get('max_depth', 2))
    try:
        results = recursive_osint_search(target, max_depth=max_depth)
        return jsonify({"success": True, "data": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@osint_blueprint.route('/csv-only', methods=['POST'])
def osint_csv_search():
    from modules.osint.osint_checker import search_csv_sources, detect_input_type
    target = request.json.get('target', '').strip()
    if not target: return jsonify({"success": False, "error": "No target"}), 400
    try:
        input_type = detect_input_type(target)
        csv_results = search_csv_sources(target, input_type)
        return jsonify({"success": True, "data": {"csv_matches": csv_results, "input_type": input_type}})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── v2 Enterprise Investigation Platform ───────────────────────────────────

@osint_blueprint.route('/v2/investigate', methods=['POST'])
def osint_v2_investigate():
    """Run a full enterprise investigation against a rich subject profile."""
    try:
        from modules.osint.osint_engine import InvestigationEngine, SubjectProfile
    except ImportError as e:
        return jsonify({"success": False, "error": f"OSINT engine not available: {e}"}), 503

    payload = request.get_json(silent=True) or {}
    profile_data = payload.get('profile')
    if not profile_data:
        return jsonify({"success": False, "error": "No profile provided"}), 400

    modes = payload.get('modes') or None
    tiers = payload.get('tiers') or None
    if tiers:
        tiers = [int(t) for t in tiers]
    enable_serp = bool(payload.get('enable_serp_discovery', True))

    try:
        profile = SubjectProfile.from_dict(profile_data)
        if not profile.has_searchable_fields():
            return jsonify({"success": False, "error": "No searchable fields provided"}), 400

        engine = InvestigationEngine()
        result = engine.run_investigation(
            profile, modes=modes, tiers=tiers,
            enable_serp_discovery=enable_serp,
        )
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@osint_blueprint.route('/v2/investigate/start', methods=['POST'])
def osint_v2_investigate_start():
    """Start an async investigation job and return a job_id for polling."""
    try:
        from modules.osint.osint_engine import InvestigationEngine, SubjectProfile
    except ImportError as e:
        return jsonify({"success": False, "error": f"OSINT engine not available: {e}"}), 503

    payload = request.get_json(silent=True) or {}
    profile_data = payload.get('profile')
    if not profile_data:
        return jsonify({"success": False, "error": "No profile provided"}), 400

    modes = payload.get('modes') or None
    tiers = payload.get('tiers') or None
    if tiers:
        tiers = [int(t) for t in tiers]
    force_refresh = bool(payload.get('force_manifest_refresh', False))
    enable_serp = bool(payload.get('enable_serp_discovery', True))

    try:
        profile = SubjectProfile.from_dict(profile_data)
        if not profile.has_searchable_fields():
            return jsonify({"success": False, "error": "No searchable fields provided"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Invalid profile: {e}"}), 400

    job = _create_osint_job(
        target=(profile.usernames[0] if profile.usernames else None) or profile.first_name or 'unknown',
        job_type="v2_investigation",
        payload={"profile": profile_data, "modes": modes, "tiers": tiers, "force_refresh": force_refresh, "enable_serp": enable_serp},
    )

    def _run_v2_job(job_id):
        try:
            with _osint_jobs_lock:
                j = _osint_jobs.get(job_id)
                j["status"] = "running"
                j["started_at"] = _utc_now()

            snap = _get_osint_job(job_id)
            pl = snap["payload"]

            def on_progress(fields):
                event_type = fields.get("type", "")

                # Map engine event type to progress dict fields
                progress_fields = {}
                for key in ("completed", "total", "found_count", "actionable_findings",
                            "manual_review_count", "error_count", "current_site",
                            "tier", "phase"):
                    if key in fields:
                        progress_fields[key] = fields[key]

                if event_type == "site_found":
                    progress_fields["latest_found_site"] = fields.get("site_name", "")
                    progress_fields["latest_confidence_level"] = fields.get("confidence_level", "")
                    progress_fields["latest_confidence_score"] = fields.get("confidence_score", 0)

                if progress_fields:
                    _update_osint_progress(job_id, progress_fields)

                # Append a log entry so the frontend log panel gets populated
                if event_type == "site_check_completed":
                    status = fields.get("status", "")
                    level = "info"
                    if status == "found":
                        level = "found"
                    elif status in ("error", "rate_limited"):
                        level = "warn"
                    sms = fields.get("subject_match_score", 0)
                    sms_label = ""
                    if sms >= 70:
                        sms_label = f" | Subject Match: {sms}%"
                    elif sms >= 30:
                        sms_label = f" | Possible Match: {sms}%"
                    username_searched = fields.get("username", "") or fields.get("username_searched", "")
                    _append_osint_log(job_id, {
                        "level": level,
                        "site_name": fields.get("site_name", ""),
                        "username": username_searched,
                        "message": f"{username_searched} — {fields.get('confidence_level', status)}{sms_label}",
                        "status": status,
                        "confidence_level": fields.get("confidence_level", ""),
                        "confidence_score": fields.get("confidence_score", 0),
                        "url": fields.get("url", ""),
                        "tier": fields.get("tier"),
                        "response_time_ms": fields.get("response_time_ms", 0),
                        "completed": fields.get("completed", 0),
                        "total": fields.get("total", 0),
                        "subject_match_score": sms,
                        "matched_attributes": fields.get("matched_attributes", []),
                        "display_name": fields.get("display_name", ""),
                        "location": fields.get("location", ""),
                        "cross_links": fields.get("cross_links", []),
                        "category": fields.get("category", ""),
                        "search_mode": fields.get("search_mode", ""),
                    })
                elif event_type == "site_check_started":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "site_name": fields.get("site_name", ""),
                        "message": f"Searching '{fields.get('username', '')}' on {fields.get('site_name', '')}",
                        "status": "checking",
                        "tier": fields.get("tier"),
                        "username": fields.get("username", ""),
                    })
                elif event_type == "tier_started":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "message": f"Starting Tier {fields.get('tier')} — {fields.get('site_count', 0)} sites",
                    })
                elif event_type == "tier_completed":
                    prog = fields.get("progress", {})
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "message": f"Tier {fields.get('tier')} complete — {prog.get('found', 0)} found of {prog.get('total_sites', 0)} sites",
                    })
                elif event_type == "investigation_started":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "message": f"Investigation started — modes: {', '.join(fields.get('modes', []))}",
                    })
                elif event_type == "investigation_completed":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "message": f"Investigation complete — {fields.get('actionable_findings', 0)} actionable findings",
                    })
                elif event_type == "manifest_loaded":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "message": f"Loaded {fields.get('enabled_sites', 0)} sites ({fields.get('suppressed_sites', 0)} suppressed)",
                    })
                elif event_type == "serp_discovery_started":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "message": f"SERP pre-pass: {fields.get('dorks', 0)} dorks via {', '.join(fields.get('backends', []))}",
                    })
                elif event_type == "serp_discovery_completed":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "message": f"SERP pre-pass found {fields.get('discoveries', 0)} on-catalog candidates + {fields.get('external_discoveries', 0)} external leads from {fields.get('raw_hits', 0)} raw hits ({fields.get('elapsed_ms', 0)}ms)",
                    })
                elif event_type == "serp_discovery_failed":
                    _append_osint_log(job_id, {
                        "level": "warn",
                        "phase": event_type,
                        "message": f"SERP pre-pass failed: {fields.get('error', '')}",
                    })
                elif event_type == "intelbase_started":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "site_name": "Intelbase Email Lookup",
                        "message": f"Intelbase email lookup started for {fields.get('email', '')}",
                        "status": "checking",
                    })
                elif event_type == "intelbase_completed":
                    level = "found" if fields.get("found") else "info"
                    _append_osint_log(job_id, {
                        "level": level,
                        "phase": event_type,
                        "site_name": "Intelbase Email Lookup",
                        "message": (
                            f"Intelbase complete for {fields.get('email', '')}: "
                            f"{fields.get('platforms', 0)} platform signals, "
                            f"{fields.get('breaches', 0)} breach signals"
                        ),
                        "status": "found" if fields.get("found") else "not_found",
                        "response_time_ms": fields.get("elapsed_ms", 0),
                    })
                elif event_type == "intelbase_skipped":
                    _append_osint_log(job_id, {
                        "level": "info",
                        "phase": event_type,
                        "site_name": "Intelbase Email Lookup",
                        "message": f"Intelbase skipped: {fields.get('reason', '')}",
                        "status": "skipped",
                    })
                elif event_type == "intelbase_failed":
                    _append_osint_log(job_id, {
                        "level": "warn",
                        "phase": event_type,
                        "site_name": "Intelbase Email Lookup",
                        "message": f"Intelbase failed for {fields.get('email', '')}: {fields.get('error', '')}",
                        "status": "error",
                    })

            engine = InvestigationEngine()
            engine.set_progress_callback(on_progress)
            engine.set_stop_callback(lambda: _should_stop_osint_job(job_id))
            engine.set_pause_callback(lambda: _should_pause_osint_job(job_id))
            prof = SubjectProfile.from_dict(pl["profile"])
            result = engine.run_investigation(
                prof,
                modes=pl.get("modes"),
                tiers=pl.get("tiers"),
                force_manifest_refresh=pl.get("force_refresh", False),
                enable_serp_discovery=pl.get("enable_serp", True),
            )

            # Add disambiguation hint if only name was provided
            has_name = bool(prof.first_name and prof.last_name)
            has_other = bool(prof.usernames or prof.emails or prof.phones)
            has_context = bool(prof.city or prof.workplace or prof.educational_institution)
            if has_name and not has_other and not has_context:
                if isinstance(result, dict) and result.get("data"):
                    data = result["data"] if isinstance(result["data"], dict) else result
                    data["disambiguation_hint"] = (
                        "Results may include accounts from different people with the same name. "
                        "Add phone, email, city, or workplace to narrow results to your specific subject."
                    )

            _finish_osint_job(job_id, "completed", result=result)
        except Exception as e:
            # Check if it was an intentional cancellation
            if type(e).__name__ == "InvestigationCancelled" or "cancelled" in str(e).lower():
                _finish_osint_job(job_id, "cancelled", error="Investigation cancelled by user")
            else:
                _finish_osint_job(job_id, "failed", error=str(e))

    Thread(target=_run_v2_job, args=(job["job_id"],), daemon=True).start()
    return jsonify({"success": True, "data": {"job_id": job["job_id"]}})


@osint_blueprint.route('/v2/investigate/status/<job_id>', methods=['GET'])
def osint_v2_investigate_status(job_id):
    return _job_response(job_id)


@osint_blueprint.route('/v2/investigate/result/<job_id>', methods=['GET'])
def osint_v2_investigate_result(job_id):
    return _job_response(job_id)


@osint_blueprint.route('/v2/investigate/cancel/<job_id>', methods=['POST'])
def osint_v2_investigate_cancel(job_id):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job: return jsonify({"success": False, "error": "Not found"}), 404
        job["cancel_requested"] = True
        job["pause_requested"] = False  # clear pause so engine can exit cleanly
    return jsonify({"success": True})


@osint_blueprint.route('/v2/investigate/pause/<job_id>', methods=['POST'])
def osint_v2_investigate_pause(job_id):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job: return jsonify({"success": False, "error": "Not found"}), 404
        if job.get("status") != "running":
            return jsonify({"success": False, "error": "Job is not running"}), 400
        job["pause_requested"] = True
        job["status"] = "paused"
    return jsonify({"success": True})


@osint_blueprint.route('/v2/investigate/resume/<job_id>', methods=['POST'])
def osint_v2_investigate_resume(job_id):
    with _osint_jobs_lock:
        job = _osint_jobs.get(job_id)
        if not job: return jsonify({"success": False, "error": "Not found"}), 404
        job["pause_requested"] = False
        job["status"] = "running"
    return jsonify({"success": True})


@osint_blueprint.route('/v2/quick', methods=['POST'])
def osint_v2_quick():
    """Quick single-target search (backward-compatible convenience endpoint)."""
    try:
        from modules.osint.osint_engine.engine import quick_search
    except ImportError as e:
        return jsonify({"success": False, "error": f"OSINT engine not available: {e}"}), 503

    payload = request.get_json(silent=True) or {}
    target = str(payload.get('target', '')).strip()
    if not target:
        return jsonify({"success": False, "error": "No target provided"}), 400

    modes = payload.get('modes') or None
    try:
        result = quick_search(target, modes=modes)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@osint_blueprint.route('/v2/calibrate', methods=['POST'])
def osint_v2_calibrate():
    """Run self-test calibration against known-good/known-absent usernames."""
    try:
        from modules.osint.osint_engine import InvestigationEngine
    except ImportError as e:
        return jsonify({"success": False, "error": f"OSINT engine not available: {e}"}), 503

    payload = request.get_json(silent=True) or {}
    sites = payload.get('sites') or None
    try:
        engine = InvestigationEngine()
        result = engine.run_calibration(site_names=sites)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@osint_blueprint.route('/v2/export', methods=['POST'])
def osint_v2_export():
    """Export investigation results as JSON, CSV, or text report."""
    from flask import Response
    payload = request.get_json(silent=True) or {}
    investigation = payload.get('investigation')
    fmt = payload.get('format', 'json').lower()

    if not investigation:
        return jsonify({"success": False, "error": "No investigation data provided"}), 400

    if fmt == 'json':
        return jsonify({"success": True, "data": investigation})

    if fmt == 'csv':
        try:
            import csv
            import io
            findings = [
                result for result in _investigation_results(investigation)
                if result.get('status') != 'not_found'
            ]

            output = io.StringIO()
            fields = ['site', 'url', 'status', 'confidence_level', 'confidence_score',
                      'tier', 'category', 'mode', 'username_searched', 'display_name',
                      'bio', 'location', 'followers', 'name_match', 'dob_match']
            writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
            writer.writeheader()
            for r in findings:
                meta = r.get('metadata') or {}
                row = {
                    'site': r.get('site') or r.get('site_name', ''),
                    'url': r.get('url', ''),
                    'status': r.get('status', ''),
                    'confidence_level': r.get('confidence_level', ''),
                    'confidence_score': r.get('confidence_score', ''),
                    'tier': r.get('tier', ''),
                    'category': r.get('category', ''),
                    'mode': r.get('mode') or r.get('search_mode', ''),
                    'username_searched': r.get('username_searched', ''),
                    'display_name': r.get('display_name') or meta.get('display_name', ''),
                    'bio': r.get('bio') or meta.get('bio', ''),
                    'location': r.get('location') or meta.get('location', ''),
                    'followers': r.get('follower_count') or meta.get('followers', ''),
                    'name_match': r.get('name_match', ''),
                    'dob_match': r.get('dob_match', ''),
                }
                writer.writerow(row)

            csv_bytes = output.getvalue().encode('utf-8')
            return Response(
                csv_bytes,
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=investigation.csv'}
            )
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    if fmt == 'report':
        try:
            report = _generate_text_report(investigation)
            return jsonify({"success": True, "data": {"report": report}})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": False, "error": f"Unknown format: {fmt}"}), 400


def _generate_text_report(inv: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("ARGUS OSINT INVESTIGATION REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("")

    profile = _investigation_profile(inv)
    if profile:
        lines.append("SUBJECT PROFILE")
        lines.append("-" * 40)
        for k, v in profile.items():
            if v:
                lines.append(f"  {k}: {v}")
        lines.append("")

    summary = _investigation_summary(inv)
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Confirmed accounts  : {summary.get('confirmed', 0)}")
    lines.append(f"  High confidence     : {summary.get('high_confidence', 0)}")
    lines.append(f"  Medium confidence   : {summary.get('medium_confidence', 0)}")
    lines.append(f"  Manual review needed: {summary.get('manual_review_count', 0)}")
    lines.append(f"  Sites checked       : {summary.get('total_checked', 0)}")
    lines.append("")

    findings = _actionable_findings(inv)
    if findings:
        lines.append("ACTIONABLE FINDINGS")
        lines.append("-" * 40)
        for f in findings:
            lines.append(f"  [{f.get('confidence_level', '?')}] {f.get('site', '?')} — {f.get('url', '')}")
            meta = f.get('metadata') or {}
            if meta.get('display_name'):
                lines.append(f"    Name: {meta['display_name']}")
            if meta.get('bio'):
                lines.append(f"    Bio : {meta['bio'][:120]}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)
    return "\n".join(lines)
