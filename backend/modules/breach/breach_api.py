from flask import Blueprint, request, jsonify
import requests
import os

breach_blueprint = Blueprint('breach', __name__)

BREACH_API_BASE_URL = os.getenv('BREACH_API_BASE_URL', 'http://127.0.0.1:8000').rstrip('/')
BREACH_SEARCH_TIMEOUT = int(os.getenv('BREACH_SEARCH_TIMEOUT', '120'))
BREACH_SEARCH_API_KEY = os.getenv('BREACH_SEARCH_API_KEY', '').strip()

def _auth_headers() -> dict:
    """Return X-API-Key header if a key is configured."""
    return {'X-API-Key': BREACH_SEARCH_API_KEY} if BREACH_SEARCH_API_KEY else {}

def breach_api_get(path, params=None, timeout=15):
    """Call the external breach API and parse its JSON response."""
    try:
        response = requests.get(
            f"{BREACH_API_BASE_URL}{path}",
            params=params,
            headers=_auth_headers(),
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise ValueError(str(e))

def breach_api_post(path, payload=None, timeout=15):
    """Call the external breach API with POST and parse its JSON response."""
    try:
        response = requests.post(
            f"{BREACH_API_BASE_URL}{path}",
            json=payload or {},
            headers=_auth_headers(),
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise ValueError(str(e))

@breach_blueprint.route('/health', methods=['GET'])
def breach_health():
    """Check connectivity to the external breach database backend."""
    try:
        data = breach_api_get('/health', timeout=5)
        return jsonify({
            "success": True,
            "connected": True,
            "backendUrl": BREACH_API_BASE_URL,
            "data": data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "connected": False,
            "backendUrl": BREACH_API_BASE_URL,
            "error": "Breach backend is offline",
            "details": str(e)
        }), 503

@breach_blueprint.route('/fields', methods=['GET'])
def breach_fields():
    """Fetch the searchable field catalog from the external breach backend."""
    try:
        fields = breach_api_get('/fields', timeout=10)
        if isinstance(fields, dict):
            fields = fields.get("direct_fields") or fields.get("all_fields") or fields.get("fields") or []
        if not isinstance(fields, list):
            raise ValueError("Invalid field catalog returned by breach backend")

        return jsonify({
            "success": True,
            "data": fields
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Breach backend is offline",
            "details": str(e)
        }), 503

@breach_blueprint.route('/search', methods=['POST'])
def search_breaches():
    """Proxy multi-filter breach searches to the unified search backend."""
    payload = request.get_json(silent=True) or {}
    filters = payload.get('filters', [])
    legacy_target = str(payload.get('target', '')).strip()

    clean_filters = []
    for item in filters:
        if not isinstance(item, dict):
            continue

        field = str(item.get('field', '')).strip()
        value = str(item.get('value', '')).strip()

        if field and value:
            clean_filters.append({
                "field": field,
                "value": value
            })

    if not clean_filters and legacy_target:
        clean_filters.append({
            "field": "email",
            "value": legacy_target
        })

    if not clean_filters:
        return jsonify({
            "success": False,
            "error": "At least one valid search filter is required"
        }), 400

    try:
        limit = int(payload.get('limit', 50))
    except (TypeError, ValueError):
        limit = 50

    try:
        offset = int(payload.get('offset', 0))
    except (TypeError, ValueError):
        offset = 0

    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    try:
        result = breach_api_post(
            '/search/direct',
            payload={
                "filters": clean_filters,
                "limit": limit,
                "offset": offset,
                "include_count": True,
            },
            timeout=BREACH_SEARCH_TIMEOUT
        )

        return jsonify({
            "success": True,
            "data": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Breach search failed",
            "details": str(e)
        }), 500


@breach_blueprint.route('/graph/connections', methods=['POST'])
def api_graph_connections():
    """Proxy for Maltego-style graph connection search."""
    payload = request.get_json(silent=True) or {}
    seed = str(payload.get('seed', '')).strip()
    seed_type = str(payload.get('seed_type', '')).strip().lower()

    if not seed or not seed_type:
        return jsonify({
            "success": False,
            "error": "Seed and seed_type are required"
        }), 400

    if seed_type not in ('email', 'phone', 'name'):
        return jsonify({
            "success": False,
            "error": "Invalid seed_type. Must be email, phone, or name"
        }), 400

    try:
        result = breach_api_post(
            '/search/connections',
            payload={
                "seed": seed,
                "seed_type": seed_type,
                "max_records_per_entity": int(payload.get('max_records_per_entity', 100))
            },
            timeout=60
        )

        return jsonify({
            "success": True,
            "data": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Graph query failed",
            "details": str(e)
        }), 500
