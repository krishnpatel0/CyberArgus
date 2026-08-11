import { JSON_HEADERS, requestJson, postJson } from '../../shared/api/http';
import { apiUrl } from '../../shared/api/apiConfig';

export async function searchOSINT(username, signal) {
    return postJson('/osint/search', { target: username }, signal, 'OSINT search failed');
}

export async function searchOSINTRecursive(target, maxDepth = 2, signal) {
    return postJson(
        '/osint/search/recursive',
        { target, max_depth: maxDepth },
        signal,
        'Recursive OSINT search failed',
    );
}

export async function searchOSINTCsvOnly(username, signal) {
    return postJson('/osint/csv-only', { target: username }, signal, 'CSV search failed');
}

export async function startOSINTSearchJob(target, options = {}, signal) {
    return postJson(
        '/osint/search/start',
        {
            target,
            recursive: Boolean(options.recursive),
            max_depth: options.maxDepth ?? 2,
        },
        signal,
        'OSINT job start failed',
    );
}

export async function getOSINTSearchJobStatus(jobId, signal) {
    return requestJson(`/osint/search/status/${jobId}`, { method: 'GET', signal }, 'OSINT job status failed');
}

export async function getOSINTSearchJobResult(jobId, signal) {
    return requestJson(`/osint/search/result/${jobId}`, { method: 'GET', signal }, 'OSINT job result failed');
}

export async function runInvestigation(profile, modes = null, tiers = null, signal) {
    const body = { profile };
    if (modes) body.modes = modes;
    if (tiers) body.tiers = tiers;

    return postJson('/osint/v2/investigate', body, signal, 'Investigation failed');
}

export async function startInvestigationJob(profile, modes = null, tiers = null, options = {}, signal) {
    const body = { profile };
    if (modes) body.modes = modes;
    if (tiers) body.tiers = tiers;
    if (options.forceManifestRefresh) body.force_manifest_refresh = true;
    body.enable_serp_discovery = options.enableSerpDiscovery !== false;

    return postJson('/osint/v2/investigate/start', body, signal, 'Investigation job start failed');
}

export async function getInvestigationJobStatus(jobId, signal) {
    return requestJson(
        `/osint/v2/investigate/status/${jobId}`,
        { method: 'GET', signal },
        'Investigation job status failed',
    );
}

export async function getInvestigationJobResult(jobId, signal) {
    return requestJson(
        `/osint/v2/investigate/result/${jobId}`,
        { method: 'GET', signal },
        'Investigation job result failed',
    );
}

export async function cancelInvestigationJob(jobId, signal) {
    return requestJson(
        `/osint/v2/investigate/cancel/${jobId}`,
        { method: 'POST', signal },
        'Investigation job cancel failed',
    );
}

export async function pauseInvestigationJob(jobId) {
    return requestJson(`/osint/v2/investigate/pause/${jobId}`, { method: 'POST' }, 'Pause failed');
}

export async function resumeInvestigationJob(jobId) {
    return requestJson(`/osint/v2/investigate/resume/${jobId}`, { method: 'POST' }, 'Resume failed');
}

export async function quickSearch(target, signal) {
    return postJson('/osint/v2/quick', { target }, signal, 'Quick search failed');
}

export async function runCalibration(sites = null, signal) {
    return postJson('/osint/v2/calibrate', sites ? { sites } : {}, signal, 'Calibration failed');
}

export async function exportInvestigation(investigation, format = 'json', signal) {
    const response = await fetch(apiUrl('/osint/v2/export'), {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify({ investigation, format }),
        signal,
    });

    if (format === 'csv') {
        if (!response.ok) {
            throw new Error('Export failed');
        }
        return response.blob();
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(data.error || `Export failed (HTTP ${response.status})`);
    }
    return data;
}
