import { apiUrl } from './apiConfig';

export const JSON_HEADERS = {
    'Content-Type': 'application/json',
};

export async function parseJsonResponse(response) {
    const text = await response.text();

    if (!text) {
        return {};
    }

    try {
        return JSON.parse(text);
    } catch {
        throw new Error(`Invalid JSON response (HTTP ${response.status})`);
    }
}

export async function requestJson(path, options = {}, defaultError = 'Request failed') {
    const headers = new Headers(options.headers || {});
    const token = window.sessionStorage.getItem('aw_token');

    if (token && !headers.has('Authorization')) {
        headers.set('Authorization', `Bearer ${token}`);
    }

    const response = await fetch(apiUrl(path), { ...options, headers });
    const data = await parseJsonResponse(response);

    if (!response.ok) {
        throw new Error(data.detail || data.error || `${defaultError} (HTTP ${response.status})`);
    }

    return data;
}

export function postJson(path, body, signal, defaultError = 'Request failed') {
    return requestJson(
        path,
        {
            method: 'POST',
            headers: JSON_HEADERS,
            body: JSON.stringify(body),
            signal,
        },
        defaultError,
    );
}
