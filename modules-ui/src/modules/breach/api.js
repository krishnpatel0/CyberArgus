import { requestJson, postJson } from '../../shared/api/http';

export const checkBreachHealth = async () => {
    try {
        const data = await requestJson('/breach/health', {}, 'Breach backend is offline');
        return { success: true, data };
    } catch (error) {
        return {
            success: false,
            error: error.message || 'Unable to reach breach backend',
        };
    }
};

export const fetchBreachFields = async () => {
    try {
        const data = await requestJson('/breach/fields', {}, 'Failed to load searchable fields');
        return { success: true, data: data.data || [] };
    } catch (error) {
        return {
            success: false,
            error: error.message || 'Failed to load searchable fields',
        };
    }
};

export const searchBreachDatabase = async ({ filters, limit = 50, offset = 0, signal }) => {
    try {
        const data = await postJson(
            '/breach/search',
            { filters, limit, offset },
            signal,
            'Database search failed',
        );
        return { success: true, data: data.data };
    } catch (error) {
        if (error.name === 'AbortError') {
            return {
                success: false,
                aborted: true,
                error: 'Search cancelled',
            };
        }

        return {
            success: false,
            error: error.message || 'Database search failed',
        };
    }
};
