import { postJson } from '../../shared/api/http';

/**
 * Fetch a Maltego-style connection graph for a given seed PII value.
 * @param {string} seed - The value to search for (email, phone, or name)
 * @param {string} seedType - "email" | "phone" | "name"
 * @param {number} maxRecords - Hard cap on records per entity (default 100)
 */
export async function buildConnectionGraph(seed, seedType, maxRecords = 100) {
    try {
        const data = await postJson(
            '/breach/graph/connections',
            {
                seed,
                seed_type: seedType,
                max_records_per_entity: maxRecords,
            },
            undefined,
            'Failed to generate connection graph',
        );

        if (!data.success) {
            throw new Error(data.error || 'Graph generation failed');
        }

        return data.data; // The Graph object
    } catch (error) {
        console.error('Connection Graph Error:', error);
        throw error;
    }
}
