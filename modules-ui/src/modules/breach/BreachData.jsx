import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    AlertTriangle,
    CheckCircle2,
    ChevronDown,
    ChevronUp,
    Database,
    Filter,
    Layers3,
    Plus,
    RefreshCw,
    Search,
    Server,
    Share2,
    UserSearch,
    X,
    Maximize2,
    Minimize2,
} from 'lucide-react';
import ForceGraph2D from 'react-force-graph-2d';
import {
    checkBreachHealth,
    fetchBreachFields,
    searchBreachDatabase,
} from './api';
import { buildConnectionGraph } from './graphApi';
import { useSearchContext } from '../../shared/context/SearchContext';
import ConnectionGraph from '../../shared/visualization/ConnectionGraph';
import './BreachData.css';

const PAGE_SIZE = 50;
const FALLBACK_FIELDS = ['email', 'source_file', 'firstname', 'lastname', 'mobile', 'phone', 'city', 'state'];

const createFilter = (field = 'email') => ({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    field,
    value: '',
});

// ─── Generic seed detection ───
// Classifies any field name into a seed type by pattern-matching,
// so it works with any data schema (not just the dummy CSVs).

const PHONE_PATTERNS = /phone|mobile|cell|tel|contact_number|whatsapp/i;
const EMAIL_PATTERNS = /email|e-mail|mail_id|email_address/i;
const NAME_PATTERNS  = /^name$|full_?name|display_?name|first_?name|last_?name|fname|lname|user_?name|real_?name/i;

const classifyField = (fieldName) => {
    if (PHONE_PATTERNS.test(fieldName)) return 'phone';
    if (EMAIL_PATTERNS.test(fieldName)) return 'email';
    if (NAME_PATTERNS.test(fieldName))  return 'name';
    return null;
};

const looksLikeEmail = (v) => typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const looksLikePhone = (v) => {
    const digits = String(v).replace(/[\s\-+()]/g, '');
    return /^\d{7,15}$/.test(digits);
};

// Scans all fields in a record and returns the best seed { value, type }.
// Priority: phone → email → name (matching the backend's entity extraction order).
const extractSeedFromFields = (fields) => {
    let emailSeed = null;
    let phoneSeed = null;
    let nameParts = {};  // collect first/last separately for combining

    for (const [key, rawVal] of Object.entries(fields)) {
        const val = rawVal == null ? '' : String(rawVal).trim();
        if (!val) continue;

        const cls = classifyField(key);

        if (cls === 'phone' && !phoneSeed && looksLikePhone(val)) {
            phoneSeed = val;
        } else if (cls === 'email' && !emailSeed && looksLikeEmail(val)) {
            emailSeed = val;
        } else if (cls === 'name') {
            // If it's a full name field, use directly
            if (/^name$|full_?name|display_?name|real_?name/i.test(key)) {
                nameParts.full = val;
            } else if (/first|fname/i.test(key)) {
                nameParts.first = val;
            } else if (/last|lname/i.test(key)) {
                nameParts.last = val;
            } else if (!nameParts.full) {
                nameParts.full = val;
            }
        }

        // Also detect by value shape if field name is ambiguous
        if (!cls) {
            if (!emailSeed && looksLikeEmail(val)) emailSeed = val;
            else if (!phoneSeed && looksLikePhone(val)) phoneSeed = val;
        }
    }

    if (emailSeed) return { value: emailSeed, type: 'email' };
    if (phoneSeed) return { value: phoneSeed, type: 'phone' };

    const nameVal = nameParts.full || [nameParts.first, nameParts.last].filter(Boolean).join(' ');
    if (nameVal && nameVal.length > 1) return { value: nameVal, type: 'name' };

    return null;
};

const formatFieldLabel = (field) =>
    field
        .replace(/_/g, ' ')
        .replace(/([a-z])([A-Z])/g, '$1 $2')
        .replace(/\b\w/g, (char) => char.toUpperCase());

const getPrimaryIdentity = (record) => {
    const data = record?.data || {};

    if (record?.email) {
        return {
            primary: record.email,
            secondary: 'Indexed email match',
        };
    }

    if (data.email) {
        return {
            primary: data.email,
            secondary: 'Nested email attribute',
        };
    }

    if (data.mobile || data.phone || data.number) {
        return {
            primary: data.mobile || data.phone || data.number,
            secondary: 'Phone-linked record',
        };
    }

    if (data.name || data.firstname || data.lastname) {
        return {
            primary: [data.name, data.firstname, data.lastname].filter(Boolean).join(' ').trim(),
            secondary: 'Name-linked record',
        };
    }

    return {
        primary: 'Sparse record',
        secondary: 'Only source metadata available',
    };
};

const getAttributePreview = (record) => {
    const data = record?.data || {};

    return Object.entries(data)
        .filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== '')
        .filter(([key]) => !['email', 'source'].includes(key))
        .slice(0, 5);
};

const BreachData = () => {
    const navigate = useNavigate();
    const { setBreachResults, setBreachFilters, launchOsintFromBreach } = useSearchContext();
    const [filters, setFilters] = useState([createFilter()]);
    const [availableFields, setAvailableFields] = useState(FALLBACK_FIELDS);
    const [backendStatus, setBackendStatus] = useState({
        checking: true,
        online: false,
        backendUrl: null,
        error: null,
    });
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);
    const [expandedRows, setExpandedRows] = useState({});
    const [lastFilterCount, setLastFilterCount] = useState(0);

    // Graph states
    const [graphData, setGraphData] = useState(null);
    const [showGraph, setShowGraph] = useState(false);
    const [graphMinimized, setGraphMinimized] = useState(false);
    const [graphLoading, setGraphLoading] = useState(false);
    const [graphError, setGraphError] = useState(null);

    const searchControllerRef = useRef(null);
    const graphControllerRef = useRef(null);
    const searchRequestIdRef = useRef(0);

    const abortPendingRequests = useCallback(() => {
        const searchController = searchControllerRef.current;
        const graphController = graphControllerRef.current;
        if (searchController) {
            searchController.abort();
        }
        if (graphController) {
            graphController.abort();
        }
    }, []);

    useEffect(() => {
        initializeBreachModule();
        return abortPendingRequests;
    }, [abortPendingRequests]);

    const loadConnections = async (record = null, manualSeed = null, manualType = null) => {
        setGraphLoading(true);
        setGraphError(null);
        setShowGraph(true);
        setGraphMinimized(false);

        let seedValue = manualSeed;
        let seedType = manualType;

        if (!manualSeed) {
            const validFilter = filters.find(f => f.value && classifyField(f.field));
            if (record && validFilter) {
                seedValue = validFilter.value;
                seedType = classifyField(validFilter.field);
            } else if (record) {
                // Single Record Mode — dynamically detect seed from any field
                const data = record.data || {};
                const allFields = { ...data };
                if (record.email) allFields.email = record.email;

                // Try to find the best seed by scanning all fields
                const found = extractSeedFromFields(allFields);
                if (found) {
                    seedValue = found.value;
                    seedType = found.type;
                }
            } else {
                // Global Mode — map the user's active filter to a seed type
                if (validFilter) {
                    seedValue = validFilter.value;
                    seedType = classifyField(validFilter.field);
                }
            }
        }

        if (!seedValue || !seedType) {
            setGraphError('Could not identify a valid seed (Phone, Email, or Name) for connection mapping.');
            setGraphLoading(false);
            return;
        }

        try {
            const graph = await buildConnectionGraph(seedValue, seedType);
            setGraphData(graph);
        } catch (err) {
            setGraphError(err.message || 'Failed to generate connection graph');
        } finally {
            setGraphLoading(false);
        }
    };

    const handleRecenter = (node) => {
        if (node.type === 'RECORD') {
            loadConnections(node.record_data);
        } else {
            const typeMap = { 'EMAIL': 'email', 'PHONE': 'phone', 'NAME': 'name' };
            const type = typeMap[node.type] || 'email';
            loadConnections(null, node.value, type);
        }
    };

    const initializeBreachModule = async () => {
        setBackendStatus((current) => ({ ...current, checking: true }));

        const [healthResult, fieldsResult] = await Promise.all([
            checkBreachHealth(),
            fetchBreachFields(),
        ]);

        if (fieldsResult.success && fieldsResult.data.length > 0) {
            const fieldSet = new Set(['email', 'source_file', ...fieldsResult.data]);
            setAvailableFields(Array.from(fieldSet));
        } else {
            setAvailableFields(FALLBACK_FIELDS);
        }

        if (healthResult.success) {
            setBackendStatus({
                checking: false,
                online: true,
                backendUrl: healthResult.data.backendUrl,
                error: null,
            });
        } else {
            setBackendStatus({
                checking: false,
                online: false,
                backendUrl: healthResult.data?.backendUrl || 'http://127.0.0.1:8000',
                error: healthResult.error,
            });
        }
    };

    // Persist results to context when they change
    useEffect(() => {
        if (results) setBreachResults(results);
    }, [results, setBreachResults]);

    useEffect(() => {
        setBreachFilters(filters);
    }, [filters, setBreachFilters]);

    const getOsintUsername = (record) => {
        const data = record?.data || {};
        // Priority: username fields > email prefix > name
        const usernameFields = ['fb_username','ig_username','linkedin_username','twitter_handle',
            'bb_username','naukri_username','username'];
        for (const f of usernameFields) {
            if (data[f]) return data[f].replace(/^@/, '');
        }
        if (record?.email) return record.email.split('@')[0];
        if (data.email) return data.email.split('@')[0];
        if (data.name) return data.name.replace(/\s+/g, '').toLowerCase();
        if (data.firstname && data.lastname)
            return `${data.firstname}${data.lastname}`.replace(/\s+/g, '').toLowerCase();
        return null;
    };

    const handleOsintLookup = (record) => {
        const username = getOsintUsername(record);
        if (!username) return;
        launchOsintFromBreach(username);
        navigate('/osint');
    };

    const updateFilter = (id, key, value) => {
        setFilters((current) =>
            current.map((filter) => (filter.id === id ? { ...filter, [key]: value } : filter)),
        );
    };

    const addFilter = () => {
        setFilters((current) => [...current, createFilter(current[0]?.field || 'email')]);
    };

    const removeFilter = (id) => {
        setFilters((current) => {
            if (current.length === 1) {
                return current;
            }

            return current.filter((filter) => filter.id !== id);
        });
    };

    const runSearch = async (offset = 0) => {
        const activeFilters = filters
            .map((filter) => ({
                field: filter.field?.trim(),
                value: filter.value?.trim(),
            }))
            .filter((filter) => filter.field && filter.value);

        if (activeFilters.length === 0) {
            setError('Enter at least one field value before searching the breach database.');
            return;
        }

        if (searchControllerRef.current) {
            searchControllerRef.current.abort();
        }

        const controller = new AbortController();
        const requestId = searchRequestIdRef.current + 1;
        searchControllerRef.current = controller;
        searchRequestIdRef.current = requestId;

        setLoading(true);
        setError(null);

        const result = await searchBreachDatabase({
            filters: activeFilters,
            limit: PAGE_SIZE,
            offset,
            signal: controller.signal,
        });

        if (result.aborted) {
            return;
        }

        if (searchRequestIdRef.current !== requestId) {
            return;
        }

        if (result.success) {
            setResults(result.data);
            setExpandedRows({});
            setLastFilterCount(activeFilters.length);
        } else {
            setResults(null);
            setError(result.error);
        }

        if (searchControllerRef.current === controller) {
            searchControllerRef.current = null;
        }
        setLoading(false);
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        await runSearch(0);
    };

    const toggleExpanded = (rowKey) => {
        setExpandedRows((current) => ({
            ...current,
            [rowKey]: !current[rowKey],
        }));
    };

    const currentPage = results ? Math.floor((results.offset || 0) / (results.limit || PAGE_SIZE)) + 1 : 1;
    const totalPages = results ? Math.max(1, Math.ceil((results.count || 0) / (results.limit || PAGE_SIZE))) : 1;

    return (
        <div className="breach-page">
            <section className="breach-hero">
                <div className="breach-top-row">
                    <div className="breach-title-block">
                        <h2>Breach Presence Hub</h2>
                        <p>
                            Multi-filter warehouse search across indexed breach and contact records using
                            the live unified search backend.
                        </p>
                    </div>

                    <div className={`breach-status ${backendStatus.online ? 'success' : backendStatus.checking ? 'info' : 'error'}`}>
                        {backendStatus.checking ? <RefreshCw size={14} className="spin-slow" /> : backendStatus.online ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                        <span>
                            {backendStatus.checking ? 'Checking Backend' : backendStatus.online ? 'Database Linked' : 'Backend Offline'}
                        </span>
                    </div>
                </div>

                <div className="breach-meta-row">
                    <div className="breach-meta-pill">
                        <Server size={14} />
                        <span>{backendStatus.backendUrl || 'http://127.0.0.1:8000'}</span>
                    </div>
                    <div className="breach-meta-pill">
                        <Layers3 size={14} />
                        <span>{availableFields.length} searchable fields</span>
                    </div>
                    <button type="button" className="breach-refresh-btn" onClick={initializeBreachModule}>
                        <RefreshCw size={14} />
                        <span>Refresh Link</span>
                    </button>
                </div>
            </section>

            {backendStatus.error && !backendStatus.online && (
                <div className="breach-alert breach-alert-warning fade-in">
                    <AlertTriangle size={18} />
                    <div>
                        <strong>Breach backend unavailable</strong>
                        <p>{backendStatus.error}</p>
                    </div>
                </div>
            )}

            {error && (
                <div className="breach-alert breach-alert-error fade-in">
                    <AlertTriangle size={18} />
                    <div>
                        <strong>Search failed</strong>
                        <p>{error}</p>
                    </div>
                </div>
            )}

            <div className="breach-layout">
                <section className="card breach-search-card">
                    <div className="breach-section-header">
                        <div>
                            <span className="breach-kicker">Query Builder</span>
                            <h3>Multi-Filter Database Search</h3>
                        </div>
                        <div className="breach-section-icon">
                            <Filter size={18} />
                        </div>
                    </div>

                    <form onSubmit={handleSubmit} className="breach-form">
                        <div className="breach-filter-list">
                            {filters.map((filter, index) => (
                                <div key={filter.id} className="breach-filter-row">
                                    <div className="breach-filter-index">{String(index + 1).padStart(2, '0')}</div>

                                    <div className="breach-field-group">
                                        <label htmlFor={`field-${filter.id}`}>Field</label>
                                        <select
                                            id={`field-${filter.id}`}
                                            className="breach-select"
                                            value={filter.field}
                                            onChange={(event) => updateFilter(filter.id, 'field', event.target.value)}
                                        >
                                            {availableFields.map((field) => (
                                                <option key={field} value={field}>
                                                    {formatFieldLabel(field)}
                                                </option>
                                            ))}
                                        </select>
                                    </div>

                                    <div className="breach-field-group breach-field-group-grow">
                                        <label htmlFor={`value-${filter.id}`}>Value</label>
                                        <input
                                            id={`value-${filter.id}`}
                                            className="breach-input"
                                            type="text"
                                            value={filter.value}
                                            placeholder={`Match ${formatFieldLabel(filter.field)}`}
                                            onChange={(event) => updateFilter(filter.id, 'value', event.target.value)}
                                        />
                                    </div>

                                    <button
                                        type="button"
                                        className="breach-remove-btn"
                                        onClick={() => removeFilter(filter.id)}
                                        disabled={filters.length === 1}
                                        aria-label="Remove filter"
                                    >
                                        <X size={16} />
                                    </button>
                                </div>
                            ))}
                        </div>

                        <div className="breach-action-row">
                            <button type="button" className="breach-secondary-btn" onClick={addFilter}>
                                <Plus size={16} />
                                <span>Add Filter</span>
                            </button>

                            <button type="submit" className="breach-primary-btn" disabled={loading}>
                                <Search size={16} />
                                <span>{loading ? 'Querying Warehouse...' : 'Search Database'}</span>
                            </button>
                        </div>
                    </form>
                </section>

                <aside className="card breach-intel-card">
                    <div className="breach-section-header">
                        <div>
                            <span className="breach-kicker">Search Intel</span>
                            <h3>What This Module Is Using</h3>
                        </div>
                        <div className="breach-section-icon">
                            <Database size={18} />
                        </div>
                    </div>

                    <div className="breach-intel-list">
                        <div className="breach-intel-item">
                            <strong>Backend</strong>
                            <p>FastAPI warehouse service proxied through the Argus Flask API.</p>
                        </div>
                        <div className="breach-intel-item">
                            <strong>Search Model</strong>
                            <p>Multiple exact-match filters with pagination over indexed warehouse data.</p>
                        </div>
                        <div className="breach-intel-item">
                            <strong>Row Shape</strong>
                            <p>Each result includes `source_file`, optional `email`, and flexible JSON attributes.</p>
                        </div>
                        <div className="breach-intel-item">
                            <strong>Operational Tip</strong>
                            <p>Use `source_file`, `city`, `mobile`, `firstname`, or `email` to quickly validate connectivity.</p>
                        </div>
                    </div>
                </aside>
            </div>

            {loading && (
                <div className="card breach-loading-card">
                    <div className="spinner breach-inline-spinner"></div>
                    <p>Running multi-filter search against the breach warehouse...</p>
                </div>
            )}

            {results && !loading && (
                <section className="breach-results fade-in">
                    <div className="breach-summary-grid">
                        <div className="card breach-summary-card">
                            <span className="breach-summary-label">Total Matches</span>
                            <strong>{(results.count || 0).toLocaleString()}</strong>
                        </div>
                        <div className="card breach-summary-card">
                            <span className="breach-summary-label">Current Page</span>
                            <strong>{currentPage} / {totalPages}</strong>
                        </div>
                        <div className="card breach-summary-card">
                            <span className="breach-summary-label">Applied Filters</span>
                            <strong>{lastFilterCount}</strong>
                        </div>
                    </div>

                    <div className="card breach-results-card">
                        <div className="breach-results-header">
                            <div>
                                <span className="breach-kicker">Result Stream</span>
                                <h3>Warehouse Records</h3>
                            </div>
                            <div className="breach-results-actions">
                                <button
                                    className="breach-action-btn"
                                    onClick={() => loadConnections(null)}
                                    title="Map connections across the entire result set"
                                >
                                    <Share2 size={16} />
                                    <span>Database Connection Map</span>
                                </button>
                            </div>
                            <div className="breach-results-meta">
                                Showing {(results.results || []).length} rows from offset {results.offset || 0}
                            </div>
                        </div>

                        {(results.results || []).length === 0 ? (
                            <div className="breach-empty-state">
                                <Database size={42} />
                                <h4>No records matched</h4>
                                <p>Try exact values like a known `source_file`, city, phone number, or indexed email.</p>
                            </div>
                        ) : (
                            <>
                                <div className="breach-table-wrap">
                                    <table className="breach-table">
                                        <thead>
                                            <tr>
                                                <th>Source</th>
                                                <th>Primary Identifier</th>
                                                <th>Attribute Snapshot</th>
                                                <th>Actions</th>
                                                </tr>
                                                </thead>

                                        <tbody>
                                            {results.results.map((record, index) => {
                                                const rowKey = `${record.source_file || 'source'}-${record.email || 'record'}-${(results.offset || 0) + index}`;
                                                const expanded = !!expandedRows[rowKey];
                                                const identity = getPrimaryIdentity(record);
                                                const preview = getAttributePreview(record);

                                                return (
                                                    <React.Fragment key={rowKey}>
                                                        <tr>
                                                            <td>
                                                                <div className="breach-source-file">{record.source_file || 'Unknown Source'}</div>
                                                                <div className="breach-row-meta">Row #{(results.offset || 0) + index + 1}</div>
                                                            </td>
                                                            <td>
                                                                <div className="breach-primary-value">{identity.primary}</div>
                                                                <div className="breach-secondary-value">{identity.secondary}</div>
                                                            </td>
                                                            <td>
                                                                <div className="breach-attribute-cloud">
                                                                    {preview.length > 0 ? preview.map(([key, value]) => (
                                                                        <span key={`${rowKey}-${key}`} className="breach-attribute-pill">
                                                                            <strong>{formatFieldLabel(key)}:</strong> {String(value)}
                                                                        </span>
                                                                    )) : (
                                                                        <span className="breach-attribute-empty">No previewable attributes</span>
                                                                    )}
                                                                </div>
                                                            </td>
                                                            <td>
                                                                <div className="breach-row-actions">
                                                                    <button
                                                                        type="button"
                                                                        className="breach-action-btn"
                                                                        title="Show Connection Graph"
                                                                        onClick={() => loadConnections(record)}
                                                                    >
                                                                        <Share2 size={16} />
                                                                        <span>Graph</span>
                                                                    </button>
                                                                    {getOsintUsername(record) && (
                                                                        <button
                                                                            type="button"
                                                                            className="breach-action-btn breach-osint-btn"
                                                                            title={`OSINT lookup: ${getOsintUsername(record)}`}
                                                                            onClick={() => handleOsintLookup(record)}
                                                                        >
                                                                            <UserSearch size={16} />
                                                                            <span>OSINT</span>
                                                                        </button>
                                                                    )}
                                                                    <button
                                                                        type="button"
                                                                        className="breach-expand-btn"
                                                                        onClick={() => toggleExpanded(rowKey)}
                                                                    >
                                                                        {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                                                                        <span>{expanded ? 'Hide' : 'Inspect'}</span>
                                                                    </button>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                        {expanded && (
                                                            <tr className="breach-expanded-row">
                                                                <td colSpan="4">
                                                                    <div className="breach-json-panel">
                                                                        <div className="breach-json-header">
                                                                            Full Row Attributes
                                                                        </div>
                                                                        <pre>{JSON.stringify(record.data || {}, null, 2)}</pre>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                        )}
                                                    </React.Fragment>
                                                );
                                            })}
                                        </tbody>
                                    </table>
                                </div>

                                <div className="breach-pagination">
                                    <button
                                        type="button"
                                        className="breach-secondary-btn"
                                        disabled={(results.offset || 0) === 0 || loading}
                                        onClick={() => runSearch(Math.max(0, (results.offset || 0) - (results.limit || PAGE_SIZE)))}
                                    >
                                        Previous
                                    </button>

                                    <div className="breach-page-pill">
                                        Page {currentPage} of {totalPages}
                                    </div>

                                    <button
                                        type="button"
                                        className="breach-secondary-btn"
                                        disabled={loading || ((results.offset || 0) + (results.limit || PAGE_SIZE)) >= (results.count || 0)}
                                        onClick={() => runSearch((results.offset || 0) + (results.limit || PAGE_SIZE))}
                                    >
                                        Next
                                    </button>
                                </div>
                            </>
                        )}
                    </div>
                </section>
            )}

            {!results && !loading && (
                <div className="card breach-placeholder">
                    <Database size={46} />
                    <h3>Awaiting Query Execution</h3>
                    <p>
                        Build one or more exact-match filters above, then query the live breach warehouse
                        through the current Argus `/breach` module.
                    </p>
                </div>
            )}

            {showGraph && (
                <div className={`breach-graph-overlay ${graphMinimized ? 'minimized' : ''} fade-in`}>
                    <div className="breach-graph-header">
                        <div className="breach-graph-title">
                            <Share2 size={18} />
                            <h3>Network Explorer: {graphData?.seed_input || 'Discovery'}</h3>
                            {graphData && <span className="breach-graph-badge">{graphData.nodes.length} nodes</span>}
                        </div>
                        <div className="breach-graph-controls">
                            <button className="graph-control-btn" onClick={() => setGraphMinimized(!graphMinimized)} title={graphMinimized ? 'Restore' : 'Minimize'}>
                                {graphMinimized ? <Maximize2 size={18} /> : <Minimize2 size={18} />}
                            </button>
                            <button className="graph-control-btn close" onClick={() => setShowGraph(false)} title="Close Map">
                                <X size={18} />
                            </button>
                        </div>
                    </div>

                    <div className="breach-graph-body">
                        {graphLoading ? (
                            <div className="breach-graph-loading">
                                <RefreshCw className="spin-slow" size={32} />
                                <p>Mapping database relationships via shared PII...</p>
                            </div>
                        ) : graphError ? (
                            <div className="breach-graph-error">
                                <AlertTriangle size={32} />
                                <p>{graphError}</p>
                            </div>
                        ) : graphData ? (
                            <div className="breach-graph-container">
                                <ConnectionGraph
                                    graphData={graphData}
                                    height={graphMinimized ? 300 : 650}
                                    onRecenter={handleRecenter}
                                />
                            </div>
                        ) : null}
                    </div>
                </div>
            )}
        </div>
    );
};

export default BreachData;
