import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useSearchContext } from '../../shared/context/SearchContext';
import {
    startInvestigationJob,
    getInvestigationJobStatus,
    getInvestigationJobResult,
    cancelInvestigationJob,
    pauseInvestigationJob,
    resumeInvestigationJob,
    exportInvestigation,
} from './api';
import {
    Search, User, Mail, Phone, MapPin, Briefcase, Globe, Shield, ChevronDown, ChevronUp,
    ExternalLink, Copy, Download, X, Check, AlertTriangle, Clock, Eye, EyeOff,
    FileText, Building, GraduationCap, Hash, Link, Camera, Crosshair, Play,
    BarChart3, Filter, Trash2, MessageSquare, RefreshCw, Award, Zap, Users,
    Pause, SkipForward, Layers, List
} from 'lucide-react';
import './OSINTTools.css';

/* ─── Constants ─── */
const CONFIDENCE_COLORS = {
    'Confirmed': '#00e676', 'High Confidence': '#00c853',
    'Medium Confidence': '#ffc107', 'Ambiguous': '#fb923c', 'Unverified': '#ff9800', 'Not Found': '#f44336', 'Blocked': '#6366f1',
};
const CONFIDENCE_BG = {
    'Confirmed': 'rgba(0,230,118,0.12)', 'High Confidence': 'rgba(0,200,83,0.12)',
    'Medium Confidence': 'rgba(255,193,7,0.12)', 'Ambiguous': 'rgba(251,146,60,0.12)',
    'Unverified': 'rgba(255,152,0,0.12)',
    'Not Found': 'rgba(244,67,54,0.08)', 'Blocked': 'rgba(99,102,241,0.12)',
};
const TIER_LABELS = { 1: 'Indian Priority', 2: 'Global Mainstream', 3: 'Niche & Regional' };
const CATEGORY_ICONS = {
    dev: '{ }', social: '@', media: '▶', creative: '✦', blog: '✎',
    gaming: '◆', business: '▣', india: '◉', other: '○',
};
const JOB_POLL_INTERVAL_MS = 1200;

const EMPTY_PROFILE = {
    first_name: '', middle_name: '', last_name: '',
    aliases: '', usernames: '', gender: '',
    date_of_birth: '', age_range: '', nationality: '', languages: '',
    emails: '', phones: '', whatsapp_number: '',
    city: '', state: '', country: '',
    workplace: '', educational_institution: '',
    occupation: '', industry: '', companies: '', registration_numbers: '',
    known_profile_urls: '', profile_picture_url: '', domains: '', known_ip: '',
    case_id: '', investigator_name: '', investigation_purpose: '', classification_level: 'Internal',
};

/* ─── Disambiguation tier config ─── */
const DISAMBIG_CONFIG = {
    DEFINITIVE: { label: 'Definitive Match',   color: '#00e676', bg: 'rgba(0,230,118,0.12)', desc: 'Email or phone confirmed' },
    HIGH:       { label: 'High Confidence',    color: '#00c853', bg: 'rgba(0,200,83,0.10)',  desc: '3+ corroborating signals' },
    POSSIBLE:   { label: 'Possible Match',     color: '#ffc107', bg: 'rgba(255,193,7,0.10)', desc: '1–2 bio signals matched' },
    UNLIKELY:   { label: 'Low Confidence',     color: '#ff7043', bg: 'rgba(255,112,67,0.10)',desc: 'Name only — may be different person' },
};
const EVIDENCE_TIER_COLOR = { definitive: '#00e676', strong: '#66bb6a', moderate: '#ffc107', weak: '#9e9e9e' };

/* ─── Result Card Component ─── */
function ResultCard({ result, expandedCards, setExpandedCards, discardedResults, toggleDiscard,
    investigatorNotes, setInvestigatorNotes, copiedUrl, setCopiedUrl,
    confirmedAccounts, excludedAccounts, toggleConfirm, toggleExclude }) {
    const isExpanded = expandedCards.has(result.url);
    const isDiscarded = discardedResults.has(result.url);
    const isConfirmed = confirmedAccounts?.has(result.url);
    const isExcluded = excludedAccounts?.has(result.url);
    const note = investigatorNotes[result.url] || '';
    const confColor = CONFIDENCE_COLORS[result.confidence_level] || '#888';
    const confBg = CONFIDENCE_BG[result.confidence_level] || 'transparent';
    const disambig = DISAMBIG_CONFIG[result.disambiguation_tier] || null;
    const evidenceChain = result.evidence_chain || [];

    let cardClass = `ov2-result-card`;
    if (isDiscarded) cardClass += ' discarded';
    if (isConfirmed) cardClass += ' confirmed-subject';
    if (isExcluded) cardClass += ' excluded-subject';

    return (
        <div className={cardClass} style={{ borderLeftColor: isConfirmed ? '#00e676' : isExcluded ? '#f44336' : confColor }}>
            <div className="ov2-result-header">
                <div className="ov2-result-site">
                    <span className="ov2-cat-icon" title={result.category}>{CATEGORY_ICONS[result.category] || '○'}</span>
                    <div>
                        <strong>{result.site_name}</strong>
                        <span className="ov2-tier-badge">T{result.tier}</span>
                    </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    {disambig && (
                        <span className="ov2-disambig-badge" style={{ background: disambig.bg, color: disambig.color }}
                            title={disambig.desc}>
                            {disambig.label}
                        </span>
                    )}
                    <div className="ov2-result-conf" style={{ background: confBg, color: confColor }}>
                        {result.confidence_score}% &middot; {result.confidence_level}
                    </div>
                </div>
            </div>

            {/* Investigator Verdict */}
            <div className="ov2-verdict-row">
                <button
                    className={`ov2-verdict-btn confirm ${isConfirmed ? 'active' : ''}`}
                    onClick={() => toggleConfirm?.(result.url)}
                    title="Mark as confirmed subject">
                    ✓ This IS the subject
                </button>
                <button
                    className={`ov2-verdict-btn exclude ${isExcluded ? 'active' : ''}`}
                    onClick={() => toggleExclude?.(result.url)}
                    title="Mark as different person">
                    ✗ Different person
                </button>
            </div>

            <div className="ov2-result-url">
                <a href={result.url} target="_blank" rel="noopener noreferrer">{result.url} <ExternalLink size={12} /></a>
                <button className="ov2-icon-btn" title="Copy URL" onClick={() => {
                    navigator.clipboard.writeText(result.url);
                    setCopiedUrl(result.url);
                    setTimeout(() => setCopiedUrl(''), 1500);
                }}>
                    {copiedUrl === result.url ? <Check size={14} /> : <Copy size={14} />}
                </button>
            </div>

            <div className="ov2-result-meta-row">
                <span>Mode: {result.search_mode}</span>
                <span>Pattern: {result.permutation_pattern}</span>
                <span>User: <strong>{result.username_searched}</strong></span>
                <span>{result.response_time_ms}ms</span>
            </div>

            {/* Evidence Chain — why this account matches */}
            {evidenceChain.length > 0 && (
                <div className="ov2-evidence-chain">
                    <div className="ov2-ec-label">Why it matched:</div>
                    <div className="ov2-ec-items">
                        {evidenceChain.map((ev, i) => (
                            <span key={i} className="ov2-ec-item"
                                style={{ borderColor: `${EVIDENCE_TIER_COLOR[ev.tier]}44`, color: EVIDENCE_TIER_COLOR[ev.tier] }}
                                title={ev.detail}>
                                {ev.tier === 'definitive' ? '🔒' : ev.tier === 'strong' ? '✅' : ev.tier === 'moderate' ? '🔍' : '〰️'}
                                {' '}{ev.label}: <strong>{ev.detail.length > 30 ? ev.detail.slice(0, 30) + '…' : ev.detail}</strong>
                            </span>
                        ))}
                    </div>
                </div>
            )}
            {evidenceChain.length === 0 && (result.status === 'found' || result.status === 'unverified') && (
                <div className="ov2-no-evidence">
                    ⚠️ No bio signals matched — this may be a different person with the same username.
                </div>
            )}

            {/* Corroboration Flags */}
            <div className="ov2-flags">
                {result.name_match && <span className="ov2-flag green">Name Match</span>}
                {result.dob_match && <span className="ov2-flag green">DOB Match</span>}
                {result.secondary_confirmation_passed === true && <span className="ov2-flag green">2nd Confirmed</span>}
                {result.secondary_confirmation && result.secondary_confirmation_passed === false && (
                    <span className="ov2-flag yellow">2nd Inconclusive</span>
                )}
                {result.waf_detected && <span className="ov2-flag red">WAF Detected</span>}
                {result.rate_limited && <span className="ov2-flag red">Rate Limited</span>}
            </div>

            {/* Metadata Preview */}
            {(result.display_name || result.bio || result.location) && (
                <div className="ov2-result-profile">
                    {result.avatar_url && (
                        <img src={result.avatar_url} alt="" className="ov2-avatar"
                            onError={e => { e.target.style.display = 'none'; }} />
                    )}
                    <div>
                        {result.display_name && <div className="ov2-display-name">{result.display_name}</div>}
                        {result.location && <div className="ov2-location"><MapPin size={12} /> {result.location}</div>}
                        {result.bio && <div className="ov2-bio">{result.bio}</div>}
                    </div>
                </div>
            )}

            {/* Actions */}
            <div className="ov2-result-actions">
                <button className="ov2-text-btn" onClick={() => {
                    setExpandedCards(prev => {
                        const next = new Set(prev);
                        next.has(result.url) ? next.delete(result.url) : next.add(result.url);
                        return next;
                    });
                }}>
                    {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    {isExpanded ? 'Hide Signals' : 'Show Signals'}
                </button>
                <button className={`ov2-text-btn ${isDiscarded ? 'undo' : 'discard'}`}
                    onClick={() => toggleDiscard(result.url)}>
                    {isDiscarded ? <RefreshCw size={14} /> : <Trash2 size={14} />}
                    {isDiscarded ? 'Restore' : 'Discard'}
                </button>
            </div>

            {/* Expanded Signals */}
            {isExpanded && (
                <div className="ov2-signals">
                    <div className="ov2-signals-title">Verification Signals</div>
                    {(result.signals || []).map((sig, i) => (
                        <div key={i} className={`ov2-signal ${sig.passed ? 'passed' : 'failed'}`}>
                            <span className="ov2-signal-icon">{sig.passed ? '+' : '-'}</span>
                            <span className="ov2-signal-name">{sig.name}</span>
                            <span className="ov2-signal-detail">{sig.detail}</span>
                            {sig.weight != null && (
                                <span className="ov2-signal-weight">({sig.weight > 0 ? '+' : ''}{sig.weight})</span>
                            )}
                        </div>
                    ))}
                    <div className="ov2-note-field">
                        <MessageSquare size={14} />
                        <input type="text" placeholder="Add investigator note..."
                            value={note}
                            onChange={e => setInvestigatorNotes(prev => ({ ...prev, [result.url]: e.target.value }))}
                        />
                    </div>
                </div>
            )}
        </div>
    );
}

/* ═══════════════════════════════════════════════════════════════════
   Main OSINTTools Page Component
   ═══════════════════════════════════════════════════════════════════ */
export default function OSINTTools() {
    const {
        investigationProfile, setInvestigationProfile,
        investigationResult, setInvestigationResult,
        investigationLoading, setInvestigationLoading,
        investigationProgress, setInvestigationProgress,
        discardedResults, setDiscardedResults,
        investigatorNotes, setInvestigatorNotes,
        saveSession, restoreSession,
        consumePendingOsint,
    } = useSearchContext();

    const [profile, setProfile] = useState({ ...EMPTY_PROFILE });
    const [expandedSections, setExpandedSections] = useState({ identity: true });
    const [selectedModes, setSelectedModes] = useState([]);
    const [selectedTiers, setSelectedTiers] = useState([1, 2, 3]);
    const [enableSerpDiscovery, setEnableSerpDiscovery] = useState(true);
    const [showNotFound, setShowNotFound] = useState(false);
    const [filterTier, setFilterTier] = useState(0);
    const [filterCategory, setFilterCategory] = useState('all');
    const [filterConfidence, setFilterConfidence] = useState('all');
    const [activeTab, setActiveTab] = useState('results');
    const [elapsedTime, setElapsedTime] = useState(0);
    const [expandedCards, setExpandedCards] = useState(new Set());
    const [copiedUrl, setCopiedUrl] = useState('');
    const [activeJobId, setActiveJobId] = useState('');
    const [liveLogs, setLiveLogs] = useState([]);
    const [isPaused, setIsPaused] = useState(false);
    const [confirmedAccounts, setConfirmedAccounts] = useState(new Set()); // URLs confirmed as subject
    const [excludedAccounts, setExcludedAccounts] = useState(new Set());   // URLs confirmed as NOT subject
    const [filterDisambig, setFilterDisambig] = useState('all');            // DEFINITIVE/HIGH/POSSIBLE/UNLIKELY/all
    const abortRef = useRef(null);
    const jobIdRef = useRef('');
    const timerRef = useRef(null);
    const liveFoundRef = useRef([]);   // always-current allLiveFound for report generation
    const tierLogRef1 = useRef(null);
    const tierLogRef2 = useRef(null);
    const tierLogRef3 = useRef(null);
    const tierLogRefs = useMemo(() => ({ 1: tierLogRef1, 2: tierLogRef2, 3: tierLogRef3 }), []);

    /* Restore session on mount */
    useEffect(() => { restoreSession(); }, [restoreSession]);
    useEffect(() => {
        if (investigationProfile) {
            setProfile(prev => ({ ...prev, ...investigationProfile }));
        }
    }, [investigationProfile]);

    /* Handle pending OSINT from breach module */
    useEffect(() => {
        const pending = consumePendingOsint();
        if (pending) setProfile(prev => ({ ...prev, usernames: pending }));
    }, [consumePendingOsint]);

    /* Auto-save on result changes */
    useEffect(() => {
        if (investigationResult) saveSession();
    }, [investigationResult, discardedResults, investigatorNotes, saveSession]);

    /* Timer */
    useEffect(() => {
        if (investigationLoading) {
            const start = Date.now();
            timerRef.current = setInterval(() => setElapsedTime(Date.now() - start), 100);
            return () => clearInterval(timerRef.current);
        }
        clearInterval(timerRef.current);
    }, [investigationLoading]);

    useEffect(() => () => {
        if (abortRef.current) abortRef.current.abort();
        clearInterval(timerRef.current);
    }, []);

    /* Auto-scroll tier log panels to bottom */
    useEffect(() => {
        [1, 2, 3].forEach(t => {
            const el = tierLogRefs[t].current;
            if (el) el.scrollTop = el.scrollHeight;
        });
    }, [liveLogs, tierLogRefs]);

    const updateProfile = useCallback((field, value) => {
        setProfile(prev => ({ ...prev, [field]: value }));
    }, []);

    const toggleSection = useCallback((key) => {
        setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
    }, []);

    const hasSearchableFields = useMemo(() => !!(
        profile.usernames.trim() ||
        (profile.first_name.trim() && profile.last_name.trim()) ||
        profile.emails.trim() ||
        profile.phones.trim()
    ), [profile.usernames, profile.first_name, profile.last_name, profile.emails, profile.phones]);

    /* Profile disambiguation strength — computed in-browser from current profile */
    const profileStrength = useMemo(() => {
        const has = (field) => {
            const v = profile[field];
            return v && String(v).trim().length > 0;
        };
        let score = 0;
        const anchors = [];
        const items = [
            { key: 'emails',     name: 'Email',        power: 'definitive', icon: '📧', pts: 35 },
            { key: 'phones',     name: 'Phone',        power: 'definitive', icon: '📱', pts: 30 },
            { key: 'profile_picture_url', name: 'Profile Photo', power: 'strong', icon: '🖼️', pts: 15 },
            { key: 'usernames',  name: 'Username',     power: 'strong',    icon: '👤', pts: 20 },
            { key: 'workplace',  name: 'Workplace',    power: 'strong',    icon: '🏢', pts: 15 },
            { key: 'educational_institution', name: 'Education', power: 'moderate', icon: '🎓', pts: 10 },
            { key: 'city',       name: 'City',         power: 'moderate',  icon: '📍', pts: 10 },
        ];
        const fullName = has('first_name') && has('last_name');
        items.forEach(item => {
            const present = has(item.key);
            if (present) score += item.pts;
            anchors.push({ ...item, present });
        });
        if (fullName && !items.some(i => i.key === 'first_name')) score += 5;
        score = Math.min(score, 100);
        const level = score >= 60 ? 'STRONG' : score >= 25 ? 'MODERATE' : 'WEAK';
        let advice = '';
        if (!has('emails') && !has('phones')) {
            advice = 'Add email or phone number — these are the strongest disambiguation anchors.';
        } else if (!has('emails')) {
            advice = 'Adding a known email address would greatly improve accuracy.';
        } else if (!has('phones')) {
            advice = 'Adding a phone number would strengthen confirmation.';
        } else if (!has('usernames') && !has('workplace')) {
            advice = 'Add a known username or workplace to filter out same-name accounts.';
        } else if (!has('city')) {
            advice = 'Adding the subject\'s city helps filter results from different regions.';
        }
        return { score, level, anchors, advice };
    }, [profile]);

    const waitForNextPoll = useCallback((signal) => new Promise((resolve, reject) => {
        const timeoutId = window.setTimeout(resolve, JOB_POLL_INTERVAL_MS);
        const abortHandler = () => {
            window.clearTimeout(timeoutId);
            reject(new DOMException('Aborted', 'AbortError'));
        };
        if (signal) {
            signal.addEventListener('abort', abortHandler, { once: true });
            window.setTimeout(() => signal.removeEventListener('abort', abortHandler), JOB_POLL_INTERVAL_MS + 50);
        }
    }), []);

    const pollInvestigationJob = useCallback(async (jobId, signal) => {
        while (!signal?.aborted) {
            const statusResponse = await getInvestigationJobStatus(jobId, signal);
            const statusData = statusResponse?.data || {};

            setInvestigationProgress({
                jobId,
                status: statusData.status,
                phase: statusData.phase,
                ...(statusData.progress || {}),
            });
            setLiveLogs(statusData.logs || []);

            if (statusData.status === 'completed') {
                setIsPaused(false);
                return await getInvestigationJobResult(jobId, signal);
            }
            if (statusData.status === 'paused') {
                setIsPaused(true);
            } else if (statusData.status === 'running') {
                setIsPaused(false);
            }
            if (statusData.status === 'failed') {
                throw new Error(statusData.error || 'Investigation failed');
            }
            if (statusData.status === 'cancelled') {
                return {
                    success: true,
                    data: {
                        job_id: jobId,
                        status: 'cancelled',
                        phase: statusData.phase,
                        error: statusData.error || 'Investigation cancelled',
                        progress: statusData.progress || {},
                    },
                };
            }

            await waitForNextPoll(signal);
        }

        throw new DOMException('Aborted', 'AbortError');
    }, [setInvestigationProgress, waitForNextPoll]);

    /* ─── Run Investigation ─── */
    const handleInvestigate = useCallback(async () => {
        if (!hasSearchableFields || investigationLoading) return;
        setInvestigationLoading(true);
        setInvestigationResult(null);
        setInvestigationProfile(profile);
        setInvestigationProgress({ phase: 'starting', status: 'queued' });
        setElapsedTime(0);
        setDiscardedResults(new Set());
        setInvestigatorNotes({});
        setLiveLogs([]);
        setActiveJobId('');
        setIsPaused(false);
        jobIdRef.current = '';

        const controller = new AbortController();
        abortRef.current = controller;

        try {
            const modes = selectedModes.length > 0 ? selectedModes : null;
            const tiers = selectedTiers.length > 0 ? selectedTiers : null;
            const startResponse = await startInvestigationJob(profile, modes, tiers, { enableSerpDiscovery }, controller.signal);
            const jobId = startResponse?.data?.job_id;
            if (!jobId) {
                throw new Error('Investigation job did not return a job id');
            }

            jobIdRef.current = jobId;
            setActiveJobId(jobId);
            setInvestigationProgress(prev => ({
                ...(prev || {}),
                jobId,
                status: startResponse?.data?.status || 'queued',
                phase: startResponse?.data?.phase || 'queued',
            }));

            const resultResponse = await pollInvestigationJob(jobId, controller.signal);
            const resultData = resultResponse?.data || {};

            if (resultData.status === 'cancelled') {
                setInvestigationResult({ cancelled: true, error: resultData.error || 'Investigation cancelled' });
            } else {
                const normalizedResult = resultData?.result?.data || resultData?.result || resultData;
                setInvestigationResult(normalizedResult);
            }
        } catch (err) {
            if (err.name !== 'AbortError') {
                console.error('Investigation failed:', err);
                setInvestigationResult({ error: err.message });
            }
        } finally {
            setInvestigationLoading(false);
        }
    }, [
        profile,
        selectedModes,
        selectedTiers,
        enableSerpDiscovery,
        hasSearchableFields,
        investigationLoading,
        pollInvestigationJob,
        setDiscardedResults,
        setInvestigationLoading,
        setInvestigationProfile,
        setInvestigationProgress,
        setInvestigationResult,
        setInvestigatorNotes,
    ]);

    const handleCancel = useCallback(async () => {
        const jobId = jobIdRef.current;
        // Abort the poll loop immediately regardless
        if (abortRef.current) abortRef.current.abort();

        if (!jobId) {
            setInvestigationLoading(false);
            return;
        }

        setInvestigationProgress(prev => ({
            ...(prev || {}),
            jobId,
            status: 'cancelling',
            phase: 'cancelling',
        }));

        try {
            await cancelInvestigationJob(jobId);
        } catch (err) {
            console.error('Investigation cancel request failed:', err);
        } finally {
            setInvestigationLoading(false);
        }
    }, [setInvestigationLoading, setInvestigationProgress]);

    const handlePause = useCallback(async () => {
        const jobId = jobIdRef.current;
        if (!jobId) return;
        try {
            await pauseInvestigationJob(jobId);
            setIsPaused(true);
        } catch (err) {
            console.error('Pause failed:', err);
        }
    }, []);

    const handleResume = useCallback(async () => {
        const jobId = jobIdRef.current;
        if (!jobId) return;
        try {
            await resumeInvestigationJob(jobId);
            setIsPaused(false);
        } catch (err) {
            console.error('Resume failed:', err);
        }
    }, []);

    const handleReset = useCallback(() => {
        setProfile({ ...EMPTY_PROFILE });
        setInvestigationProfile(null);
        setInvestigationResult(null);
        setInvestigationProgress(null);
        setDiscardedResults(new Set());
        setInvestigatorNotes({});
        setSelectedModes([]);
        setSelectedTiers([1, 2, 3]);
        setLiveLogs([]);
        setActiveJobId('');
        setConfirmedAccounts(new Set());
        setExcludedAccounts(new Set());
        setFilterDisambig('all');
        jobIdRef.current = '';
        sessionStorage.removeItem('osint_investigation_session');
    }, [
        setDiscardedResults,
        setInvestigationProfile,
        setInvestigationProgress,
        setInvestigationResult,
        setInvestigatorNotes,
    ]);

    /* ─── Download Reports ─── */
    const generateReportHTML = useCallback((type) => {
        // Use full results if available, otherwise fall back to live found entries
        const data = investigationResult || {};
        const subject = data.subject_profile || {};
        const subjectName = [subject.first_name, subject.middle_name, subject.last_name].filter(Boolean).join(' ') || 'Unknown Subject';
        // Use full results array if available; fall back to live found log entries during/after scan
        const fullFound = (data.results || []).filter(r => r.status === 'found' || r.status === 'unverified');
        const foundResults = fullFound.length > 0 ? fullFound : liveFoundRef.current.map(l => ({
            site_name: l.site_name, url: l.url, tier: l.tier, confidence_score: l.confidence_score,
            confidence_level: l.confidence_level, username_searched: l.username, display_name: l.display_name,
            location: l.location, matched_attributes: l.matched_attributes || [],
        }));
        if (foundResults.length === 0) return null;
        const date = new Date().toLocaleString('en-IN', { dateStyle: 'long', timeStyle: 'short' });

        const confColor = { 'Confirmed': '#00e676', 'High Confidence': '#00c853', 'Medium Confidence': '#ffc107', 'Unverified': '#ff9800' };
        const tierLabel = { 1: 'India Priority', 2: 'Global Mainstream', 3: 'Niche & Regional' };

        const accountCard = (r) => `
            <div class="account-card" style="border-left:4px solid ${confColor[r.confidence_level] || '#555'}">
                <div class="account-header">
                    <span class="site-name">${r.site_name || ''}</span>
                    <span class="tier-tag">Tier ${r.tier} · ${tierLabel[r.tier] || ''}</span>
                    <span class="conf-badge" style="background:${confColor[r.confidence_level]}22;color:${confColor[r.confidence_level] || '#888'}">${r.confidence_score}% · ${r.confidence_level}</span>
                </div>
                <a class="account-url" href="${r.url}" target="_blank">${r.url}</a>
                <div class="account-meta">
                    ${r.username_searched ? `<span>@${r.username_searched}</span>` : ''}
                    ${r.display_name ? `<span>Name: ${r.display_name}</span>` : ''}
                    ${r.location ? `<span>📍 ${r.location}</span>` : ''}
                    ${r.bio ? `<span class="bio">${r.bio.slice(0, 120)}${r.bio.length > 120 ? '…' : ''}</span>` : ''}
                </div>
                ${(r.matched_attributes || []).length > 0 ? `
                <div class="match-attrs">${r.matched_attributes.slice(0, 4).map(a => `<span class="attr-chip">${a.replace(':', ': ')}</span>`).join('')}</div>` : ''}
            </div>`;

        let bodyContent = '';
        if (type === 'grouped' && (data.identity_clusters || []).length > 0) {
            bodyContent = `<h2 class="section-title">Identity Clusters</h2>`;
            data.identity_clusters.forEach((cluster, ci) => {
                bodyContent += `
                <div class="cluster-block">
                    <div class="cluster-header">
                        <span class="cluster-num">Cluster ${ci + 1}</span>
                        ${cluster.display_name ? `<span class="cluster-name">${cluster.display_name}</span>` : ''}
                        <span class="cluster-conf">${cluster.cluster_confidence}% match · ${cluster.account_count} accounts</span>
                        ${(cluster.locations || []).length ? `<span class="cluster-loc">📍 ${cluster.locations.join(', ')}</span>` : ''}
                    </div>
                    ${(cluster.bio_snippets || []).length ? `<p class="cluster-bio">${cluster.bio_snippets[0]}</p>` : ''}
                    ${cluster.accounts.map(a => accountCard(a)).join('')}
                </div>`;
            });
            // Unclustered accounts
            const clusteredUrls = new Set((data.identity_clusters || []).flatMap(c => (c.accounts || []).map(a => a.url)));
            const unclustered = foundResults.filter(r => !clusteredUrls.has(r.url));
            if (unclustered.length > 0) {
                bodyContent += `<h2 class="section-title" style="margin-top:32px">Other Found Accounts</h2>`;
                bodyContent += unclustered.map(accountCard).join('');
            }
        } else {
            bodyContent = `<h2 class="section-title">All Found Accounts (${foundResults.length})</h2>`;
            const sorted = [...foundResults].sort((a, b) => b.confidence_score - a.confidence_score);
            bodyContent += sorted.map(accountCard).join('');
        }

        const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Argus OSINT Report — ${subjectName}</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background:#0a0c14; color:#e0e6ef; padding:0; }
  .cover { background:linear-gradient(135deg,#0d1117 0%,#1a0533 50%,#0d1117 100%); padding:48px 40px 40px; border-bottom:2px solid #7c3aed; }
  .cover-logo { font-size:28px; font-weight:800; color:#a78bfa; letter-spacing:2px; margin-bottom:8px; }
  .cover-logo span { color:#fff; }
  .cover-subtitle { font-size:13px; color:#6b7280; margin-bottom:32px; }
  .cover-subject { font-size:26px; font-weight:700; color:#fff; margin-bottom:6px; }
  .cover-meta { display:flex; flex-wrap:wrap; gap:20px; margin-top:20px; }
  .meta-item { font-size:12px; color:#9ca3af; } .meta-item strong { color:#d1d5db; }
  .stats-bar { background:#111827; border-bottom:1px solid #1f2937; padding:16px 40px; display:flex; gap:32px; flex-wrap:wrap; }
  .stat { text-align:center; }
  .stat-val { font-size:24px; font-weight:700; }
  .stat-val.green { color:#00e676; } .stat-val.yellow { color:#ffc107; } .stat-val.blue { color:#60a5fa; } .stat-val.dim { color:#6b7280; }
  .stat-label { font-size:11px; color:#6b7280; margin-top:2px; }
  .content { padding:32px 40px; max-width:1100px; }
  .section-title { font-size:16px; font-weight:700; color:#a78bfa; margin-bottom:16px; text-transform:uppercase; letter-spacing:1px; padding-bottom:8px; border-bottom:1px solid #1f2937; }
  .cluster-block { background:#111827; border:1px solid #1f2937; border-radius:10px; padding:20px; margin-bottom:20px; }
  .cluster-header { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:12px; padding-bottom:12px; border-bottom:1px solid #1f2937; }
  .cluster-num { background:#7c3aed22; color:#a78bfa; padding:3px 10px; border-radius:4px; font-size:12px; font-weight:700; }
  .cluster-name { font-size:15px; font-weight:600; color:#fff; }
  .cluster-conf { font-size:12px; color:#9ca3af; margin-left:auto; }
  .cluster-loc { font-size:12px; color:#60a5fa; }
  .cluster-bio { font-size:12px; color:#6b7280; font-style:italic; margin-bottom:12px; }
  .account-card { background:#0d1117; border-radius:7px; border:1px solid #1f2937; padding:14px 16px; margin-bottom:10px; }
  .account-header { display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:8px; }
  .site-name { font-size:14px; font-weight:700; color:#e5e7eb; }
  .tier-tag { font-size:10px; color:#6b7280; background:#1f2937; padding:2px 7px; border-radius:3px; }
  .conf-badge { font-size:11px; font-weight:600; padding:3px 10px; border-radius:4px; margin-left:auto; }
  .account-url { display:block; font-size:12px; color:#60a5fa; text-decoration:none; margin-bottom:8px; word-break:break-all; }
  .account-url:hover { text-decoration:underline; }
  .account-meta { display:flex; flex-wrap:wrap; gap:10px; font-size:11px; color:#9ca3af; margin-bottom:6px; }
  .bio { font-style:italic; color:#6b7280; }
  .match-attrs { display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; }
  .attr-chip { font-size:10px; background:#7c3aed22; color:#a78bfa; border:1px solid #7c3aed44; padding:2px 8px; border-radius:3px; text-transform:capitalize; }
  .footer { text-align:center; padding:24px; color:#374151; font-size:11px; border-top:1px solid #1f2937; margin-top:32px; }
  @media print { body { background:#fff; color:#111; } .cover { background:#f3f4f6; border-color:#7c3aed; } .account-card { background:#f9fafb; } .cluster-block { background:#f3f4f6; } }
</style>
</head>
<body>
<div class="cover">
  <div class="cover-logo">ARGUS <span>OSINT</span></div>
  <div class="cover-subtitle">Investigation Intelligence Platform · ${type === 'grouped' ? 'Identity Cluster Report' : 'Full Accounts Report'}</div>
  <div class="cover-subject">${subjectName}</div>
  ${subject.city || subject.workplace || subject.occupation ? `<div style="color:#9ca3af;font-size:13px;margin-top:4px">${[subject.occupation, subject.workplace, subject.city].filter(Boolean).join(' · ')}</div>` : ''}
  <div class="cover-meta">
    ${subject.case_id ? `<div class="meta-item"><strong>Case ID:</strong> ${subject.case_id}</div>` : ''}
    ${subject.investigator_name ? `<div class="meta-item"><strong>Investigator:</strong> ${subject.investigator_name}</div>` : ''}
    <div class="meta-item"><strong>Generated:</strong> ${date}</div>
    <div class="meta-item"><strong>Investigation ID:</strong> ${data.investigation_id || 'N/A'}</div>
    <div class="meta-item"><strong>Classification:</strong> ${subject.classification_level || 'Internal'}</div>
  </div>
</div>
<div class="stats-bar">
  <div class="stat"><div class="stat-val green">${data.actionable_findings || 0}</div><div class="stat-label">Actionable</div></div>
  <div class="stat"><div class="stat-val yellow">${data.manual_review_count || 0}</div><div class="stat-label">Review Required</div></div>
  <div class="stat"><div class="stat-val blue">${data.total_sites_checked || 0}</div><div class="stat-label">Sites Checked</div></div>
  <div class="stat"><div class="stat-val" style="color:#a78bfa">${(data.identity_clusters || []).length}</div><div class="stat-label">Identity Clusters</div></div>
  <div class="stat"><div class="stat-val dim">${((data.elapsed_ms || 0) / 1000).toFixed(1)}s</div><div class="stat-label">Elapsed</div></div>
</div>
<div class="content">${bodyContent}</div>
<div class="footer">Generated by Argus OSINT Intelligence Platform · ${date} · Confidential — Authorised Use Only</div>
</body></html>`;
        return html;
    }, [investigationResult]);

    const handleDownloadReport = useCallback((type) => {
        const html = generateReportHTML(type);
        if (!html) return;
        const subject = investigationResult?.subject_profile || {};
        const subjectName = [subject.first_name, subject.last_name].filter(Boolean).join('_') || 'subject';
        const caseId = subject.case_id ? `_${subject.case_id}` : '';
        const ts = new Date().toISOString().slice(0, 10);
        const filename = `argus_osint_${type}_${subjectName}${caseId}_${ts}.html`;
        const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename; a.click();
        URL.revokeObjectURL(url);
    }, [generateReportHTML, investigationResult]);

    /* ─── Export ─── */
    const handleExport = useCallback(async (format) => {
        if (!investigationResult) return;
        try {
            if (format === 'csv') {
                const blob = await exportInvestigation(investigationResult, 'csv');
                downloadBlob(blob, `investigation_${investigationResult.investigation_id || 'report'}.csv`);
            } else if (format === 'json') {
                const blob = new Blob([JSON.stringify(investigationResult, null, 2)], { type: 'application/json' });
                downloadBlob(blob, `investigation_${investigationResult.investigation_id || 'report'}.json`);
            } else if (format === 'pdf') {
                const res = await exportInvestigation(investigationResult, 'pdf');
                const text = res?.data?.report_text || '';
                const blob = new Blob([text], { type: 'text/plain' });
                downloadBlob(blob, `investigation_${investigationResult.investigation_id || 'report'}.txt`);
            }
        } catch (err) { console.error('Export failed:', err); }
    }, [investigationResult]);

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename; a.click();
        URL.revokeObjectURL(url);
    }

    /* ─── Copy URLs ─── */
    const copyUrls = useCallback((level) => {
        if (!investigationResult?.results) return;
        const urls = investigationResult.results
            .filter(r => r.status === 'found' && !discardedResults.has(r.url))
            .filter(r => level === 'all' || r.confidence_level === level || r.tier === level)
            .map(r => r.url).join('\n');
        navigator.clipboard.writeText(urls);
        setCopiedUrl(level);
        setTimeout(() => setCopiedUrl(''), 2000);
    }, [investigationResult, discardedResults]);

    const toggleConfirm = useCallback((url) => {
        setConfirmedAccounts(prev => {
            const next = new Set(prev);
            if (next.has(url)) { next.delete(url); } else { next.add(url); setExcludedAccounts(ex => { const n = new Set(ex); n.delete(url); return n; }); }
            return next;
        });
    }, []);

    const toggleExclude = useCallback((url) => {
        setExcludedAccounts(prev => {
            const next = new Set(prev);
            if (next.has(url)) { next.delete(url); } else { next.add(url); setConfirmedAccounts(cf => { const n = new Set(cf); n.delete(url); return n; }); }
            return next;
        });
    }, []);

    const toggleDiscard = useCallback((url) => {
        setDiscardedResults(prev => {
            const next = new Set(prev);
            next.has(url) ? next.delete(url) : next.add(url);
            return next;
        });
    }, [setDiscardedResults]);

    /* ─── Filter results ─── */
    const filteredResults = useMemo(() => {
        if (!investigationResult?.results) return [];
        return investigationResult.results.filter(r => {
            if (!showNotFound && r.status === 'not_found') return false;
            if (r.status === 'not_found' && r.confidence_score === 0) return false;
            if (filterTier > 0 && r.tier !== filterTier) return false;
            if (filterCategory !== 'all' && r.category !== filterCategory) return false;
            if (filterConfidence !== 'all' && r.confidence_level !== filterConfidence) return false;
            if (discardedResults.has(r.url) && activeTab !== 'discarded') return false;
            if (filterDisambig !== 'all' && r.disambiguation_tier !== filterDisambig) return false;
            return true;
        }).sort((a, b) => {
            // Confirmed accounts always float to top
            const aC = confirmedAccounts.has(a.url) ? 1 : 0;
            const bC = confirmedAccounts.has(b.url) ? 1 : 0;
            if (bC !== aC) return bC - aC;
            // Excluded accounts sink to bottom
            const aE = excludedAccounts.has(a.url) ? 1 : 0;
            const bE = excludedAccounts.has(b.url) ? 1 : 0;
            if (aE !== bE) return aE - bE;
            return b.confidence_score - a.confidence_score;
        });
    }, [investigationResult, showNotFound, filterTier, filterCategory, filterConfidence, discardedResults, activeTab, filterDisambig, confirmedAccounts, excludedAccounts]);

    const discardedList = useMemo(() => {
        if (!investigationResult?.results) return [];
        return investigationResult.results.filter(r => discardedResults.has(r.url));
    }, [investigationResult, discardedResults]);

    /* ─── Review Queue: real leads needing human verdict ─── */
    const reviewQueue = useMemo(() => {
        if (!investigationResult?.results) return [];
        return investigationResult.results
            .filter(r => {
                if (r.status !== 'found') return false;
                if (discardedResults.has(r.url)) return false;
                if (confirmedAccounts.has(r.url) || excludedAccounts.has(r.url)) return false;
                return r.confidence_level === 'Medium Confidence' || r.confidence_level === 'Ambiguous';
            })
            .sort((a, b) => {
                const aSms = a.subject_match_score || 0;
                const bSms = b.subject_match_score || 0;
                if (bSms !== aSms) return bSms - aSms;
                return (b.confidence_score || 0) - (a.confidence_score || 0);
            });
    }, [investigationResult, discardedResults, confirmedAccounts, excludedAccounts]);

    /* ─── All found log entries — never truncated so findings never disappear ─── */
    const allLiveFound = useMemo(() => {
        const found = liveLogs.filter(l => l.level === 'found' && l.url);
        liveFoundRef.current = found;
        return found;
    }, [liveLogs]);

    /* ─── Live Identity Clustering ───
       Step 1: group by username permutation (always works, even without bio signals).
       Step 2: merge username-groups that share a bio signal (display_name / location /
               cross-link / ≥2 overlapping matched_attributes with score ≥ 40).
    ─── */
    const liveClusters = useMemo(() => {
        if (allLiveFound.length === 0) return [];

        // ── Step 1: group by username key ──────────────────────────────────────
        const byUsername = new Map();
        for (const entry of allLiveFound) {
            const key = (entry.username || '').toLowerCase().trim() || '__anon__';
            if (!byUsername.has(key)) byUsername.set(key, []);
            byUsername.get(key).push(entry);
        }

        // Convert to array of group objects
        let groups = [];
        for (const [uname, accounts] of byUsername.entries()) {
            const allAttrs = new Set();
            accounts.forEach(a => (a.matched_attributes || []).forEach(attr => allAttrs.add(attr)));
            const locs = [...new Set(accounts.map(a => (a.location || '').trim()).filter(Boolean))];
            const nameFreq = new Map();
            accounts.forEach(a => { const dn = (a.display_name || '').trim(); if (dn) nameFreq.set(dn, (nameFreq.get(dn) || 0) + 1); });
            const displayName = nameFreq.size > 0 ? [...nameFreq.entries()].sort((x, y) => y[1] - x[1])[0][0] : '';
            const avgScore = Math.round(accounts.reduce((s, a) => s + (a.subject_match_score || 0), 0) / accounts.length);
            groups.push({ usernames: new Set([uname]), displayName, accounts, attrs: allAttrs, locs, avgScore });
        }

        // ── Step 2: merge groups linked by bio signals ─────────────────────────
        // Helper: do two groups share a bio signal?
        const shouldMerge = (g1, g2) => {
            const dn1 = g1.displayName.toLowerCase(), dn2 = g2.displayName.toLowerCase();
            if (dn1 && dn2 && dn1 === dn2) return true;
            const loc1 = new Set(g1.locs.map(l => l.toLowerCase()));
            for (const l of g2.locs) { if (loc1.has(l.toLowerCase())) return true; }
            // Cross-links: any account in g1 links to any URL in g2, or vice versa
            const urls2 = new Set(g2.accounts.map(a => a.url));
            for (const a of g1.accounts) {
                for (const link of (a.cross_links || [])) { if (urls2.has(link)) return true; }
            }
            const urls1 = new Set(g1.accounts.map(a => a.url));
            for (const a of g2.accounts) {
                for (const link of (a.cross_links || [])) { if (urls1.has(link)) return true; }
            }
            // ≥2 overlapping matched_attributes when both have score ≥ 40
            if (g1.avgScore >= 40 && g2.avgScore >= 40) {
                let overlap = 0;
                for (const attr of g2.attrs) { if (g1.attrs.has(attr)) overlap++; }
                if (overlap >= 2) return true;
            }
            return false;
        };

        // Union-Find over groups array index
        const parent = groups.map((_, i) => i);
        const find = (i) => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
        const union = (i, j) => { parent[find(i)] = find(j); };

        for (let i = 0; i < groups.length; i++) {
            for (let j = i + 1; j < groups.length; j++) {
                if (shouldMerge(groups[i], groups[j])) union(i, j);
            }
        }

        // Collect merged clusters
        const rootMap = new Map();
        for (let i = 0; i < groups.length; i++) {
            const root = find(i);
            if (!rootMap.has(root)) rootMap.set(root, []);
            rootMap.get(root).push(groups[i]);
        }

        const clusters = [];
        for (const memberGroups of rootMap.values()) {
            const accounts = memberGroups.flatMap(g => g.accounts);
            if (accounts.length === 0) continue;
            const allAttrs = new Set();
            memberGroups.forEach(g => g.attrs.forEach(a => allAttrs.add(a)));
            const locs = [...new Set(memberGroups.flatMap(g => g.locs))];
            const avgScore = Math.round(accounts.reduce((s, a) => s + (a.subject_match_score || 0), 0) / accounts.length);

            // Label: prefer a real display_name, else the username key(s)
            const nameFreq = new Map();
            memberGroups.forEach(g => { if (g.displayName) nameFreq.set(g.displayName, (nameFreq.get(g.displayName) || 0) + g.accounts.length); });
            const label = nameFreq.size > 0
                ? [...nameFreq.entries()].sort((x, y) => y[1] - x[1])[0][0]
                : [...new Set(memberGroups.map(g => [...g.usernames][0]).filter(u => u !== '__anon__'))].slice(0, 2).join(' / ') || 'Unknown';

            clusters.push({ label, accounts, shared_attrs: [...allAttrs].filter(Boolean), confidence: avgScore, locations: locs });
        }

        return clusters.sort((a, b) =>
            b.accounts.length !== a.accounts.length
                ? b.accounts.length - a.accounts.length
                : b.confidence - a.confidence
        );
    }, [allLiveFound]);

    /* ─── Profile Form Section Renderer ─── */
    const renderSection = (title, icon, sectionKey, fields) => (
        <div className="ov2-section" key={sectionKey}>
            <button className="ov2-section-header" onClick={() => toggleSection(sectionKey)}>
                <span className="ov2-section-icon">{icon}</span>
                <span>{title}</span>
                {expandedSections[sectionKey] ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
            {expandedSections[sectionKey] && (
                <div className="ov2-section-body">
                    {fields.map(f => (
                        <div className="ov2-field" key={f.key}>
                            <label>{f.label}{f.required && <span className="ov2-required">*</span>}</label>
                            {f.type === 'select' ? (
                                <select value={profile[f.key]} onChange={e => updateProfile(f.key, e.target.value)}>
                                    {f.options.map(o => <option key={o} value={o}>{o}</option>)}
                                </select>
                            ) : f.type === 'textarea' ? (
                                <textarea value={profile[f.key]} onChange={e => updateProfile(f.key, e.target.value)}
                                    placeholder={f.placeholder || ''} rows={2} />
                            ) : (
                                <input type={f.type || 'text'} value={profile[f.key]}
                                    onChange={e => updateProfile(f.key, e.target.value)}
                                    placeholder={f.placeholder || ''} />
                            )}
                            {f.hint && <span className="ov2-hint">{f.hint}</span>}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );

    /* ═══════════════════════════════════════════
       RENDER
       ═══════════════════════════════════════════ */
    const data = investigationResult;
    const hasResults = data && !data.error && data.results;
    const progress = investigationProgress || {};
    const phaseLabel = (progress.phase || 'queued').replace(/_/g, ' ');
    const completedChecks = Number(progress.completed || 0);
    const totalChecks = Number(progress.total || 0);
    const liveCompletion = totalChecks > 0 ? Math.min(100, Math.round((completedChecks / totalChecks) * 100)) : 0;
    // Last 250 log entries for tier log panels (keeps panels fast)
    const logEntries = liveLogs.slice(-250);

    return (
        <div className="ov2-page">
            {/* Header */}
            <div className="ov2-header">
                <div className="ov2-header-content">
                    <div className="ov2-title-row">
                        <Shield size={28} />
                        <div>
                            <h1>OSINT Investigation Platform</h1>
                            <p>Enterprise-grade identity intelligence &middot; Multi-signal verification</p>
                        </div>
                    </div>
                    {hasResults && (
                        <div className="ov2-header-actions">
                            <button className="ov2-dl-btn grouped" onClick={() => handleDownloadReport('grouped')} title="Download identity-clustered HTML report">
                                <Layers size={15} /> Grouped Report
                            </button>
                            <button className="ov2-dl-btn full" onClick={() => handleDownloadReport('all')} title="Download all accounts HTML report">
                                <List size={15} /> Full Report
                            </button>
                            <button onClick={() => handleExport('json')}><Download size={16} /> JSON</button>
                            <button onClick={() => handleExport('csv')}><Download size={16} /> CSV</button>
                            <button onClick={() => copyUrls('all')}>
                                {copiedUrl === 'all' ? <Check size={16} /> : <Copy size={16} />} URLs
                            </button>
                        </div>
                    )}
                </div>
            </div>

            <div className="ov2-layout">
                {/* ═══ Left Sidebar: Profile Form ═══ */}
                <div className="ov2-sidebar">
                    <div className="ov2-form-header">
                        <Crosshair size={18} /><span>Investigation Subject</span>
                        {Object.values(profile).some(v => v && v !== 'Internal') && (
                            <button className="ov2-clear-btn" onClick={handleReset} title="Clear all"><X size={14} /></button>
                        )}
                    </div>

                    <div className="ov2-form-scroll">
                        {renderSection('Identity', <User size={16} />, 'identity', [
                            { key: 'first_name', label: 'First Name', placeholder: 'Rahul' },
                            { key: 'middle_name', label: 'Middle Name', placeholder: 'Kumar' },
                            { key: 'last_name', label: 'Last Name', placeholder: 'Sharma' },
                            { key: 'aliases', label: 'Aliases / Nicknames', placeholder: 'rahul_s, rsharma', hint: 'Comma-separated' },
                            { key: 'usernames', label: 'Username(s)', placeholder: 'rahulsharma, rahul.s99', hint: 'Triggers active search' },
                            { key: 'gender', label: 'Gender', type: 'select', options: ['', 'Male', 'Female', 'Other'] },
                            { key: 'date_of_birth', label: 'Date of Birth', placeholder: 'DD/MM/YYYY', hint: 'Used for suffix generation' },
                            { key: 'age_range', label: 'Age Range', placeholder: '25-35' },
                            { key: 'nationality', label: 'Nationality', placeholder: 'Indian' },
                            { key: 'languages', label: 'Languages', placeholder: 'Hindi, English, Marathi', hint: 'Comma-separated' },
                        ])}

                        {renderSection('Contact', <Mail size={16} />, 'contact', [
                            { key: 'emails', label: 'Email Address(es)', placeholder: 'rahul@gmail.com', hint: 'Triggers active search' },
                            { key: 'phones', label: 'Phone Number(s)', placeholder: '+91-98765-43210', hint: 'Triggers active search' },
                            { key: 'whatsapp_number', label: 'WhatsApp Number', placeholder: '+91-98765-43210' },
                        ])}

                        {renderSection('Location', <MapPin size={16} />, 'location', [
                            { key: 'city', label: 'City / Town', placeholder: 'Mumbai' },
                            { key: 'state', label: 'State', placeholder: 'Maharashtra' },
                            { key: 'country', label: 'Country', placeholder: 'India' },
                            { key: 'workplace', label: 'Workplace', placeholder: 'Tata Consultancy Services' },
                            { key: 'educational_institution', label: 'Educational Institution', placeholder: 'IIT Bombay' },
                        ])}

                        {renderSection('Professional', <Briefcase size={16} />, 'professional', [
                            { key: 'occupation', label: 'Occupation', placeholder: 'Software Engineer' },
                            { key: 'industry', label: 'Industry', placeholder: 'Information Technology' },
                            { key: 'companies', label: 'Company Names', placeholder: 'TCS, Infosys', hint: 'Comma-separated' },
                            { key: 'registration_numbers', label: 'Registration Numbers', placeholder: 'CA ICAI: 123456' },
                        ])}

                        {renderSection('Digital Footprint', <Globe size={16} />, 'digital', [
                            { key: 'known_profile_urls', label: 'Known Profile URLs', type: 'textarea', placeholder: 'https://github.com/rahulsharma' },
                            { key: 'profile_picture_url', label: 'Profile Picture URL', placeholder: 'https://...' },
                            { key: 'domains', label: 'Associated Domains', placeholder: 'rahulsharma.com', hint: 'Comma-separated' },
                            { key: 'known_ip', label: 'Known IP Address', placeholder: '203.0.113.1' },
                        ])}

                        {renderSection('Case Metadata', <FileText size={16} />, 'case', [
                            { key: 'case_id', label: 'Case / Investigation ID', placeholder: 'INV-2026-0042' },
                            { key: 'investigator_name', label: 'Investigator Name', placeholder: 'Det. Priya Patel' },
                            { key: 'investigation_purpose', label: 'Purpose', type: 'textarea', placeholder: 'Background check for...' },
                            { key: 'classification_level', label: 'Classification', type: 'select', options: ['Internal', 'Confidential', 'Restricted'] },
                        ])}
                    </div>

                    {/* Mode & Tier Selection */}
                    <div className="ov2-modes">
                        <div className="ov2-modes-label">Search Modes (auto if none):</div>
                        <div className="ov2-mode-chips">
                            {[
                                { id: 'username', label: 'Username', icon: <User size={12} /> },
                                { id: 'name', label: 'Full Name', icon: <Hash size={12} /> },
                                { id: 'email', label: 'Email', icon: <Mail size={12} /> },
                                { id: 'phone', label: 'Phone', icon: <Phone size={12} /> },
                            ].map(m => (
                                <button key={m.id}
                                    className={`ov2-mode-chip ${selectedModes.includes(m.id) ? 'active' : ''}`}
                                    onClick={() => setSelectedModes(prev =>
                                        prev.includes(m.id) ? prev.filter(x => x !== m.id) : [...prev, m.id])}>
                                    {m.icon} {m.label}
                                </button>
                            ))}
                        </div>
                        <div className="ov2-modes-label" style={{ marginTop: 8 }}>Tiers:</div>
                        <div className="ov2-mode-chips">
                            {[1, 2, 3].map(t => (
                                <button key={t}
                                    className={`ov2-mode-chip ${selectedTiers.includes(t) ? 'active' : ''}`}
                                    onClick={() => setSelectedTiers(prev =>
                                        prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])}>
                                    T{t}: {TIER_LABELS[t]}
                                </button>
                            ))}
                        </div>
                        <div className="ov2-modes-label" style={{ marginTop: 8 }}>Discovery:</div>
                        <div className="ov2-mode-chips">
                            <button
                                className={`ov2-mode-chip ${enableSerpDiscovery ? 'active' : ''}`}
                                onClick={() => setEnableSerpDiscovery(v => !v)}
                                title="Run a Google/DuckDuckGo dork pre-pass to surface vanity-handle and name+context profiles before per-site probing.">
                                <Globe size={12} /> SERP Pre-pass {enableSerpDiscovery ? '(ON)' : '(OFF)'}
                            </button>
                        </div>
                    </div>

                    {/* Profile Quality Indicator */}
                    <div className="ov2-profile-quality">
                        <div className="ov2-pq-header">
                            <span className="ov2-pq-title">Disambiguation Power</span>
                            <span className={`ov2-pq-level ${profileStrength.level.toLowerCase()}`}>
                                {profileStrength.level}
                            </span>
                        </div>
                        <div className="ov2-pq-bar-track">
                            <div className="ov2-pq-bar-fill" style={{
                                width: `${profileStrength.score}%`,
                                background: profileStrength.level === 'STRONG' ? '#00c853' : profileStrength.level === 'MODERATE' ? '#ffc107' : '#f44336',
                            }} />
                        </div>
                        <div className="ov2-pq-anchors">
                            {profileStrength.anchors.map(a => (
                                <span key={a.key} className={`ov2-pq-anchor ${a.present ? 'present' : 'missing'} ${a.power}`}
                                    title={`${a.power} anchor${a.present ? ' — provided' : ' — missing'}`}>
                                    {a.icon} {a.name}
                                </span>
                            ))}
                        </div>
                        {profileStrength.advice && (
                            <div className="ov2-pq-advice">💡 {profileStrength.advice}</div>
                        )}
                    </div>

                    {/* Launch Button */}
                    <div className="ov2-launch">
                        {!investigationLoading ? (
                            <button className="ov2-launch-btn" onClick={handleInvestigate} disabled={!hasSearchableFields}>
                                <Play size={18} /> Begin Investigation
                            </button>
                        ) : (
                            <div className="ov2-launch-controls">
                                <button
                                    className={`ov2-launch-btn pause-resume ${isPaused ? 'resume' : 'pause'}`}
                                    onClick={isPaused ? handleResume : handlePause}
                                    title={isPaused ? 'Resume scanning' : 'Pause scanning'}>
                                    {isPaused ? <><SkipForward size={16} /> Resume</> : <><Pause size={16} /> Pause</>}
                                </button>
                                <button className="ov2-launch-btn cancel" onClick={handleCancel}>
                                    <X size={16} /> Cancel
                                </button>
                            </div>
                        )}
                        {!hasSearchableFields && (
                            <div className="ov2-launch-hint">
                                Provide at least one: Username, First+Last Name, Email, or Phone
                            </div>
                        )}
                    </div>
                </div>

                {/* ═══ Right Main: Results ═══ */}
                <div className="ov2-main">
                    {/* Loading */}
                    {investigationLoading && (
                        <>
                            <div className="ov2-loading">
                                <div className="ov2-loading-spinner" />
                                <div className="ov2-loading-text">
                                    <strong>Investigation in progress...</strong>
                                    <span>Elapsed: {(elapsedTime / 1000).toFixed(1)}s</span>
                                </div>
                                <div className="ov2-loading-detail">
                                    {activeJobId ? `Job ${activeJobId.slice(0, 8)} · ${phaseLabel}` : 'Preparing investigation job...'}
                                </div>
                            </div>

                            <div className="ov2-live-console">
                                <div className="ov2-live-summary">
                                    <div className="ov2-live-card">
                                        <span className="ov2-live-label">Phase</span>
                                        <strong>{phaseLabel}</strong>
                                        <small>{progress.current_site || 'Waiting for first site...'}</small>
                                    </div>
                                    <div className="ov2-live-card">
                                        <span className="ov2-live-label">Progress</span>
                                        <strong>{completedChecks}/{totalChecks || '?'}</strong>
                                        <small>{liveCompletion}% complete</small>
                                    </div>
                                    <div className="ov2-live-card">
                                        <span className="ov2-live-label">Actionable</span>
                                        <strong>{progress.actionable_findings || 0}</strong>
                                        <small>{progress.manual_review_count || 0} queued for review</small>
                                    </div>
                                    <div className="ov2-live-card">
                                        <span className="ov2-live-label">Manifest</span>
                                        <strong>{progress.sites_enabled || 0} active sites</strong>
                                        <small>{progress.sites_suppressed || 0} suppressed upfront</small>
                                    </div>
                                </div>

                                {totalChecks > 0 && (
                                    <div className="ov2-live-progress">
                                        <div className="ov2-progress-track">
                                            <div className="ov2-progress-fill" style={{ width: `${liveCompletion}%` }} />
                                        </div>
                                    </div>
                                )}

                                {/* Live Findings Feed — uses allLiveFound so entries never disappear */}
                                {allLiveFound.length > 0 && (
                                    <div className="ov2-live-findings">
                                        <div className="ov2-live-findings-header">
                                            <Zap size={14} />
                                            <strong>Live Findings</strong>
                                            <span className="ov2-live-findings-count">{allLiveFound.length} account{allLiveFound.length !== 1 ? 's' : ''} found</span>
                                            <div className="ov2-live-dl-btns">
                                                <button className="ov2-dl-btn grouped" onClick={() => handleDownloadReport('grouped')} title="Download grouped report">
                                                    <Layers size={12} /> Grouped
                                                </button>
                                                <button className="ov2-dl-btn full" onClick={() => handleDownloadReport('all')} title="Download full report">
                                                    <List size={12} /> Full
                                                </button>
                                            </div>
                                        </div>
                                        <div className="ov2-live-findings-list">
                                            {allLiveFound.map((f, i) => {
                                                const confColor = CONFIDENCE_COLORS[f.confidence_level] || '#888';
                                                const sms = f.subject_match_score || 0;
                                                const smsClass = sms >= 70 ? 'sms-strong' : sms >= 30 ? 'sms-possible' : 'sms-weak';
                                                return (
                                                    <div key={`lf_${i}_${f.url}`} className="ov2-live-finding-row">
                                                        <span className="ov2-lf-tier" style={{
                                                            background: f.tier === 1 ? 'rgba(255,107,53,0.15)' : f.tier === 2 ? 'rgba(124,58,237,0.15)' : 'rgba(14,165,233,0.15)',
                                                            color: f.tier === 1 ? '#ff6b35' : f.tier === 2 ? '#a78bfa' : '#38bdf8',
                                                        }}>T{f.tier || '?'}</span>
                                                        <span className="ov2-lf-conf" style={{ color: confColor }}>{f.confidence_score}%</span>
                                                        <span className="ov2-lf-site">{f.site_name}</span>
                                                        {f.username && <span className="ov2-lf-username">@{f.username}</span>}
                                                        <span className="ov2-lf-level" style={{ color: confColor }}>{f.confidence_level}</span>
                                                        {sms > 0 && (
                                                            <span className={`ov2-lf-sms ${smsClass}`} title={(f.matched_attributes || []).join(', ') || 'Subject match'}>
                                                                {sms >= 70 ? 'Strong' : sms >= 30 ? 'Possible' : 'Weak'} {sms}%
                                                            </span>
                                                        )}
                                                        <a href={f.url} target="_blank" rel="noopener noreferrer" className="ov2-lf-link" title={f.url}>
                                                            {f.url.length > 40 ? f.url.slice(0, 40) + '…' : f.url}
                                                            <ExternalLink size={11} />
                                                        </a>
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}

                                {/* Live Identity Clusters — grouped by bio signals */}
                                {liveClusters.length > 0 && (
                                    <div className="ov2-live-clusters">
                                        <div className="ov2-lc-header">
                                            <Users size={14} />
                                            <strong>Live Identity Groups</strong>
                                            <span className="ov2-lc-subtitle">{liveClusters.length} cluster{liveClusters.length !== 1 ? 's' : ''} by bio signals</span>
                                        </div>
                                        <div className="ov2-lc-list">
                                            {liveClusters.map((cluster, ci) => (
                                                <div key={`lc_${ci}_${cluster.label}`} className="ov2-lc-card">
                                                    <div className="ov2-lc-card-top">
                                                        <span className="ov2-lc-username">{cluster.label}</span>
                                                        <span className="ov2-lc-count">{cluster.accounts.length} account{cluster.accounts.length !== 1 ? 's' : ''}</span>
                                                        {cluster.confidence > 0 && (
                                                            <span className={`ov2-lc-conf ${cluster.confidence >= 70 ? 'high' : cluster.confidence >= 30 ? 'med' : 'low'}`}>
                                                                {cluster.confidence}% match
                                                            </span>
                                                        )}
                                                        {cluster.locations.length > 0 && (
                                                            <span className="ov2-lc-loc"><MapPin size={10} /> {cluster.locations[0]}</span>
                                                        )}
                                                    </div>
                                                    {cluster.shared_attrs.length > 0 && (
                                                        <div className="ov2-lc-attrs">{cluster.shared_attrs.slice(0, 4).map(a => (
                                                            <span key={a} className="ov2-lc-attr-chip">{a.replace(':', ': ')}</span>
                                                        ))}</div>
                                                    )}
                                                    <div className="ov2-lc-chips">
                                                        {cluster.accounts.map((acc, ai) => (
                                                            <a key={`${ci}_${ai}`} href={acc.url} target="_blank" rel="noopener noreferrer" className="ov2-ic-account-chip">
                                                                <span className="ov2-ic-chip-site">{acc.site_name}</span>
                                                                <span className="ov2-ic-chip-score" style={{
                                                                    color: CONFIDENCE_COLORS[acc.confidence_level] || '#888'
                                                                }}>{acc.confidence_score}%</span>
                                                            </a>
                                                        ))}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Three Tier Log Panels */}
                                <div className="ov2-tier-logs-grid">
                                    {[
                                        { tier: 1, label: 'Tier 1 — India Priority', color: '#ff6b35' },
                                        { tier: 2, label: 'Tier 2 — Global',         color: '#a78bfa' },
                                        { tier: 3, label: 'Tier 3 — Niche',          color: '#38bdf8' },
                                    ].map(({ tier, label, color }) => {
                                        const tierLogs = logEntries.filter(l => l.tier === tier);
                                        const checking = [...tierLogs].reverse().find(l => l.status === 'checking');
                                        const tierFound = tierLogs.filter(l => l.level === 'found');
                                        return (
                                            <div key={tier} className="ov2-tier-log-panel">
                                                <div className="ov2-tier-log-header" style={{ borderTopColor: color }}>
                                                    <div className="ov2-tier-log-title">
                                                        <span className="ov2-tier-log-badge" style={{ background: color }}>T{tier}</span>
                                                        <span>{label}</span>
                                                    </div>
                                                    <span className="ov2-tier-log-stats">{tierFound.length} found / {tierLogs.length} events</span>
                                                </div>

                                                {checking ? (
                                                    <div className="ov2-tier-checking" style={{ borderColor: `${color}33` }}>
                                                        <div className="ov2-cs-spinner" style={{ borderTopColor: color }} />
                                                        <span className="ov2-tier-checking-site">{checking.site_name}</span>
                                                        {checking.username && <span className="ov2-tier-checking-user">@{checking.username}</span>}
                                                    </div>
                                                ) : (
                                                    <div className="ov2-tier-checking idle">
                                                        <span className="ov2-tier-idle-dot" style={{ background: color }} />
                                                        <span>Waiting for Tier {tier}...</span>
                                                    </div>
                                                )}

                                                <div className="ov2-tier-log-stream" ref={tierLogRefs[tier]}>
                                                    {tierLogs.length > 0 ? tierLogs.map((log, li) => (
                                                        <div key={`t${tier}_${li}_${log.seq || log.timestamp}`}
                                                            className={`ov2-log-line ${log.level || 'info'} ${log.status || ''}`}>
                                                            <span className="ov2-log-time">
                                                                {log.timestamp ? new Date(log.timestamp).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '--:--:--'}
                                                            </span>
                                                            <span className="ov2-log-body">
                                                                <strong>{log.site_name || 'system'}</strong>
                                                                <span>{log.message}</span>
                                                            </span>
                                                            <span className="ov2-log-meta" style={{ color: log.level === 'found' ? '#00e676' : undefined }}>
                                                                {log.status || log.confidence_level || ''}
                                                            </span>
                                                        </div>
                                                    )) : (
                                                        <div className="ov2-log-empty">Tier {tier} starting...</div>
                                                    )}
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        </>
                    )}

                    {/* Error */}
                    {data?.error && (
                        <div className="ov2-error"><AlertTriangle size={20} /><span>{data.error}</span></div>
                    )}

                    {/* Results UI */}
                    {hasResults && (
                        <>
                            {/* Disambiguation Warning */}
                            {data?.disambiguation_hint && (
                                <div className="ov2-disambiguation-warning">
                                    <AlertTriangle size={16} />
                                    <span>{data.disambiguation_hint}</span>
                                </div>
                            )}

                            {/* SERP Pre-pass Discoveries */}
                            {data?.serp_discovery?.enabled && (
                                <div className="ov2-serp-summary">
                                    <div className="ov2-serp-header">
                                        <Globe size={16} />
                                        <strong>SERP Pre-pass Discovery</strong>
                                        <span className="ov2-serp-meta">
                                            {data.serp_discovery.discoveries?.length || 0} candidates
                                            + {data.serp_discovery.external_discoveries?.length || 0} external
                                            from {data.serp_discovery.dorks_executed || 0} dorks
                                            ({data.serp_discovery.raw_hits || 0} raw hits) ·
                                            backends: {(data.serp_discovery.backends || []).join(', ') || 'none'}
                                        </span>
                                    </div>
                                    {(data.serp_discovery.discoveries || []).slice(0, 12).map((d, di) => (
                                        <div key={di} className="ov2-serp-row">
                                            <a href={d.url} target="_blank" rel="noopener noreferrer" className="ov2-serp-url">
                                                <strong>{d.site_name}</strong> @{d.username}
                                            </a>
                                            <span className={`ov2-serp-score ${d.score >= 60 ? 'high' : d.score >= 30 ? 'med' : 'low'}`}>
                                                {d.score}%
                                            </span>
                                            <span className="ov2-serp-dork" title={d.dork}>via: {d.reason}</span>
                                            {d.snippet && <div className="ov2-serp-snip">{d.snippet}</div>}
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* SERP External (off-catalog) Leads */}
                            {data?.serp_discovery?.enabled && (data.serp_discovery.external_discoveries?.length || 0) > 0 && (
                                <div className="ov2-serp-summary ov2-serp-external">
                                    <div className="ov2-serp-header">
                                        <Globe size={16} />
                                        <strong>Additional Leads (Outside Catalog)</strong>
                                        <span className="ov2-serp-meta">
                                            {data.serp_discovery.external_discoveries.length} profile-like URLs from sites not in our 300-site list ·
                                            <em> unverified — manual review</em>
                                        </span>
                                    </div>
                                    {data.serp_discovery.external_discoveries.map((d, di) => (
                                        <div key={di} className="ov2-serp-row">
                                            <a href={d.url} target="_blank" rel="noopener noreferrer" className="ov2-serp-url">
                                                <strong>{d.domain}</strong> @{d.extracted_username}
                                            </a>
                                            <span className={`ov2-serp-score ${d.score >= 60 ? 'high' : d.score >= 30 ? 'med' : 'low'}`}>
                                                {d.score}%
                                            </span>
                                            <span className="ov2-serp-dork" title={d.dork}>via: {d.reason}</span>
                                            {d.verified === true && <span className="ov2-serp-verified">live</span>}
                                            {d.verified === false && <span className="ov2-serp-dead">dead</span>}
                                            {d.snippet && <div className="ov2-serp-snip">{d.snippet}</div>}
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Identity Clusters */}
                            {data?.identity_clusters && data.identity_clusters.length > 0 && (
                                <div className="ov2-identity-clusters">
                                    <div className="ov2-ic-header">
                                        <Users size={16} />
                                        <strong>Identity Clusters</strong>
                                        <span className="ov2-ic-subtitle">Accounts likely belonging to the same person</span>
                                    </div>
                                    {data.identity_clusters.map((cluster, ci) => (
                                        <div key={cluster.cluster_id || ci} className="ov2-ic-card">
                                            <div className="ov2-ic-card-header">
                                                <strong>{cluster.display_name || 'Unknown'}</strong>
                                                <span className={`ov2-ic-confidence ${cluster.cluster_confidence >= 70 ? 'high' : cluster.cluster_confidence >= 30 ? 'med' : 'low'}`}>
                                                    Match: {cluster.cluster_confidence}%
                                                </span>
                                                <span className="ov2-ic-count">{cluster.account_count} accounts</span>
                                            </div>
                                            {cluster.locations && cluster.locations.length > 0 && (
                                                <div className="ov2-ic-meta">Location: {cluster.locations.join(', ')}</div>
                                            )}
                                            <div className="ov2-ic-accounts">
                                                {cluster.accounts.map((acc, ai) => (
                                                    <a key={ai} href={acc.url} target="_blank" rel="noopener noreferrer" className="ov2-ic-account-chip">
                                                        <span className="ov2-ic-chip-site">{acc.site_name}</span>
                                                        <span className="ov2-ic-chip-score">{acc.confidence_score}%</span>
                                                    </a>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Download Report Buttons */}
                            <div className="ov2-report-dl-bar">
                                <span className="ov2-report-dl-label">Download Report:</span>
                                <button className="ov2-dl-btn grouped" onClick={() => handleDownloadReport('grouped')}>
                                    <Layers size={14} /> Grouped by Identity
                                </button>
                                <button className="ov2-dl-btn full" onClick={() => handleDownloadReport('all')}>
                                    <List size={14} /> All Accounts
                                </button>
                            </div>

                            {/* Summary Cards */}
                            <div className="ov2-summary">
                                <div className="ov2-summary-card green">
                                    <div className="ov2-summary-value">{data.actionable_findings}</div>
                                    <div className="ov2-summary-label">Actionable</div>
                                    <div className="ov2-summary-sub">{data.confirmed_count} confirmed + {data.high_confidence_count} high</div>
                                </div>
                                <div
                                    className="ov2-summary-card yellow clickable"
                                    role="button"
                                    tabIndex={0}
                                    onClick={() => setActiveTab('review')}
                                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setActiveTab('review'); }}
                                    title="Open the Review Queue to triage these leads">
                                    <div className="ov2-summary-value">{data.manual_review_count || 0}</div>
                                    <div className="ov2-summary-label">Manual Review →</div>
                                    <div className="ov2-summary-sub">
                                        {data.medium_confidence_count || 0} medium + {data.ambiguous_count || 0} ambiguous
                                        {(data.low_signal_count || 0) > 0 && (
                                            <> · {data.low_signal_count} low-signal hidden</>
                                        )}
                                    </div>
                                </div>
                                <div className="ov2-summary-card blue">
                                    <div className="ov2-summary-value">{data.csv_matches?.length || 0}</div>
                                    <div className="ov2-summary-label">Breach Records</div>
                                </div>
                                <div className="ov2-summary-card dim">
                                    <div className="ov2-summary-value">{data.total_sites_checked}</div>
                                    <div className="ov2-summary-label">Sites Checked</div>
                                    <div className="ov2-summary-sub">{(data.elapsed_ms / 1000).toFixed(1)}s elapsed</div>
                                </div>
                            </div>

                            {/* Investigator Summary */}
                            {(confirmedAccounts.size > 0 || excludedAccounts.size > 0) && (
                                <div className="ov2-verdict-summary">
                                    {confirmedAccounts.size > 0 && (
                                        <span className="ov2-vs-confirmed">✓ {confirmedAccounts.size} confirmed as subject</span>
                                    )}
                                    {excludedAccounts.size > 0 && (
                                        <span className="ov2-vs-excluded">✗ {excludedAccounts.size} marked as different person</span>
                                    )}
                                </div>
                            )}

                            {/* Pivot Suggestions — new identifiers found in bios */}
                            {data.pivot_suggestions && Object.keys(data.pivot_suggestions).some(k => (data.pivot_suggestions[k] || []).length > 0) && (
                                <div className="ov2-pivot-panel">
                                    <div className="ov2-pivot-header">
                                        <span>🔄</span>
                                        <strong>Pivot Suggestions</strong>
                                        <span className="ov2-pivot-sub">New identifiers found in account bios — add to profile for deeper search</span>
                                    </div>
                                    <div className="ov2-pivot-items">
                                        {(data.pivot_suggestions.emails || []).map((email, i) => (
                                            <div key={`pe_${i}`} className="ov2-pivot-item">
                                                <span className="ov2-pivot-type">📧 Email</span>
                                                <span className="ov2-pivot-value">{email}</span>
                                                <button className="ov2-pivot-add" onClick={() => {
                                                    const cur = profile.emails ? profile.emails + ', ' + email : email;
                                                    updateProfile('emails', cur);
                                                }}>+ Add to Profile</button>
                                            </div>
                                        ))}
                                        {(data.pivot_suggestions.phones || []).map((phone, i) => (
                                            <div key={`pp_${i}`} className="ov2-pivot-item">
                                                <span className="ov2-pivot-type">📱 Phone</span>
                                                <span className="ov2-pivot-value">{phone}</span>
                                                <button className="ov2-pivot-add" onClick={() => {
                                                    const cur = profile.phones ? profile.phones + ', ' + phone : phone;
                                                    updateProfile('phones', cur);
                                                }}>+ Add to Profile</button>
                                            </div>
                                        ))}
                                        {(data.pivot_suggestions.profile_urls || []).map((url, i) => (
                                            <div key={`pu_${i}`} className="ov2-pivot-item">
                                                <span className="ov2-pivot-type">🔗 Profile URL</span>
                                                <a href={url} target="_blank" rel="noopener noreferrer" className="ov2-pivot-value">{url}</a>
                                                <button className="ov2-pivot-add" onClick={() => {
                                                    const cur = profile.known_profile_urls ? profile.known_profile_urls + '\n' + url : url;
                                                    updateProfile('known_profile_urls', cur);
                                                }}>+ Add to Profile</button>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Tier Progress Bars */}
                            {data.tier_progress && (
                                <div className="ov2-tier-progress">
                                    {data.tier_progress.map(tp => (
                                        <div key={tp.tier} className="ov2-tier-bar">
                                            <div className="ov2-tier-bar-label">
                                                <span>Tier {tp.tier}: {TIER_LABELS[tp.tier]}</span>
                                                <span>{tp.found} found / {tp.total_sites} sites</span>
                                            </div>
                                            <div className="ov2-progress-track">
                                                <div className="ov2-progress-fill" style={{ width: `${tp.percentage}%` }} />
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {/* Tabs */}
                            <div className="ov2-tabs">
                                {[
                                    { id: 'results', label: 'Findings', count: filteredResults.filter(r => r.status !== 'not_found').length },
                                    { id: 'review', label: 'Review Queue', count: reviewQueue.length, highlight: reviewQueue.length > 0 },
                                    { id: 'correlation', label: 'Correlation', count: data.correlation_clusters?.length || 0 },
                                    { id: 'breaches', label: 'Breach Data', count: data.csv_matches?.length || 0 },
                                    { id: 'discarded', label: 'Discarded', count: discardedList.length },
                                    { id: 'report', label: 'Footprint' },
                                ].map(tab => (
                                    <button key={tab.id}
                                        className={`ov2-tab ${activeTab === tab.id ? 'active' : ''}`}
                                        onClick={() => setActiveTab(tab.id)}>
                                        {tab.label}
                                        {tab.count !== undefined && <span className="ov2-tab-count">{tab.count}</span>}
                                    </button>
                                ))}
                            </div>

                            {/* Filters */}
                            {activeTab === 'results' && (
                                <div className="ov2-filters">
                                    <Filter size={14} />
                                    <select value={filterTier} onChange={e => setFilterTier(Number(e.target.value))}>
                                        <option value={0}>All Tiers</option>
                                        <option value={1}>Tier 1: Indian Priority</option>
                                        <option value={2}>Tier 2: Global</option>
                                        <option value={3}>Tier 3: Niche</option>
                                    </select>
                                    <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)}>
                                        <option value="all">All Categories</option>
                                        {['dev','social','media','creative','blog','gaming','business','india','other'].map(c => (
                                            <option key={c} value={c}>{c}</option>
                                        ))}
                                    </select>
                                    <select value={filterConfidence} onChange={e => setFilterConfidence(e.target.value)}>
                                        <option value="all">All Confidence</option>
                                        <option value="Confirmed">Confirmed</option>
                                        <option value="High Confidence">High Confidence</option>
                                        <option value="Medium Confidence">Medium Confidence</option>
                                        <option value="Ambiguous">Ambiguous</option>
                                        <option value="Unverified">Unverified (low signal)</option>
                                    </select>
                                    <select value={filterDisambig} onChange={e => setFilterDisambig(e.target.value)}>
                                        <option value="all">All Matches</option>
                                        <option value="DEFINITIVE">Definitive (email/phone)</option>
                                        <option value="HIGH">High Confidence (3+ signals)</option>
                                        <option value="POSSIBLE">Possible (1–2 signals)</option>
                                        <option value="UNLIKELY">Low Confidence</option>
                                    </select>
                                    <label className="ov2-toggle-label">
                                        <input type="checkbox" checked={showNotFound} onChange={e => setShowNotFound(e.target.checked)} />
                                        Show Not Found
                                    </label>
                                </div>
                            )}

                            {/* ─── Tab: Findings ─── */}
                            {activeTab === 'results' && (
                                <div className="ov2-results-list">
                                    {filteredResults.length > 0 ? filteredResults.map(r => (
                                        <ResultCard key={`${r.site_name}_${r.username_searched}_${r.url}`} result={r}
                                            expandedCards={expandedCards} setExpandedCards={setExpandedCards}
                                            discardedResults={discardedResults} toggleDiscard={toggleDiscard}
                                            investigatorNotes={investigatorNotes} setInvestigatorNotes={setInvestigatorNotes}
                                            copiedUrl={copiedUrl} setCopiedUrl={setCopiedUrl}
                                            confirmedAccounts={confirmedAccounts} excludedAccounts={excludedAccounts}
                                            toggleConfirm={toggleConfirm} toggleExclude={toggleExclude} />
                                    )) : (
                                        <div className="ov2-empty"><Search size={32} /><p>No results match current filters</p></div>
                                    )}
                                </div>
                            )}

                            {/* ─── Tab: Review Queue ─── */}
                            {activeTab === 'review' && (
                                <div className="ov2-review-queue">
                                    {reviewQueue.length > 0 ? (
                                        <>
                                            <div className="ov2-review-toolbar">
                                                <div className="ov2-review-help">
                                                    <strong>{reviewQueue.length}</strong> leads ranked by subject-match strength.
                                                    Click each URL, then hit <em>IS subject</em> or <em>Different person</em>.
                                                </div>
                                                <div className="ov2-review-batch">
                                                    <button
                                                        className="ov2-text-btn"
                                                        onClick={() => {
                                                            reviewQueue.slice(0, 10).forEach(r => {
                                                                window.open(r.url, '_blank', 'noopener,noreferrer');
                                                            });
                                                        }}
                                                        title="Open the top 10 URLs in new tabs">
                                                        <ExternalLink size={14} /> Open top 10
                                                    </button>
                                                    <button
                                                        className="ov2-text-btn discard"
                                                        onClick={() => {
                                                            if (!window.confirm(`Dismiss all ${reviewQueue.length} leads as "Different person"?`)) return;
                                                            reviewQueue.forEach(r => toggleExclude?.(r.url));
                                                        }}>
                                                        <Trash2 size={14} /> Dismiss all
                                                    </button>
                                                </div>
                                            </div>
                                            <div className="ov2-results-list">
                                                {reviewQueue.map(r => (
                                                    <ResultCard key={`rev_${r.site_name}_${r.username_searched}_${r.url}`} result={r}
                                                        expandedCards={expandedCards} setExpandedCards={setExpandedCards}
                                                        discardedResults={discardedResults} toggleDiscard={toggleDiscard}
                                                        investigatorNotes={investigatorNotes} setInvestigatorNotes={setInvestigatorNotes}
                                                        copiedUrl={copiedUrl} setCopiedUrl={setCopiedUrl}
                                                        confirmedAccounts={confirmedAccounts} excludedAccounts={excludedAccounts}
                                                        toggleConfirm={toggleConfirm} toggleExclude={toggleExclude} />
                                                ))}
                                            </div>
                                        </>
                                    ) : (
                                        <div className="ov2-empty">
                                            <Check size={32} />
                                            <p>Review queue is clear — no ambiguous leads awaiting triage.</p>
                                            {(data.low_signal_count || 0) > 0 && (
                                                <small>{data.low_signal_count} low-signal hits were auto-hidden. Enable "Show Not Found" on the Findings tab to inspect them.</small>
                                            )}
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* ─── Tab: Correlation ─── */}
                            {activeTab === 'correlation' && (
                                <div className="ov2-correlation">
                                    {data.correlation_clusters?.length > 0 ? data.correlation_clusters.map((c, i) => (
                                        <div key={i} className="ov2-cluster-card">
                                            <div className="ov2-cluster-type">
                                                {c.corroboration_type === 'username_match' && <Award size={16} />}
                                                {c.corroboration_type === 'name_match' && <User size={16} />}
                                                {c.corroboration_type === 'cross_platform_link' && <Link size={16} />}
                                                <span>{c.corroboration_type.replace(/_/g, ' ')}</span>
                                                <span className="ov2-boost">+{c.confidence_boost}%</span>
                                            </div>
                                            <div className="ov2-cluster-detail">{c.detail}</div>
                                            <div className="ov2-cluster-platforms">
                                                {c.platforms.map((p, j) => (
                                                    <span key={j} className="ov2-platform-chip">{p}</span>
                                                ))}
                                            </div>
                                        </div>
                                    )) : (
                                        <div className="ov2-empty"><Zap size={32} /><p>No cross-platform correlations found</p></div>
                                    )}
                                </div>
                            )}

                            {/* ─── Tab: Breach Data ─── */}
                            {activeTab === 'breaches' && (
                                <div className="ov2-breaches">
                                    {data.csv_matches?.length > 0 ? data.csv_matches.map((m, i) => (
                                        <div key={i} className="ov2-breach-card">
                                            <div className="ov2-breach-header">
                                                <span className="ov2-breach-source">{m._source_csv || 'unknown'}</span>
                                                <span className="ov2-breach-field">Matched: {m._matched_field}</span>
                                            </div>
                                            <div className="ov2-breach-data">
                                                {Object.entries(m).filter(([k]) => !k.startsWith('_')).slice(0, 8).map(([k, v]) => (
                                                    <div key={k} className="ov2-breach-kv">
                                                        <span className="ov2-breach-key">{k}</span>
                                                        <span className="ov2-breach-val">{String(v).slice(0, 100)}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )) : (
                                        <div className="ov2-empty"><BarChart3 size={32} /><p>No breach data matches</p></div>
                                    )}
                                </div>
                            )}

                            {/* ─── Tab: Discarded ─── */}
                            {activeTab === 'discarded' && (
                                <div className="ov2-results-list">
                                    {discardedList.length > 0 ? discardedList.map(r => (
                                        <ResultCard key={`disc_${r.url}`} result={r}
                                            expandedCards={expandedCards} setExpandedCards={setExpandedCards}
                                            discardedResults={discardedResults} toggleDiscard={toggleDiscard}
                                            investigatorNotes={investigatorNotes} setInvestigatorNotes={setInvestigatorNotes}
                                            copiedUrl={copiedUrl} setCopiedUrl={setCopiedUrl}
                                            confirmedAccounts={confirmedAccounts} excludedAccounts={excludedAccounts}
                                            toggleConfirm={toggleConfirm} toggleExclude={toggleExclude} />
                                    )) : (
                                        <div className="ov2-empty"><Trash2 size={32} /><p>No discarded results</p></div>
                                    )}
                                </div>
                            )}

                            {/* ─── Tab: Footprint ─── */}
                            {activeTab === 'report' && data.digital_footprint && (
                                <div className="ov2-footprint">
                                    <h3>Digital Footprint Summary</h3>
                                    <div className="ov2-footprint-grid">
                                        <div className="ov2-fp-item">
                                            <div className="ov2-fp-value">{data.digital_footprint.total_confirmed_accounts}</div>
                                            <div className="ov2-fp-label">Confirmed Accounts</div>
                                        </div>
                                        <div className="ov2-fp-item">
                                            <div className="ov2-fp-value">{data.digital_footprint.total_breach_matches}</div>
                                            <div className="ov2-fp-label">Breach Records</div>
                                        </div>
                                        <div className="ov2-fp-item">
                                            <div className="ov2-fp-value">{data.digital_footprint.correlation_clusters_count}</div>
                                            <div className="ov2-fp-label">Correlation Clusters</div>
                                        </div>
                                        <div className="ov2-fp-item">
                                            <div className="ov2-fp-value">{data.digital_footprint.cross_platform_links_found}</div>
                                            <div className="ov2-fp-label">Cross-Platform Links</div>
                                        </div>
                                    </div>

                                    {data.digital_footprint.category_breakdown && Object.keys(data.digital_footprint.category_breakdown).length > 0 && (
                                        <div className="ov2-fp-section">
                                            <h4>Category Breakdown</h4>
                                            <div className="ov2-fp-cats">
                                                {Object.entries(data.digital_footprint.category_breakdown).map(([cat, count]) => (
                                                    <div key={cat} className="ov2-fp-cat">
                                                        <span>{cat}</span><span>{count}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {data.digital_footprint.usernames_used?.length > 0 && (
                                        <div className="ov2-fp-section">
                                            <h4>Usernames Identified</h4>
                                            <div className="ov2-fp-usernames">
                                                {data.digital_footprint.usernames_used.map(u => (
                                                    <span key={u} className="ov2-platform-chip">{u}</span>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {data.digital_footprint.most_active_platforms?.length > 0 && (
                                        <div className="ov2-fp-section">
                                            <h4>Most Active Platforms</h4>
                                            {data.digital_footprint.most_active_platforms.map((p, i) => (
                                                <div key={i} className="ov2-fp-platform">
                                                    <span>{i + 1}. {p.platform}</span>
                                                    <span className="ov2-fp-score">Richness: {p.richness_score}</span>
                                                </div>
                                            ))}
                                        </div>
                                    )}

                                    {data.digital_footprint.name_corroboration_found && (
                                        <div className="ov2-fp-flag green">Name Corroboration Found</div>
                                    )}
                                    {data.digital_footprint.dob_corroboration_found && (
                                        <div className="ov2-fp-flag green">DOB Corroboration Found</div>
                                    )}
                                </div>
                            )}
                        </>
                    )}

                    {/* Empty State */}
                    {!investigationLoading && !hasResults && !data?.error && (
                        <div className="ov2-empty-state">
                            <Shield size={48} />
                            <h2>OSINT Investigation Platform</h2>
                            <p>Fill in the subject profile on the left and click "Begin Investigation".</p>
                            <div className="ov2-capabilities">
                                <div><Search size={14} /> Multi-signal verification across 400+ sites</div>
                                <div><Shield size={14} /> Enterprise confidence scoring (Confirmed / High / Medium / Unverified)</div>
                                <div><Globe size={14} /> India-centric Tier 1 priority with 3-tier ordering</div>
                                <div><User size={14} /> 4 search modes: Username, Full Name, Email, Phone</div>
                                <div><BarChart3 size={14} /> Entity correlation and digital footprint analysis</div>
                                <div><FileText size={14} /> Professional investigation report export (JSON / CSV / PDF)</div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
