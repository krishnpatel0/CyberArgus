/* eslint-disable react-refresh/only-export-components -- provider and hook form one public context API */
import React, { createContext, useContext, useState, useCallback } from 'react';

const SearchContext = createContext(null);

export const useSearchContext = () => {
    const ctx = useContext(SearchContext);
    if (!ctx) throw new Error('useSearchContext must be used within SearchProvider');
    return ctx;
};

export const SearchProvider = ({ children }) => {
    // Breach module state persistence
    const [breachResults, setBreachResults] = useState(null);
    const [breachFilters, setBreachFilters] = useState([]);
    const [breachStatus, setBreachStatus] = useState(null);

    // OSINT module state persistence (legacy v1)
    const [osintTarget, setOsintTarget] = useState('');
    const [osintResults, setOsintResults] = useState(null);
    const [osintLoading, setOsintLoading] = useState(false);
    const [osintInputType, setOsintInputType] = useState('USERNAME');
    const [osintGraphData, setOsintGraphData] = useState(null);
    const [osintRecursive, setOsintRecursive] = useState(false);

    // OSINT v2 Investigation Platform state
    const [investigationProfile, setInvestigationProfile] = useState(null);
    const [investigationResult, setInvestigationResult] = useState(null);
    const [investigationLoading, setInvestigationLoading] = useState(false);
    const [investigationProgress, setInvestigationProgress] = useState(null);
    const [discardedResults, setDiscardedResults] = useState(new Set());
    const [investigatorNotes, setInvestigatorNotes] = useState({});

    // Auto-save session data
    const saveSession = useCallback(() => {
        if (investigationResult) {
            try {
                const sessionData = {
                    profile: investigationProfile,
                    result: investigationResult,
                    discarded: [...discardedResults],
                    notes: investigatorNotes,
                    savedAt: new Date().toISOString(),
                };
                sessionStorage.setItem('osint_investigation_session', JSON.stringify(sessionData));
            } catch (e) {
                console.warn('Failed to save session:', e);
            }
        }
    }, [investigationResult, investigationProfile, discardedResults, investigatorNotes]);

    const restoreSession = useCallback(() => {
        try {
            const raw = sessionStorage.getItem('osint_investigation_session');
            if (raw) {
                const data = JSON.parse(raw);
                if (data.profile) setInvestigationProfile(data.profile);
                if (data.result) setInvestigationResult(data.result);
                if (data.discarded) setDiscardedResults(new Set(data.discarded));
                if (data.notes) setInvestigatorNotes(data.notes);
                return true;
            }
        } catch (e) {
            console.warn('Failed to restore session:', e);
        }
        return false;
    }, []);

    // Cross-module: launch OSINT from breach
    const [pendingOsintUsername, setPendingOsintUsername] = useState(null);

    const launchOsintFromBreach = useCallback((username) => {
        setPendingOsintUsername(username);
        setOsintTarget(username);
    }, []);

    const consumePendingOsint = useCallback(() => {
        const username = pendingOsintUsername;
        setPendingOsintUsername(null);
        return username;
    }, [pendingOsintUsername]);

    return (
        <SearchContext.Provider value={{
            breachResults, setBreachResults,
            breachFilters, setBreachFilters,
            breachStatus, setBreachStatus,
            osintTarget, setOsintTarget,
            osintResults, setOsintResults,
            osintLoading, setOsintLoading,
            osintInputType, setOsintInputType,
            osintGraphData, setOsintGraphData,
            osintRecursive, setOsintRecursive,
            // v2 Investigation state
            investigationProfile, setInvestigationProfile,
            investigationResult, setInvestigationResult,
            investigationLoading, setInvestigationLoading,
            investigationProgress, setInvestigationProgress,
            discardedResults, setDiscardedResults,
            investigatorNotes, setInvestigatorNotes,
            saveSession, restoreSession,
            // Cross-module
            pendingOsintUsername,
            launchOsintFromBreach,
            consumePendingOsint,
        }}>
            {children}
        </SearchContext.Provider>
    );
};
