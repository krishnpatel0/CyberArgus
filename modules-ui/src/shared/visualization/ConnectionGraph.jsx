import React, { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { forceCollide } from 'd3-force-3d';
import ForceGraph2D from 'react-force-graph-2d';
import {
    X,
    Maximize2,
    Download,
    Mail,
    Phone,
    User,
    MapPin,
    AlertCircle,
    Eye,
    EyeOff,
    Layers,
    Crosshair,
} from 'lucide-react';
import './ConnectionGraph.css';

const NODE_COLORS = {
    SEED_RECORD: '#FF3B3B',
    RECORD_D1: '#FF8C00',
    RECORD_D2: '#FFD700',
    EMAIL: '#00B4FF',
    PHONE: '#00E676',
    NAME: '#E040FB',
    ADDRESS: '#FF6D00',
};

const NODE_GLOW = {
    SEED_RECORD: 'rgba(255, 59, 59, 0.35)',
    RECORD_D1: 'rgba(255, 140, 0, 0.25)',
    RECORD_D2: 'rgba(255, 215, 0, 0.2)',
    EMAIL: 'rgba(0, 180, 255, 0.25)',
    PHONE: 'rgba(0, 230, 118, 0.25)',
    NAME: 'rgba(224, 64, 251, 0.25)',
    ADDRESS: 'rgba(255, 109, 0, 0.25)',
};

const EDGE_COLORS = {
    HAS_EMAIL: 'rgba(0, 180, 255, 0.4)',
    HAS_PHONE: 'rgba(0, 230, 118, 0.4)',
    HAS_NAME: 'rgba(224, 64, 251, 0.4)',
    HAS_ADDRESS: 'rgba(255, 109, 0, 0.4)',
    DEFAULT: 'rgba(255, 255, 255, 0.08)'
};

const EDGE_HIGHLIGHT = {
    HAS_EMAIL: '#00B4FF',
    HAS_PHONE: '#00E676',
    HAS_NAME: '#E040FB',
    HAS_ADDRESS: '#FF6D00',
    DEFAULT: 'rgba(255, 255, 255, 0.3)'
};

const NODE_OBJECTS = {
    RECORD: 'person',
    EMAIL: 'envelope',
    PHONE: 'phone',
    NAME: 'badge',
    ADDRESS: 'pin',
};

const LEGEND_ITEMS = [
    { label: 'Seed Person', color: NODE_COLORS.SEED_RECORD, icon: User },
    { label: '1st Degree Person', color: NODE_COLORS.RECORD_D1, icon: User },
    { label: '2nd Degree Person', color: NODE_COLORS.RECORD_D2, icon: User },
    { label: 'Email', color: NODE_COLORS.EMAIL, icon: Mail },
    { label: 'Phone', color: NODE_COLORS.PHONE, icon: Phone },
    { label: 'Name', color: NODE_COLORS.NAME, icon: User },
    { label: 'Address', color: NODE_COLORS.ADDRESS, icon: MapPin },
];

const toSafeText = (value, fallback = '') => {
    if (typeof value === 'string') return value;
    if (value === null || value === undefined) return fallback;
    return String(value);
};

const sanitizeNode = (node, index) => {
    if (!node || (node.id === null || node.id === undefined)) return null;

    const id = toSafeText(node.id, `node-${index}`);
    const value = toSafeText(node.value, id);
    const label = toSafeText(node.label, value);
    const degree = Number.isFinite(Number(node.degree)) ? Number(node.degree) : 0;

    return {
        ...node,
        id,
        type: toSafeText(node.type, 'RECORD'),
        value,
        label,
        degree,
        is_seed: Boolean(node.is_seed),
    };
};

const extractLinkEndpoint = (endpoint) => {
    if (typeof endpoint === 'string' || typeof endpoint === 'number') return String(endpoint);
    if (endpoint && (typeof endpoint.id === 'string' || typeof endpoint.id === 'number')) return String(endpoint.id);
    return null;
};

const sanitizeEdge = (edge, index) => {
    if (!edge) return null;

    const source = extractLinkEndpoint(edge.source);
    const target = extractLinkEndpoint(edge.target);
    if (!source || !target) return null;

    return {
        ...edge,
        id: toSafeText(edge.id, `${source}-${target}-${index}`),
        source,
        target,
        relationship: toSafeText(edge.relationship, 'DEFAULT'),
        shared_value: toSafeText(edge.shared_value, ''),
    };
};

// ─── Canvas shape drawers ───

// ─── Component ───

function drawRoundedRectPath(ctx, x, y, width, height, radius) {
    const halfW = width / 2;
    const halfH = height / 2;
    const cr = Math.min(radius, halfW, halfH);
    ctx.beginPath();
    ctx.moveTo(x - halfW + cr, y - halfH);
    ctx.lineTo(x + halfW - cr, y - halfH);
    ctx.quadraticCurveTo(x + halfW, y - halfH, x + halfW, y - halfH + cr);
    ctx.lineTo(x + halfW, y + halfH - cr);
    ctx.quadraticCurveTo(x + halfW, y + halfH, x + halfW - cr, y + halfH);
    ctx.lineTo(x - halfW + cr, y + halfH);
    ctx.quadraticCurveTo(x - halfW, y + halfH, x - halfW, y + halfH - cr);
    ctx.lineTo(x - halfW, y - halfH + cr);
    ctx.quadraticCurveTo(x - halfW, y - halfH, x - halfW + cr, y - halfH);
    ctx.closePath();
}

function drawPersonObject(ctx, x, y, r, color, detailColor) {
    const headRadius = r * 0.38;

    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(x, y - r * 0.58, headRadius, 0, 2 * Math.PI);
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(x - r * 0.92, y + r * 0.95);
    ctx.quadraticCurveTo(x - r * 0.98, y + r * 0.08, x - r * 0.12, y + r * 0.02);
    ctx.lineTo(x + r * 0.12, y + r * 0.02);
    ctx.quadraticCurveTo(x + r * 0.98, y + r * 0.08, x + r * 0.92, y + r * 0.95);
    ctx.closePath();
    ctx.fill();

    ctx.strokeStyle = detailColor;
    ctx.lineWidth = Math.max(1, r * 0.12);
    ctx.beginPath();
    ctx.moveTo(x - r * 0.32, y + r * 0.24);
    ctx.quadraticCurveTo(x, y - r * 0.05, x + r * 0.32, y + r * 0.24);
    ctx.stroke();
}

function drawEnvelopeObject(ctx, x, y, r, color, detailColor) {
    const width = r * 2.15;
    const height = r * 1.45;
    drawRoundedRectPath(ctx, x, y, width, height, r * 0.24);
    ctx.fillStyle = color;
    ctx.fill();

    ctx.strokeStyle = detailColor;
    ctx.lineWidth = Math.max(1, r * 0.14);
    ctx.beginPath();
    ctx.moveTo(x - width * 0.38, y - height * 0.18);
    ctx.lineTo(x, y + height * 0.16);
    ctx.lineTo(x + width * 0.38, y - height * 0.18);
    ctx.moveTo(x - width * 0.42, y + height * 0.32);
    ctx.lineTo(x - width * 0.08, y + height * 0.02);
    ctx.moveTo(x + width * 0.42, y + height * 0.32);
    ctx.lineTo(x + width * 0.08, y + height * 0.02);
    ctx.stroke();
}

function drawPhoneObject(ctx, x, y, r, color, detailColor) {
    const width = r * 1.18;
    const height = r * 2.05;
    drawRoundedRectPath(ctx, x, y, width, height, r * 0.3);
    ctx.fillStyle = color;
    ctx.fill();

    drawRoundedRectPath(ctx, x, y + r * 0.04, width * 0.74, height * 0.62, r * 0.12);
    ctx.fillStyle = 'rgba(5, 8, 17, 0.18)';
    ctx.fill();

    ctx.strokeStyle = detailColor;
    ctx.lineWidth = Math.max(1, r * 0.12);
    ctx.beginPath();
    ctx.moveTo(x - width * 0.14, y - height * 0.31);
    ctx.lineTo(x + width * 0.14, y - height * 0.31);
    ctx.stroke();

    ctx.fillStyle = detailColor;
    ctx.beginPath();
    ctx.arc(x, y + height * 0.31, r * 0.1, 0, 2 * Math.PI);
    ctx.fill();
}

function drawBadgeObject(ctx, x, y, r, color, detailColor) {
    const width = r * 2.05;
    const height = r * 1.42;
    drawRoundedRectPath(ctx, x, y, width, height, r * 0.22);
    ctx.fillStyle = color;
    ctx.fill();

    ctx.fillStyle = detailColor;
    ctx.beginPath();
    ctx.arc(x - width * 0.22, y - height * 0.04, r * 0.2, 0, 2 * Math.PI);
    ctx.fill();

    ctx.beginPath();
    ctx.moveTo(x - width * 0.42, y + height * 0.31);
    ctx.quadraticCurveTo(x - width * 0.22, y + height * 0.06, x - width * 0.02, y + height * 0.31);
    ctx.lineTo(x - width * 0.42, y + height * 0.31);
    ctx.fill();

    ctx.strokeStyle = detailColor;
    ctx.lineWidth = Math.max(1, r * 0.12);
    ctx.beginPath();
    ctx.moveTo(x + width * 0.02, y - height * 0.18);
    ctx.lineTo(x + width * 0.32, y - height * 0.18);
    ctx.moveTo(x + width * 0.02, y + height * 0.02);
    ctx.lineTo(x + width * 0.38, y + height * 0.02);
    ctx.moveTo(x + width * 0.02, y + height * 0.22);
    ctx.lineTo(x + width * 0.26, y + height * 0.22);
    ctx.stroke();
}

function drawPinObject(ctx, x, y, r, color, detailColor) {
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.moveTo(x, y + r * 1.18);
    ctx.bezierCurveTo(x + r * 0.86, y + r * 0.38, x + r * 0.82, y - r * 0.86, x, y - r * 0.94);
    ctx.bezierCurveTo(x - r * 0.82, y - r * 0.86, x - r * 0.86, y + r * 0.38, x, y + r * 1.18);
    ctx.closePath();
    ctx.fill();

    ctx.fillStyle = detailColor;
    ctx.beginPath();
    ctx.arc(x, y - r * 0.18, r * 0.28, 0, 2 * Math.PI);
    ctx.fill();
}

function drawNodeObject(ctx, objectType, x, y, r, color, detailColor) {
    switch (objectType) {
        case 'envelope':
            drawEnvelopeObject(ctx, x, y, r, color, detailColor);
            break;
        case 'phone':
            drawPhoneObject(ctx, x, y, r, color, detailColor);
            break;
        case 'badge':
            drawBadgeObject(ctx, x, y, r, color, detailColor);
            break;
        case 'pin':
            drawPinObject(ctx, x, y, r, color, detailColor);
            break;
        case 'person':
        default:
            drawPersonObject(ctx, x, y, r, color, detailColor);
            break;
    }
}

const ConnectionGraph = ({ graphData, height = 600, onRecenter }) => {
    const fgRef = useRef();
    const [selectedNode, setSelectedNode] = useState(null);
    const [hoveredNode, setHoveredNode] = useState(null);
    const [showRecords, setShowRecords] = useState(true);
    const [showEntities, setShowEntities] = useState(true);
    const [showDegree2, setShowDegree2] = useState(true);
    const [showLegend, setShowLegend] = useState(true);
    const rawNodes = useMemo(() => (graphData?.nodes ?? []).map(sanitizeNode).filter(Boolean), [graphData]);
    const rawEdges = useMemo(() => ((graphData?.edges ?? graphData?.links ?? []).map(sanitizeEdge).filter(Boolean)), [graphData]);

    const filteredData = useMemo(() => {
        if (!graphData) return { nodes: [], links: [] };

        const visibleNodes = rawNodes.filter(node => {
            if (node.type === 'RECORD') {
                if (!showRecords) return false;
                if (!showDegree2 && node.degree > 1) return false;
                return true;
            }
            return showEntities;
        });

        const nodeIds = new Set(visibleNodes.map(n => n.id));
        const visibleLinks = rawEdges.filter(link =>
            nodeIds.has(link.source?.id || link.source) && nodeIds.has(link.target?.id || link.target)
        );

        return { nodes: visibleNodes, links: visibleLinks };
    }, [graphData, rawNodes, rawEdges, showRecords, showEntities, showDegree2]);

    const handleNodeClick = useCallback(node => {
        setSelectedNode(node);
        if (fgRef.current && Number.isFinite(node?.x) && Number.isFinite(node?.y)) {
            fgRef.current.centerAt(node.x, node.y, 500);
            fgRef.current.zoom(2.5, 500);
        }
    }, []);

    const handleExport = useCallback(() => {
        if (!fgRef.current?.toDataURL) return;
        const link = document.createElement('a');
        link.download = `graph_export_${new Date().getTime()}.png`;
        link.href = fgRef.current.toDataURL();
        link.click();
    }, []);

    const getNodeColor = useCallback(node => {
        if (node.type === 'RECORD') {
            if (node.is_seed) return NODE_COLORS.SEED_RECORD;
            if (node.degree === 1) return NODE_COLORS.RECORD_D1;
            return NODE_COLORS.RECORD_D2;
        }
        return NODE_COLORS[node.type] || '#CCCCCC';
    }, []);

    const getNodeGlow = useCallback(node => {
        if (node.type === 'RECORD') {
            if (node.is_seed) return NODE_GLOW.SEED_RECORD;
            if (node.degree === 1) return NODE_GLOW.RECORD_D1;
            return NODE_GLOW.RECORD_D2;
        }
        return NODE_GLOW[node.type] || 'rgba(255,255,255,0.1)';
    }, []);

    const getNodeSize = useCallback(node => {
        if (node.type === 'RECORD') {
            if (node.is_seed) return 14;
            if (node.degree === 1) return 9;
            return 7;
        }
        return 8;
    }, []);

    const getNodeObject = useCallback(node => {
        if (node.type === 'RECORD') return NODE_OBJECTS.RECORD;
        return NODE_OBJECTS[node.type] || NODE_OBJECTS.RECORD;
    }, []);

    const layoutMetrics = useMemo(() => {
        const nodeCount = filteredData.nodes.length;
        return {
            linkDistance: Math.min(105, 62 + Math.sqrt(Math.max(nodeCount, 1)) * 2),
            chargeStrength: -Math.min(650, 220 + nodeCount * 4),
        };
    }, [filteredData.nodes.length]);

    const getCollisionRadius = useCallback(node => {
        const label = toSafeText(node?.label, toSafeText(node?.value, toSafeText(node?.id)));
        const labelRadius = 18 + Math.min(label.length, 22) * 0.85;
        return Math.max(getNodeSize(node) + 10, labelRadius);
    }, [getNodeSize]);

    useEffect(() => {
        const graph = fgRef.current;
        if (!graph || filteredData.nodes.length === 0) return undefined;

        graph.d3Force('charge')
            ?.strength(layoutMetrics.chargeStrength)
            .distanceMax(layoutMetrics.linkDistance * 8);
        graph.d3Force('link')
            ?.distance(link => (
                link.relationship === 'HAS_ADDRESS'
                    ? layoutMetrics.linkDistance * 1.15
                    : layoutMetrics.linkDistance
            ))
            .strength(0.48);
        graph.d3Force(
            'collide',
            forceCollide(getCollisionRadius)
                .strength(0.92)
                .iterations(3),
        );
        graph.d3ReheatSimulation();

        const fitTimer = window.setTimeout(() => {
            graph.zoomToFit?.(700, 90);
        }, 900);

        return () => window.clearTimeout(fitTimer);
    }, [filteredData.nodes, getCollisionRadius, layoutMetrics]);

    const stats = useMemo(() => {
        if (!graphData) return { records: 0, emails: 0, phones: 0, names: 0, addresses: 0 };
        return rawNodes.reduce((acc, node) => {
            if (node.type === 'RECORD') acc.records++;
            else if (node.type === 'EMAIL') acc.emails++;
            else if (node.type === 'PHONE') acc.phones++;
            else if (node.type === 'NAME') acc.names++;
            else if (node.type === 'ADDRESS') acc.addresses++;
            return acc;
        }, { records: 0, emails: 0, phones: 0, names: 0, addresses: 0 });
    }, [graphData, rawNodes]);

    // Check if a node is connected to hovered node
    const isConnectedToHovered = useCallback((nodeId) => {
        if (!hoveredNode || !graphData) return false;
        return rawEdges.some(e => {
            const src = e.source?.id || e.source;
            const tgt = e.target?.id || e.target;
            return (src === hoveredNode.id && tgt === nodeId) || (tgt === hoveredNode.id && src === nodeId);
        });
    }, [hoveredNode, graphData, rawEdges]);

    if (!graphData) return null;

    if (rawNodes.length === 0) {
        return (
            <div className="connection-graph-wrapper">
                <div
                    style={{
                        minHeight: height,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'var(--color-text-secondary)',
                        padding: '2rem',
                        textAlign: 'center',
                    }}
                >
                    No graph nodes were returned for this query. Try a more specific seed or a record with email/phone/name data.
                </div>
            </div>
        );
    }

    return (
        <div className="connection-graph-wrapper">
            {/* Control Bar */}
            <div className="graph-controls-bar">
                <div className="controls-group">
                    <button
                        className={`control-pill ${showRecords ? 'active' : ''}`}
                        onClick={() => setShowRecords(!showRecords)}
                    >
                        {showRecords ? <Eye size={13} /> : <EyeOff size={13} />}
                        <span>Records</span>
                        <span className="pill-count">{stats.records}</span>
                    </button>
                    <button
                        className={`control-pill ${showEntities ? 'active' : ''}`}
                        onClick={() => setShowEntities(!showEntities)}
                    >
                        {showEntities ? <Eye size={13} /> : <EyeOff size={13} />}
                        <span>Entities</span>
                        <span className="pill-count">{stats.emails + stats.phones + stats.names + stats.addresses}</span>
                    </button>
                    <button
                        className={`control-pill ${showDegree2 ? 'active' : ''}`}
                        onClick={() => setShowDegree2(!showDegree2)}
                    >
                        <Layers size={13} />
                        <span>Depth {showDegree2 ? '2' : '1'}</span>
                    </button>
                </div>

                <div className="controls-group">
                    <div className="stats-badges">
                        <span className="badge email"><Mail size={10} /> {stats.emails}</span>
                        <span className="badge phone"><Phone size={10} /> {stats.phones}</span>
                        <span className="badge name"><User size={10} /> {stats.names}</span>
                        {stats.addresses > 0 && (
                            <span className="badge address"><MapPin size={10} /> {stats.addresses}</span>
                        )}
                    </div>
                    <div className="control-divider" />
                    <button className="icon-btn" onClick={() => setShowLegend(!showLegend)} title="Toggle Legend">
                        <Crosshair size={16} />
                    </button>
                    <button className="icon-btn" onClick={handleExport} title="Export PNG">
                        <Download size={16} />
                    </button>
                    <button className="icon-btn" onClick={() => fgRef.current?.zoomToFit?.(400, 50)} title="Fit Screen">
                        <Maximize2 size={16} />
                    </button>
                </div>
            </div>

            {/* Legend */}
            {showLegend && (
                <div className="graph-legend">
                    {LEGEND_ITEMS.map((item, i) => (
                        <div key={i} className="legend-item">
                            <span className="legend-icon-wrap" style={{ '--swatch-color': item.color }}>
                                <item.icon size={11} />
                            </span>
                            <span className="legend-label">{item.label}</span>
                        </div>
                    ))}
                </div>
            )}

            <div className="graph-canvas-container" style={{ height }}>
                <ForceGraph2D
                    ref={fgRef}
                    graphData={filteredData}
                    backgroundColor="rgba(0,0,0,0)"
                    nodeRelSize={1}
                    nodeVal={getNodeSize}
                    nodeColor={getNodeColor}
                    linkColor={link => {
                        if (hoveredNode) {
                            const src = link.source?.id || link.source;
                            const tgt = link.target?.id || link.target;
                            if (src === hoveredNode.id || tgt === hoveredNode.id) {
                                return EDGE_HIGHLIGHT[link.relationship] || EDGE_HIGHLIGHT.DEFAULT;
                            }
                        }
                        return EDGE_COLORS[link.relationship] || EDGE_COLORS.DEFAULT;
                    }}
                    linkWidth={link => {
                        if (hoveredNode) {
                            const src = link.source?.id || link.source;
                            const tgt = link.target?.id || link.target;
                            if (src === hoveredNode.id || tgt === hoveredNode.id) return 2.5;
                        }
                        return 0.8;
                    }}
                    linkDirectionalParticles={2}
                    linkDirectionalParticleWidth={2}
                    linkDirectionalParticleSpeed={0.004}
                    linkDirectionalParticleColor={link => EDGE_HIGHLIGHT[link.relationship] || '#ffffff'}
                    linkCurvature={0.1}
                    linkLabel={link => toSafeText(link.relationship, 'RELATED TO').replaceAll('_', ' ')}
                    linkDirectionalArrowLength={3.5}
                    linkDirectionalArrowRelPos={0.78}
                    linkDirectionalArrowColor={link => EDGE_HIGHLIGHT[link.relationship] || '#ffffff'}
                    d3AlphaDecay={0.016}
                    d3VelocityDecay={0.26}
                    warmupTicks={100}
                    cooldownTicks={280}
                    onNodeClick={handleNodeClick}
                    onNodeRightClick={onRecenter ? (node) => onRecenter(node) : null}
                    onNodeHover={setHoveredNode}
                    nodeCanvasObjectMode={() => 'replace'}
                    nodeCanvasObject={(node, ctx, globalScale) => {
                        if (!Number.isFinite(node?.x) || !Number.isFinite(node?.y)) return;
                        const size = getNodeSize(node);
                        const color = getNodeColor(node);
                        const glow = getNodeGlow(node);
                        const objectType = getNodeObject(node);
                        const isHovered = node === hoveredNode;
                        const isSelected = node === selectedNode;
                        const isNeighbor = hoveredNode && isConnectedToHovered(node.id);
                        const isHighlighted = isHovered || isSelected || isNeighbor;
                        const dimmed = hoveredNode && !isHighlighted;
                        const scale = globalScale > 0 ? globalScale : 1;
                        const detailColor = dimmed ? 'rgba(5, 8, 17, 0.35)' : 'rgba(5, 8, 17, 0.58)';

                        // Outer glow
                        if (isHighlighted || node.is_seed) {
                            const glowRadius = size * (isHovered ? 3.5 : 2.5);
                            const gradient = ctx.createRadialGradient(node.x, node.y, size * 0.5, node.x, node.y, glowRadius);
                            gradient.addColorStop(0, glow);
                            gradient.addColorStop(1, 'transparent');
                            ctx.beginPath();
                            ctx.arc(node.x, node.y, glowRadius, 0, 2 * Math.PI);
                            ctx.fillStyle = gradient;
                            ctx.fill();
                        }

                        // Node object
                        ctx.globalAlpha = dimmed ? 0.25 : 1;
                        drawNodeObject(ctx, objectType, node.x, node.y, size, color, detailColor);

                        // Orbit ring for selected/hovered
                        if (isHovered || isSelected) {
                            ctx.beginPath();
                            ctx.arc(node.x, node.y, size * 1.3, 0, 2 * Math.PI);
                            ctx.strokeStyle = '#FFFFFF';
                            ctx.lineWidth = 1.8 / scale;
                            ctx.stroke();
                        }

                        // Seed ring
                        if (node.is_seed) {
                            ctx.beginPath();
                            ctx.arc(node.x, node.y, size * 1.08, 0, 2 * Math.PI);
                            ctx.strokeStyle = 'rgba(255,255,255,0.5)';
                            ctx.lineWidth = 1 / scale;
                            ctx.stroke();
                        }

                        ctx.globalAlpha = 1;

                        // Label
                        if (globalScale > 0.8 || isHighlighted) {
                            const fontSize = Math.min(14 / scale, 12);
                            const rawLabel = toSafeText(node.label, toSafeText(node.value, toSafeText(node.id)));
                            const label = rawLabel.length > 22 ? rawLabel.substring(0, 20) + '..' : rawLabel;
                            ctx.font = `600 ${fontSize}px Inter, system-ui, sans-serif`;
                            ctx.textAlign = 'center';
                            ctx.textBaseline = 'top';

                            // Label background
                            const textWidth = ctx.measureText(label).width;
                            const bgPadX = 4;
                            const bgPadY = 2;
                            const labelY = node.y + size + 4;

                            ctx.fillStyle = 'rgba(5, 8, 17, 0.75)';
                            ctx.beginPath();
                            const bgX = node.x - textWidth / 2 - bgPadX;
                            const bgY = labelY - bgPadY;
                            const bgW = textWidth + bgPadX * 2;
                            const bgH = fontSize + bgPadY * 2;
                            const bgR = 3;
                            ctx.moveTo(bgX + bgR, bgY);
                            ctx.lineTo(bgX + bgW - bgR, bgY);
                            ctx.quadraticCurveTo(bgX + bgW, bgY, bgX + bgW, bgY + bgR);
                            ctx.lineTo(bgX + bgW, bgY + bgH - bgR);
                            ctx.quadraticCurveTo(bgX + bgW, bgY + bgH, bgX + bgW - bgR, bgY + bgH);
                            ctx.lineTo(bgX + bgR, bgY + bgH);
                            ctx.quadraticCurveTo(bgX, bgY + bgH, bgX, bgY + bgH - bgR);
                            ctx.lineTo(bgX, bgY + bgR);
                            ctx.quadraticCurveTo(bgX, bgY, bgX + bgR, bgY);
                            ctx.fill();

                            ctx.fillStyle = dimmed ? 'rgba(255,255,255,0.3)' : 'rgba(255, 255, 255, 0.9)';
                            ctx.fillText(label, node.x, labelY);
                        }

                        // Warning icon
                        if (node.warning) {
                            const wSize = 8 / scale;
                            ctx.fillStyle = '#ef4444';
                            ctx.beginPath();
                            ctx.arc(node.x + size + 2, node.y - size - 2, wSize, 0, 2 * Math.PI);
                            ctx.fill();
                            ctx.fillStyle = '#fff';
                            ctx.font = `bold ${wSize * 1.4}px sans-serif`;
                            ctx.textAlign = 'center';
                            ctx.textBaseline = 'middle';
                            ctx.fillText('!', node.x + size + 2, node.y - size - 2);
                        }
                    }}
                />

                {/* Info Panel Overlay */}
                {selectedNode && (
                    <div className="graph-info-panel fade-in">
                        <div className="panel-header">
                            <div className="header-title">
                                <div className="header-icon-wrap" style={{ '--icon-color': getNodeColor(selectedNode) }}>
                                    {selectedNode.type === 'RECORD' ? <User size={16} /> :
                                     selectedNode.type === 'EMAIL' ? <Mail size={16} /> :
                                     selectedNode.type === 'PHONE' ? <Phone size={16} /> :
                                     selectedNode.type === 'NAME' ? <User size={16} /> : <MapPin size={16} />}
                                </div>
                                <div>
                                    <h4>{selectedNode.type === 'RECORD' ? 'PERSON' : selectedNode.type}</h4>
                                    <span className="header-sub">
                                        {selectedNode.type === 'RECORD' ? `Degree ${selectedNode.degree}` : 'Investigative Entity'}
                                    </span>
                                </div>
                            </div>
                            <button onClick={() => setSelectedNode(null)} className="close-btn"><X size={16} /></button>
                        </div>

                        <div className="panel-content">
                            <div className="info-main">
                                <label>Value</label>
                                <div className="value-box">{selectedNode.value}</div>
                                {selectedNode.warning && (
                                    <div className="warning-banner">
                                        <AlertCircle size={14} /> {selectedNode.warning}
                                    </div>
                                )}
                            </div>

                            {selectedNode.type === 'RECORD' && selectedNode.record_data ? (
                                <div className="record-details">
                                    <label>Source File</label>
                                    <div className="source-badge">{selectedNode.source_file}</div>
                                    <label style={{ marginTop: '1rem' }}>Attributes</label>
                                    <div className="data-grid">
                                        {Object.entries(selectedNode.record_data).map(([key, val]) => (
                                            val && typeof val !== 'object' && (
                                                <div key={key} className="data-item">
                                                    <span className="key">{key}</span>
                                                    <span className="val">{String(val)}</span>
                                                </div>
                                            )
                                        ))}
                                    </div>
                                </div>
                            ) : (
                                <div className="entity-stats">
                                    <div className="degree-badge-row">
                                        <div className="degree-indicator" style={{ '--deg-color': getNodeColor(selectedNode) }}>
                                            Degree {selectedNode.degree}
                                        </div>
                                        <div className="type-indicator">{selectedNode.type}</div>
                                    </div>
                                    {onRecenter && (
                                        <button
                                            className="recenter-btn"
                                            onClick={() => onRecenter(selectedNode)}
                                        >
                                            <Crosshair size={14} />
                                            Re-center Graph
                                        </button>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ConnectionGraph;
