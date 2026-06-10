# backend/routes/graph.py
"""API routes for Neo4j threat network graph visualization"""
from fastapi import APIRouter, Query
from typing import Optional
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/graph", tags=["graph"])


def _get_neo4j():
    """Lazy-load the Neo4j integration instance"""
    from backend.db.neo4j_integration import get_neo4j
    return get_neo4j()


@router.get("/network")
async def get_threat_network(
    limit: int = Query(200, ge=10, le=1000),
    threat_filter: Optional[str] = Query(None, description="Filter by threat status: malicious, safe, or all"),
):
    """Get full threat network graph (nodes + edges) for visualization.

    Returns nodes (Scans, URLs, Emails, Domains, ThreatTypes, Indicators)
    and edges (relationships between them) for rendering in react-force-graph.
    """
    neo4j = _get_neo4j()
    if not neo4j or not neo4j.is_connected:
        return {
            "nodes": [], "edges": [],
            "stats": {"total_nodes": 0, "total_edges": 0},
            "neo4j_status": "disconnected",
        }

    data = neo4j.get_threat_network(limit=limit, threat_filter=threat_filter)
    data["neo4j_status"] = "connected"
    return data


@router.get("/network/domain/{domain}")
async def get_domain_network(domain: str):
    """Get threat subgraph for a specific domain.

    Shows all URLs belonging to the domain, all scans of those URLs,
    and their associated threat types and indicators.
    """
    neo4j = _get_neo4j()
    if not neo4j or not neo4j.is_connected:
        return {
            "nodes": [], "edges": [],
            "stats": {"total_nodes": 0, "total_edges": 0},
            "neo4j_status": "disconnected",
        }

    data = neo4j.get_domain_network(domain)
    data["neo4j_status"] = "connected"
    return data


@router.get("/stats")
async def get_graph_stats():
    """Get high-level graph statistics.

    Returns total node/edge counts, node counts by type,
    top domains, and top indicators.
    """
    neo4j = _get_neo4j()
    if not neo4j or not neo4j.is_connected:
        return {
            "total_nodes": 0, "total_edges": 0,
            "node_counts": {}, "top_domains": [], "top_indicators": [],
            "neo4j_status": "disconnected",
        }

    data = neo4j.get_graph_stats()
    data["neo4j_status"] = "connected"
    return data


@router.get("/health")
async def graph_health():
    """Check Neo4j connection health"""
    neo4j = _get_neo4j()
    connected = neo4j.is_connected if neo4j else False

    return {
        "neo4j": "connected" if connected else "disconnected",
        "status": "healthy" if connected else "unavailable",
    }
