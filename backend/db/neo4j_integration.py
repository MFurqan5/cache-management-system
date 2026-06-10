"""Neo4j Graph Database integration for Threat Network visualization"""
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

NEO4J_URL = os.getenv("NEO4J_URL", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "cyberpass123")


class Neo4jIntegration:
    """Handles all Neo4j graph database operations for threat network mapping"""

    def __init__(self):
        self.driver = None
        self._connected = False
        self._connect()

    def _connect(self):
        """Initialize Neo4j driver connection"""
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(
                NEO4J_URL,
                auth=(NEO4J_USER, NEO4J_PASSWORD),
                max_connection_lifetime=300,
            )
            self.driver.verify_connectivity()
            self._connected = True
            logger.info("Neo4j connected at %s", NEO4J_URL)
            self._init_constraints()
        except Exception as e:
            logger.warning("Neo4j connection failed: %s. Graph features disabled.", e)
            self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected and self.driver is not None

    def _init_constraints(self):
        """Create uniqueness constraints and indexes for the graph schema"""
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (u:URL) REQUIRE u.value IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:ThreatType) REQUIRE t.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (i:Indicator) REQUIRE i.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.uid IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (s:Scan) ON (s.scan_id)",
            "CREATE INDEX IF NOT EXISTS FOR (s:Scan) ON (s.timestamp)",
            "CREATE INDEX IF NOT EXISTS FOR (e:Email) ON (e.hash)",
        ]
        try:
            with self.driver.session() as session:
                for cypher in constraints:
                    session.run(cypher)
            logger.info("Neo4j constraints and indexes created")
        except Exception as e:
            logger.warning("Failed to create Neo4j constraints: %s", e)

    @staticmethod
    def _extract_domain(url_string: str) -> Optional[str]:
        """Extract domain name from a URL string"""
        try:
            parsed = urlparse(url_string)
            domain = parsed.netloc or parsed.path
            domain = domain.split(":")[0]
            if domain.startswith("www."):
                domain = domain[4:]
            return domain if domain else None
        except Exception:
            return None

    def save_scan_to_graph(
        self,
        request_id: str,
        user_id: str,
        input_type: str,
        input_value: str,
        prediction: Dict[str, Any],
        model_version: str,
        inference_ms: float,
    ):
        """Save a scan and its relationships to the Neo4j graph.

        Creates the following graph pattern:
          (User)-[:PERFORMED]->(Scan)-[:SCANNED]->(URL|Email)
          (Scan)-[:CLASSIFIED_AS]->(ThreatType)
          (Scan)-[:TRIGGERED]->(Indicator)
          (URL)-[:BELONGS_TO]->(Domain)
        """
        if not self.is_connected:
            return

        try:
            label = prediction.get("label", "safe")
            threat_type = prediction.get("threat_type", "clean")
            confidence = prediction.get("confidence", 0.0)
            explanation = prediction.get("explanation", "")
            indicators = prediction.get("indicators", [])
            timestamp = datetime.utcnow().isoformat()

            with self.driver.session() as session:
                session.run(
                    "MERGE (u:User {uid: $uid})",
                    uid=user_id,
                )
                session.run(
                    """
                    CREATE (s:Scan {
                        scan_id: $scan_id,
                        input_type: $input_type,
                        status: $label,
                        confidence: $confidence,
                        model_version: $model_version,
                        inference_ms: $inference_ms,
                        explanation: $explanation,
                        timestamp: $timestamp
                    })
                    """,
                    scan_id=request_id,
                    input_type=input_type,
                    label=label,
                    confidence=confidence,
                    model_version=model_version,
                    inference_ms=inference_ms,
                    explanation=explanation,
                    timestamp=timestamp,
                )
                session.run(
                    """
                    MATCH (u:User {uid: $uid}), (s:Scan {scan_id: $scan_id})
                    MERGE (u)-[:PERFORMED]->(s)
                    """,
                    uid=user_id,
                    scan_id=request_id,
                )

                if input_type == "url":
                    domain = self._extract_domain(input_value)
                    session.run(
                        """
                        MERGE (url:URL {value: $value})
                        ON CREATE SET url.domain = $domain, url.first_seen = $ts
                        SET url.last_seen = $ts
                        WITH url
                        MATCH (s:Scan {scan_id: $scan_id})
                        MERGE (s)-[:SCANNED]->(url)
                        """,
                        value=input_value[:500],
                        domain=domain or "unknown",
                        ts=timestamp,
                        scan_id=request_id,
                    )
                    if domain:
                        session.run(
                            """
                            MERGE (d:Domain {name: $domain})
                            ON CREATE SET d.first_seen = $ts
                            SET d.last_seen = $ts
                            WITH d
                            MATCH (url:URL {value: $value})
                            MERGE (url)-[:BELONGS_TO]->(d)
                            """,
                            domain=domain,
                            value=input_value[:500],
                            ts=timestamp,
                        )

                elif input_type == "email":
                    import hashlib
                    email_hash = hashlib.sha256(input_value.encode()).hexdigest()
                    session.run(
                        """
                        MERGE (e:Email {hash: $hash})
                        ON CREATE SET e.preview = $preview, e.first_seen = $ts
                        SET e.last_seen = $ts
                        WITH e
                        MATCH (s:Scan {scan_id: $scan_id})
                        MERGE (s)-[:SCANNED]->(e)
                        """,
                        hash=email_hash,
                        preview=input_value[:120],
                        ts=timestamp,
                        scan_id=request_id,
                    )

                elif input_type in ("file", "app"):
                    session.run(
                        """
                        MERGE (f:File {hash: $hash})
                        ON CREATE SET f.name = $name, f.type = $type, f.first_seen = $ts
                        SET f.last_seen = $ts
                        WITH f
                        MATCH (s:Scan {scan_id: $scan_id})
                        MERGE (s)-[:SCANNED]->(f)
                        """,
                        hash=input_value[:64],
                        name=input_value[:200],
                        type=input_type,
                        ts=timestamp,
                        scan_id=request_id,
                    )

                session.run(
                    """
                    MERGE (t:ThreatType {name: $name})
                    WITH t
                    MATCH (s:Scan {scan_id: $scan_id})
                    MERGE (s)-[:CLASSIFIED_AS {confidence: $confidence}]->(t)
                    """,
                    name=threat_type,
                    scan_id=request_id,
                    confidence=confidence,
                )

                for ind in indicators:
                    if ind:
                        session.run(
                            """
                            MERGE (i:Indicator {name: $name})
                            WITH i
                            MATCH (s:Scan {scan_id: $scan_id})
                            MERGE (s)-[:TRIGGERED]->(i)
                            """,
                            name=ind,
                            scan_id=request_id,
                        )

            logger.info("Saved to Neo4j graph: %s (%s)", request_id[:16], input_type)

        except Exception as e:
            logger.warning("Neo4j save failed: %s", e)
    def get_threat_network(
        self, limit: int = 200, threat_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get the threat network graph as nodes + edges for visualization.

        Returns:
            {
              "nodes": [{"id": ..., "label": ..., "type": ..., ...}, ...],
              "edges": [{"source": ..., "target": ..., "type": ...}, ...],
              "stats": {"total_nodes": N, "total_edges": M}
            }
        """
        if not self.is_connected:
            return {"nodes": [], "edges": [], "stats": {"total_nodes": 0, "total_edges": 0}}

        try:
            with self.driver.session() as session:
                where_clause = ""
                params: Dict[str, Any] = {"limit": limit}

                if threat_filter and threat_filter != "all":
                    where_clause = "WHERE s.status = $status OR t.name = $status"
                    params["status"] = threat_filter

                result = session.run(
                    f"""
                    MATCH (s:Scan)-[r]->(target)
                    {where_clause}
                    WITH s, r, target
                    ORDER BY s.timestamp DESC
                    LIMIT $limit
                    RETURN
                        s.scan_id AS scan_id,
                        s.input_type AS scan_type,
                        s.status AS scan_status,
                        s.confidence AS scan_confidence,
                        s.timestamp AS scan_ts,
                        type(r) AS rel_type,
                        labels(target)[0] AS target_label,
                        target AS target_props
                    """,
                    **params,
                )

                nodes_map: Dict[str, Dict] = {}
                edges: List[Dict] = []

                for record in result:
                    scan_id = record["scan_id"]
                    scan_node_id = f"scan_{scan_id[:12]}"
                    if scan_node_id not in nodes_map:
                        nodes_map[scan_node_id] = {
                            "id": scan_node_id,
                            "label": f"{record['scan_type']} scan",
                            "type": "Scan",
                            "status": record["scan_status"],
                            "confidence": record["scan_confidence"],
                            "timestamp": record["scan_ts"],
                        }
                    target_label = record["target_label"]
                    target_props = dict(record["target_props"]) if record["target_props"] else {}
                    target_node_id = self._make_node_id(target_label, target_props)
                    if target_node_id and target_node_id not in nodes_map:
                        nodes_map[target_node_id] = {
                            "id": target_node_id,
                            "label": self._make_node_label(target_label, target_props),
                            "type": target_label,
                            "status": target_props.get("status", target_props.get("name", "")),
                        }
                    if target_node_id:
                        edges.append({
                            "source": scan_node_id,
                            "target": target_node_id,
                            "type": record["rel_type"],
                        })

                domain_result = session.run(
                    """
                    MATCH (url:URL)-[:BELONGS_TO]->(d:Domain)
                    RETURN url.value AS url_val, d.name AS domain_name
                    LIMIT $limit
                    """,
                    limit=limit,
                )
                for record in domain_result:
                    url_id = f"url_{hash(record['url_val']) % 10**8}"
                    domain_id = f"domain_{record['domain_name']}"

                    if url_id not in nodes_map:
                        nodes_map[url_id] = {
                            "id": url_id,
                            "label": record["url_val"][:60],
                            "type": "URL",
                        }
                    if domain_id not in nodes_map:
                        nodes_map[domain_id] = {
                            "id": domain_id,
                            "label": record["domain_name"],
                            "type": "Domain",
                        }
                    edges.append({
                        "source": url_id,
                        "target": domain_id,
                        "type": "BELONGS_TO",
                    })

                nodes = list(nodes_map.values())
                return {
                    "nodes": nodes,
                    "edges": edges,
                    "stats": {
                        "total_nodes": len(nodes),
                        "total_edges": len(edges),
                    },
                }

        except Exception as e:
            logger.error("Neo4j get_threat_network failed: %s", e)
            return {"nodes": [], "edges": [], "stats": {"total_nodes": 0, "total_edges": 0}}

    def get_domain_network(self, domain: str) -> Dict[str, Any]:
        """Get all threats linked to a specific domain"""
        if not self.is_connected:
            return {"nodes": [], "edges": [], "stats": {"total_nodes": 0, "total_edges": 0}}

        try:
            with self.driver.session() as session:
                result = session.run(
                    """
                    MATCH (d:Domain {name: $domain})<-[:BELONGS_TO]-(url:URL)<-[:SCANNED]-(s:Scan)
                    OPTIONAL MATCH (s)-[:CLASSIFIED_AS]->(t:ThreatType)
                    OPTIONAL MATCH (s)-[:TRIGGERED]->(i:Indicator)
                    RETURN d, url, s, t, i
                    LIMIT 300
                    """,
                    domain=domain,
                )

                nodes_map: Dict[str, Dict] = {}
                edges: List[Dict] = []

                for record in result:
                    d = dict(record["d"]) if record["d"] else {}
                    url = dict(record["url"]) if record["url"] else {}
                    s = dict(record["s"]) if record["s"] else {}
                    t = dict(record["t"]) if record["t"] else {}
                    ind = dict(record["i"]) if record["i"] else {}

                    domain_id = f"domain_{domain}"
                    url_id = f"url_{hash(url.get('value', '')) % 10**8}"
                    scan_id = f"scan_{s.get('scan_id', '')[:12]}"

                    if domain_id not in nodes_map:
                        nodes_map[domain_id] = {"id": domain_id, "label": domain, "type": "Domain"}

                    if url.get("value") and url_id not in nodes_map:
                        nodes_map[url_id] = {
                            "id": url_id, "label": url["value"][:60], "type": "URL"
                        }
                        edges.append({"source": url_id, "target": domain_id, "type": "BELONGS_TO"})

                    if s.get("scan_id") and scan_id not in nodes_map:
                        nodes_map[scan_id] = {
                            "id": scan_id,
                            "label": f"{s.get('input_type', '')} scan",
                            "type": "Scan",
                            "status": s.get("status", "safe"),
                            "confidence": s.get("confidence", 0),
                        }
                        if url.get("value"):
                            edges.append({"source": scan_id, "target": url_id, "type": "SCANNED"})

                    if t.get("name"):
                        threat_id = f"threat_{t['name']}"
                        if threat_id not in nodes_map:
                            nodes_map[threat_id] = {"id": threat_id, "label": t["name"], "type": "ThreatType"}
                        edges.append({"source": scan_id, "target": threat_id, "type": "CLASSIFIED_AS"})

                    if ind.get("name"):
                        ind_id = f"ind_{ind['name']}"
                        if ind_id not in nodes_map:
                            nodes_map[ind_id] = {"id": ind_id, "label": ind["name"], "type": "Indicator"}
                        edges.append({"source": scan_id, "target": ind_id, "type": "TRIGGERED"})

                nodes = list(nodes_map.values())
                return {
                    "nodes": nodes,
                    "edges": edges,
                    "stats": {"total_nodes": len(nodes), "total_edges": len(edges)},
                }

        except Exception as e:
            logger.error("Neo4j domain network query failed: %s", e)
            return {"nodes": [], "edges": [], "stats": {"total_nodes": 0, "total_edges": 0}}

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get high-level graph statistics for dashboard cards"""
        if not self.is_connected:
            return {
                "total_nodes": 0, "total_edges": 0,
                "node_counts": {}, "top_domains": [], "top_indicators": [],
            }

        try:
            with self.driver.session() as session:
                node_counts = {}
                for label in ["Scan", "URL", "Email", "File", "Domain", "ThreatType", "Indicator", "User"]:
                    result = session.run(f"MATCH (n:{label}) RETURN count(n) as cnt")
                    node_counts[label] = result.single()["cnt"]

                total_nodes = sum(node_counts.values())

                rel_result = session.run("MATCH ()-[r]->() RETURN count(r) as cnt")
                total_edges = rel_result.single()["cnt"]

                top_domains_result = session.run(
                    """
                    MATCH (d:Domain)<-[:BELONGS_TO]-(url:URL)<-[:SCANNED]-(s:Scan)
                    RETURN d.name AS domain, count(s) AS scan_count
                    ORDER BY scan_count DESC
                    LIMIT 5
                    """
                )
                top_domains = [
                    {"domain": r["domain"], "scan_count": r["scan_count"]}
                    for r in top_domains_result
                ]

                top_indicators_result = session.run(
                    """
                    MATCH (i:Indicator)<-[:TRIGGERED]-(s:Scan)
                    RETURN i.name AS indicator, count(s) AS trigger_count
                    ORDER BY trigger_count DESC
                    LIMIT 5
                    """
                )
                top_indicators = [
                    {"indicator": r["indicator"], "count": r["trigger_count"]}
                    for r in top_indicators_result
                ]

                status_result = session.run(
                    """
                    MATCH (s:Scan)
                    RETURN s.status AS status, count(s) AS cnt
                    """
                )
                status_counts = {r["status"]: r["cnt"] for r in status_result}

                return {
                    "total_nodes": total_nodes,
                    "total_edges": total_edges,
                    "node_counts": node_counts,
                    "status_counts": status_counts,
                    "top_domains": top_domains,
                    "top_indicators": top_indicators,
                }

        except Exception as e:
            logger.error("Neo4j stats query failed: %s", e)
            return {
                "total_nodes": 0, "total_edges": 0,
                "node_counts": {}, "top_domains": [], "top_indicators": [],
            }

    @staticmethod
    def _make_node_id(label: str, props: dict) -> Optional[str]:
        if label == "URL":
            return f"url_{hash(props.get('value', '')) % 10**8}"
        elif label == "Email":
            return f"email_{props.get('hash', 'unknown')[:12]}"
        elif label == "File":
            return f"file_{props.get('hash', 'unknown')[:12]}"
        elif label == "Domain":
            return f"domain_{props.get('name', 'unknown')}"
        elif label == "ThreatType":
            return f"threat_{props.get('name', 'unknown')}"
        elif label == "Indicator":
            return f"ind_{props.get('name', 'unknown')}"
        elif label == "User":
            return f"user_{props.get('uid', 'unknown')[:12]}"
        return None

    @staticmethod
    def _make_node_label(label: str, props: dict) -> str:
        if label == "URL":
            return (props.get("value") or "")[:60]
        elif label == "Email":
            return (props.get("preview") or "email")[:40]
        elif label == "File":
            return (props.get("name") or "file")[:40]
        elif label == "Domain":
            return props.get("name", "")
        elif label == "ThreatType":
            return props.get("name", "")
        elif label == "Indicator":
            return props.get("name", "")
        elif label == "User":
            return f"User {props.get('uid', '')[:8]}"
        return label

    def close(self):
        """Close the Neo4j driver connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j driver closed")


neo4j_db: Optional[Neo4jIntegration] = None

def get_neo4j() -> Optional[Neo4jIntegration]:
    """Get or create the global Neo4j integration instance"""
    global neo4j_db
    if neo4j_db is None:
        try:
            neo4j_db = Neo4jIntegration()
        except Exception as e:
            logger.warning("Failed to initialize Neo4j: %s", e)
    return neo4j_db
