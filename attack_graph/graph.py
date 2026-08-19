"""Attack Graph - NetworkX-based visualization of attack paths."""

from dataclasses import dataclass, field
from typing import Any, Optional
from uuid import UUID, uuid4

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


@dataclass
class GraphNode:
    """A node in the attack graph."""

    id: UUID = field(default_factory=uuid4)
    label: str = ""
    node_type: str = "host"  # host, service, vulnerability, credential, objective
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """An edge in the attack graph."""

    source: UUID
    target: UUID
    edge_type: str = "discovered"  # discovered, exploited, pivoted, credential
    evidence_id: Optional[UUID] = None
    properties: dict[str, Any] = field(default_factory=dict)


class AttackGraph:
    """NetworkX-based attack graph for tracking attack paths."""

    def __init__(self):
        self._nodes: dict[UUID, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        if HAS_NETWORKX:
            self._graph = nx.DiGraph()
        else:
            self._graph = None

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph."""
        if self._graph:
            self._graph.add_node(
                node.id,
                label=node.label,
                node_type=node.node_type,
                **node.properties,
            )
        else:
            self._nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph."""
        if self._graph:
            self._graph.add_edge(
                edge.source,
                edge.target,
                edge_type=edge.edge_type,
                evidence_id=edge.evidence_id,
                **edge.properties,
            )
        else:
            self._edges.append(edge)

    def get_node(self, node_id: UUID) -> Optional[GraphNode]:
        """Get a node by ID."""
        if self._graph and node_id in self._graph:
            data = self._graph.nodes[node_id]
            return GraphNode(
                id=node_id,
                label=data.get("label", ""),
                node_type=data.get("node_type", "host"),
                properties={k: v for k, v in data.items() if k not in ["label", "node_type"]},
            )
        elif not self._graph:
            return self._nodes.get(node_id)
        return None

    def get_neighbors(self, node_id: UUID) -> list[GraphNode]:
        """Get neighbors of a node."""
        neighbors = []
        if self._graph and node_id in self._graph:
            for neighbor_id in self._graph.neighbors(node_id):
                node = self.get_node(neighbor_id)
                if node:
                    neighbors.append(node)
        return neighbors

    def find_paths(self, source: UUID, target: UUID) -> list[list[UUID]]:
        """Find all paths between two nodes."""
        if self._graph:
            try:
                return list(nx.all_simple_paths(self._graph, source, target))
            except (nx.NetworkXError, nx.NodeNotFound):
                return []
        return []

    def find_shortest_path(self, source: UUID, target: UUID) -> Optional[list[UUID]]:
        """Find shortest path between two nodes."""
        if self._graph:
            try:
                return nx.shortest_path(self._graph, source, target)
            except (nx.NetworkXError, nx.NodeNotFound, nx.NetworkXNoPath):
                return None
        return None

    def get_subgraph(self, node_ids: list[UUID]) -> "AttackGraph":
        """Get a subgraph containing only specified nodes."""
        subgraph = AttackGraph()
        if self._graph:
            node_set = set(node_ids)
            for node_id in node_ids:
                node = self.get_node(node_id)
                if node:
                    subgraph.add_node(node)

            for edge in self._edges:
                if edge.source in node_set and edge.target in node_set:
                    subgraph.add_edge(edge)

        return subgraph

    def to_dict(self) -> dict:
        """Convert graph to dictionary representation."""
        if self._graph:
            return {
                "nodes": [
                    {
                        "id": str(node_id),
                        **data,
                    }
                    for node_id, data in self._graph.nodes(data=True)
                ],
                "edges": [
                    {
                        "source": str(u),
                        "target": str(v),
                        **data,
                    }
                    for u, v, data in self._graph.edges(data=True)
                ],
            }
        return {
            "nodes": [
                {"id": str(n.id), "label": n.label, "type": n.node_type}
                for n in self._nodes.values()
            ],
            "edges": [
                {"source": str(e.source), "target": str(e.target), "type": e.edge_type}
                for e in self._edges
            ],
        }

    def get_statistics(self) -> dict:
        """Get graph statistics."""
        if self._graph:
            return {
                "nodes": self._graph.number_of_nodes(),
                "edges": self._graph.number_of_edges(),
                "density": nx.density(self._graph) if self._graph.number_of_nodes() > 0 else 0,
            }
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
        }

    def visualize_ascii(self) -> str:
        """Generate ASCII visualization of the graph."""
        if not self._graph:
            return "Graph not available (networkx not installed)"

        lines = ["Attack Graph:"]
        for node_id, data in self._graph.nodes(data=True):
            label = data.get("label", str(node_id)[:8])
            node_type = data.get("node_type", "host")
            lines.append(f"  [{node_type}] {label}")

        lines.append("")
        lines.append("Connections:")
        for u, v, data in self._graph.edges(data=True):
            u_label = self._graph.nodes[u].get("label", str(u)[:8])
            v_label = self._graph.nodes[v].get("label", str(v)[:8])
            edge_type = data.get("edge_type", "connected")
            lines.append(f"  {u_label} --[{edge_type}]--> {v_label}")

        return "\n".join(lines)
