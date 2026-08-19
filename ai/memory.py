"""AI Memory System - Three levels of memory for PEN-AI with RAG support."""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class MemoryEntry(BaseModel):
    """A single memory entry."""

    content: str
    category: str = "general"
    importance: float = 0.5  # 0-1 scale
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ShortTermMemory:
    """Current reasoning loop context - resets between reasoning cycles."""

    def __init__(self, max_entries: int = 50):
        self._entries: list[MemoryEntry] = []
        self._max_entries = max_entries

    def add(self, content: str, category: str = "general", importance: float = 0.5) -> None:
        """Add a memory entry."""
        entry = MemoryEntry(content=content, category=category, importance=importance)
        self._entries.append(entry)

        # Evict low-importance entries if over limit
        if len(self._entries) > self._max_entries:
            self._entries.sort(key=lambda e: e.importance)
            self._entries = self._entries[-self._max_entries:]

    def get_recent(self, n: int = 10) -> list[MemoryEntry]:
        """Get the N most recent entries."""
        return self._entries[-n:]

    def get_by_category(self, category: str) -> list[MemoryEntry]:
        """Get entries by category."""
        return [e for e in self._entries if e.category == category]

    def get_important(self, threshold: float = 0.7) -> list[MemoryEntry]:
        """Get entries above importance threshold."""
        return [e for e in self._entries if e.importance >= threshold]

    def clear(self) -> None:
        """Clear all short-term memory."""
        self._entries.clear()

    def to_context(self) -> str:
        """Convert to context string for LLM."""
        if not self._entries:
            return "No recent context."

        lines = ["Recent context:"]
        for entry in self.get_recent(20):
            lines.append(f"- [{entry.category}] {entry.content}")
        return "\n".join(lines)


class EngagementMemory:
    """Persistent memory for the current engagement."""

    def __init__(self):
        self._discoveries: list[MemoryEntry] = []
        self._credentials: list[MemoryEntry] = []
        self._vulnerabilities: list[MemoryEntry] = []
        self._exploits: list[MemoryEntry] = []
        self._pivots: list[MemoryEntry] = []
        self._objectives: list[MemoryEntry] = []
        self._failures: list[MemoryEntry] = []

    def add_discovery(self, content: str, metadata: Optional[dict] = None) -> None:
        """Record a discovery."""
        entry = MemoryEntry(content=content, category="discovery", importance=0.7, metadata=metadata or {})
        self._discoveries.append(entry)

    def add_credential(self, content: str, metadata: Optional[dict] = None) -> None:
        """Record a credential."""
        entry = MemoryEntry(content=content, category="credential", importance=0.9, metadata=metadata or {})
        self._credentials.append(entry)

    def add_vulnerability(self, content: str, metadata: Optional[dict] = None) -> None:
        """Record a vulnerability."""
        entry = MemoryEntry(content=content, category="vulnerability", importance=0.8, metadata=metadata or {})
        self._vulnerabilities.append(entry)

    def add_exploit(self, content: str, metadata: Optional[dict] = None) -> None:
        """Record an exploit attempt."""
        entry = MemoryEntry(content=content, category="exploit", importance=0.8, metadata=metadata or {})
        self._exploits.append(entry)

    def add_pivot(self, content: str, metadata: Optional[dict] = None) -> None:
        """Record a pivot."""
        entry = MemoryEntry(content=content, category="pivot", importance=0.85, metadata=metadata or {})
        self._pivots.append(entry)

    def add_objective(self, content: str, metadata: Optional[dict] = None) -> None:
        """Record an objective."""
        entry = MemoryEntry(content=content, category="objective", importance=0.9, metadata=metadata or {})
        self._objectives.append(entry)

    def add_failure(self, content: str, metadata: Optional[dict] = None) -> None:
        """Record a failure (for learning)."""
        entry = MemoryEntry(content=content, category="failure", importance=0.6, metadata=metadata or {})
        self._failures.append(entry)

    def get_all(self) -> dict[str, list[MemoryEntry]]:
        """Get all memories by category."""
        return {
            "discoveries": self._discoveries,
            "credentials": self._credentials,
            "vulnerabilities": self._vulnerabilities,
            "exploits": self._exploits,
            "pivots": self._pivots,
            "objectives": self._objectives,
            "failures": self._failures,
        }

    def to_context(self) -> str:
        """Convert to context string for LLM."""
        sections = []

        if self._discoveries:
            sections.append("Discoveries:")
            for d in self._discoveries[-10:]:
                sections.append(f"  - {d.content}")

        if self._credentials:
            sections.append("Credentials:")
            for c in self._credentials:
                sections.append(f"  - {c.content}")

        if self._vulnerabilities:
            sections.append("Vulnerabilities:")
            for v in self._vulnerabilities[-10:]:
                sections.append(f"  - {v.content}")

        if self._exploits:
            sections.append("Exploits:")
            for e in self._exploits[-10:]:
                sections.append(f"  - {e.content}")

        if self._pivots:
            sections.append("Pivots:")
            for p in self._pivots:
                sections.append(f"  - {p.content}")

        if self._objectives:
            sections.append("Objectives:")
            for o in self._objectives:
                sections.append(f"  - {o.content}")

        if self._failures:
            sections.append("Learned from failures:")
            for f in self._failures[-5:]:
                sections.append(f"  - {f.content}")

        return "\n".join(sections) if sections else "No engagement memory yet."


class KnowledgeMemory:
    """Long-term knowledge from CPENT methodology and RAG."""

    def __init__(self):
        self._entries: list[MemoryEntry] = []
        self._rag_client = None

    def set_rag_client(self, rag_client: Any) -> None:
        """Set the RAG client for vector search."""
        self._rag_client = rag_client

    def add(self, content: str, category: str = "knowledge", importance: float = 0.5) -> None:
        """Add a knowledge entry."""
        entry = MemoryEntry(content=content, category=category, importance=importance)
        self._entries.append(entry)

    def search(self, query: str, limit: int = 5) -> list[MemoryEntry]:
        """Search knowledge base using RAG if available."""
        # Try RAG search first
        if self._rag_client:
            try:
                results = self._rag_client.query(query, n_results=limit)
                if results:
                    return [
                        MemoryEntry(
                            content=r["content"],
                            category=r.get("metadata", {}).get("category", "knowledge"),
                            importance=r.get("metadata", {}).get("importance", 0.5),
                            metadata=r.get("metadata", {}),
                        )
                        for r in results
                    ]
            except Exception:
                pass

        # Fallback to keyword matching
        results = []
        query_lower = query.lower()
        for entry in self._entries:
            if query_lower in entry.content.lower():
                results.append(entry)
        results.sort(key=lambda e: e.importance, reverse=True)
        return results[:limit]

    def search_by_category(self, category: str, limit: int = 5) -> list[MemoryEntry]:
        """Search by category."""
        if self._rag_client:
            try:
                from knowledge.cpent_data import KnowledgeCategory
                cat = KnowledgeCategory(category)
                results = self._rag_client.search_by_category(cat, limit=limit)
                return [
                    MemoryEntry(
                        content=r["content"],
                        category=category,
                        metadata=r.get("metadata", {}),
                    )
                    for r in results
                ]
            except Exception:
                pass

        return [e for e in self._entries if e.category == category][:limit]

    def to_context(self) -> str:
        """Convert to context string."""
        if not self._entries:
            return "No knowledge loaded."
        return f"Knowledge base: {len(self._entries)} entries loaded."

    def get_rag_context(self, query: str, max_tokens: int = 2000) -> str:
        """Get context from RAG for LLM."""
        if self._rag_client:
            return self._rag_client.get_context_for_query(query, max_tokens)
        return self.to_context()


class AIMemory:
    """Combined memory system for PEN-AI."""

    def __init__(self, rag_client: Optional[Any] = None):
        self.short_term = ShortTermMemory()
        self.engagement = EngagementMemory()
        self.knowledge = KnowledgeMemory()

        if rag_client:
            self.knowledge.set_rag_client(rag_client)

    def to_context(self) -> str:
        """Combine all memory into context for LLM."""
        parts = [
            "=== PEN-AI MEMORY STATE ===",
            "",
            "--- Short-Term Context ---",
            self.short_term.to_context(),
            "",
            "--- Engagement Memory ---",
            self.engagement.to_context(),
            "",
            "--- Knowledge ---",
            self.knowledge.to_context(),
            "",
            "==========================",
        ]
        return "\n".join(parts)

    def get_rag_context(self, query: str, max_tokens: int = 2000) -> str:
        """Get RAG context for a specific query."""
        return self.knowledge.get_rag_context(query, max_tokens)

    def clear_short_term(self) -> None:
        """Clear short-term memory between reasoning cycles."""
        self.short_term.clear()
