"""RAG Client - ChromaDB-based retrieval augmented generation for CPENT knowledge."""

from dataclasses import dataclass, field
from typing import Any, Optional
from pathlib import Path

try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False

from knowledge.cpent_data import (
    KnowledgeEntry,
    KnowledgeCategory,
    get_all_entries,
    get_entries_by_category,
)


@dataclass
class RAGConfig:
    """RAG configuration."""

    persist_directory: str = "knowledge/chroma_db"
    collection_name: str = "cpent_knowledge"
    embedding_model: str = "all-MiniLM-L6-v2"  # Sentence transformer model
    max_results: int = 5


class RAGClient:
    """ChromaDB-based RAG client for CPENT knowledge."""

    def __init__(self, config: Optional[RAGConfig] = None):
        self.config = config or RAGConfig()
        self._client = None
        self._collection = None
        self._initialized = False

    def initialize(self) -> bool:
        """Initialize ChromaDB client and collection."""
        if not HAS_CHROMADB:
            print("[yellow]Warning: ChromaDB not installed. Using fallback mode.[/yellow]")
            return False

        try:
            # Create persist directory
            persist_dir = Path(self.config.persist_directory)
            persist_dir.mkdir(parents=True, exist_ok=True)

            # Initialize ChromaDB
            self._client = chromadb.PersistentClient(
                path=str(persist_dir),
                settings=Settings(anonymized_telemetry=False),
            )

            # Get or create collection
            self._collection = self._client.get_or_create_collection(
                name=self.config.collection_name,
                metadata={"hnsw:space": "cosine"},
            )

            self._initialized = True
            return True
        except Exception as e:
            print(f"[red]Error initializing ChromaDB: {e}[/red]")
            return False

    def load_knowledge(self, entries: Optional[list[KnowledgeEntry]] = None) -> int:
        """Load knowledge entries into the vector store."""
        if not self._initialized:
            if not self.initialize():
                return 0

        if entries is None:
            entries = get_all_entries()

        # Prepare data for ChromaDB
        ids = []
        documents = []
        metadatas = []

        for entry in entries:
            ids.append(entry.id)
            documents.append(f"{entry.title}\n\n{entry.content}")
            metadatas.append({
                "title": entry.title,
                "category": entry.category.value,
                "tags": ",".join(entry.tags),
                "importance": entry.importance,
                "source": entry.source or "",
            })

        # Add to collection in batches
        batch_size = 100
        for i in range(0, len(ids), batch_size):
            batch_ids = ids[i:i + batch_size]
            batch_docs = documents[i:i + batch_size]
            batch_metas = metadatas[i:i + batch_size]

            self._collection.upsert(
                ids=batch_ids,
                documents=batch_docs,
                metadatas=batch_metas,
            )

        return len(ids)

    def query(
        self,
        query_text: str,
        n_results: Optional[int] = None,
        category: Optional[KnowledgeCategory] = None,
        min_importance: float = 0.0,
    ) -> list[dict]:
        """Query the knowledge base."""
        if not self._initialized:
            return self._fallback_query(query_text, n_results)

        n = n_results or self.config.max_results

        # Build where filter
        where = None
        if category:
            where = {"category": category.value}

        try:
            results = self._collection.query(
                query_texts=[query_text],
                n_results=n,
                where=where,
                include=["documents", "metadatas", "distances"],
            )

            # Format results
            formatted = []
            if results and results["documents"]:
                for i, doc in enumerate(results["documents"][0]):
                    metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                    distance = results["distances"][0][i] if results["distances"] else 0

                    # Filter by importance
                    importance = metadata.get("importance", 0.5)
                    if importance >= min_importance:
                        formatted.append({
                            "content": doc,
                            "metadata": metadata,
                            "score": 1 - distance,  # Convert distance to similarity
                        })

            return formatted
        except Exception as e:
            print(f"[red]Query error: {e}[/red]")
            return self._fallback_query(query_text, n_results)

    def _fallback_query(self, query_text: str, n_results: Optional[int] = None) -> list[dict]:
        """Fallback query when ChromaDB is not available."""
        entries = get_all_entries()
        query_lower = query_text.lower()

        # Simple keyword matching
        scored_entries = []
        for entry in entries:
            score = 0
            # Check title
            if query_lower in entry.title.lower():
                score += 0.3
            # Check content
            if query_lower in entry.content.lower():
                score += 0.4
            # Check tags
            for tag in entry.tags:
                if query_lower in tag.lower():
                    score += 0.2
            # Add importance
            score += entry.importance * 0.1

            if score > 0:
                scored_entries.append({
                    "content": f"{entry.title}\n\n{entry.content}",
                    "metadata": {
                        "title": entry.title,
                        "category": entry.category.value,
                        "tags": ",".join(entry.tags),
                        "importance": entry.importance,
                    },
                    "score": min(score, 1.0),
                })

        # Sort by score and return top results
        scored_entries.sort(key=lambda x: x["score"], reverse=True)
        n = n_results or self.config.max_results
        return scored_entries[:n]

    def get_context_for_query(self, query: str, max_tokens: int = 2000) -> str:
        """Get formatted context for LLM from query."""
        results = self.query(query, n_results=3)

        if not results:
            return "No relevant knowledge found."

        context_parts = ["Relevant CPENT Knowledge:"]
        current_length = 0

        for result in results:
            content = result["content"]
            if current_length + len(content) > max_tokens:
                # Truncate to fit
                remaining = max_tokens - current_length
                if remaining > 100:
                    content = content[:remaining] + "..."
                else:
                    break
            context_parts.append(f"\n---\n{content}")
            current_length += len(content)

        return "\n".join(context_parts)

    def search_by_category(
        self,
        category: KnowledgeCategory,
        limit: int = 5,
    ) -> list[dict]:
        """Search by category."""
        if not self._initialized:
            entries = get_entries_by_category(category)
            return [
                {
                    "content": f"{e.title}\n\n{e.content}",
                    "metadata": {"title": e.title, "category": e.category.value},
                }
                for e in entries[:limit]
            ]

        try:
            results = self._collection.query(
                query_texts=[category.value],
                n_results=limit,
                where={"category": category.value},
                include=["documents", "metadatas"],
            )

            formatted = []
            if results and results["documents"]:
                for i, doc in enumerate(results["documents"][0]):
                    metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                    formatted.append({
                        "content": doc,
                        "metadata": metadata,
                    })
            return formatted
        except Exception as e:
            return []

    def get_stats(self) -> dict:
        """Get RAG statistics."""
        if not self._initialized:
            return {"initialized": False, "entries": len(get_all_entries())}

        return {
            "initialized": True,
            "collection": self.config.collection_name,
            "entries": self._collection.count() if self._collection else 0,
        }


# Global RAG client instance
_rag_client: Optional[RAGClient] = None


def get_rag_client() -> RAGClient:
    """Get or create the global RAG client."""
    global _rag_client
    if _rag_client is None:
        _rag_client = RAGClient()
    return _rag_client


def initialize_rag() -> bool:
    """Initialize the global RAG client."""
    client = get_rag_client()
    if client.initialize():
        count = client.load_knowledge()
        print(f"[green]Loaded {count} knowledge entries into RAG[/green]")
        return True
    return False
