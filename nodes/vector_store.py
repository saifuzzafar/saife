"""
Vector Store — ChromaDB + Sentence Transformers
=================================================
Embeds OWASP knowledge base into ChromaDB for RAG retrieval.
Uses local sentence-transformers for embeddings (no external API needed).
"""
import os
import re
from pathlib import Path
from dataclasses import dataclass

import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction


from config import settings

# ── Configuration ─────────────────────────────────────────────────

COLLECTION_NAME = "owasp_knowledge"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
DATA_DIR = Path(__file__).parent.parent / "data"
CHROMA_DIR = Path(settings.chroma_db_path) if settings.chroma_db_path.startswith("/") else Path(__file__).parent.parent / settings.chroma_db_path
KNOWLEDGE_FILE = DATA_DIR / "owasp_knowledge.md"


# ── Data Models ───────────────────────────────────────────────────

@dataclass
class RetrievedChunk:
    """A retrieved chunk from the vector store."""
    text: str
    source: str
    score: float


# ── Vector Store ──────────────────────────────────────────────────

class VectorStore:
    """ChromaDB-backed vector store for OWASP knowledge retrieval."""

    def __init__(self, persist_dir: str | None = None):
        self._persist_dir = persist_dir or str(CHROMA_DIR)
        self._embedding_fn = SentenceTransformerEmbeddingFunction(
            model_name=EMBEDDING_MODEL,
        )
        self._client = chromadb.PersistentClient(path=self._persist_dir)
        self._collection = None
        self._cache: dict[str, list[RetrievedChunk]] = {}

    def initialize(self, knowledge_path: str | None = None) -> int:
        """Load, chunk, and embed the knowledge base.

        Returns the number of chunks indexed.
        Skips re-indexing if the collection already has documents.
        """
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=self._embedding_fn,
            metadata={"hnsw:space": "cosine"},
        )

        # Skip if already populated
        if self._collection.count() > 0:
            return self._collection.count()

        # Load knowledge file
        kb_path = knowledge_path or str(KNOWLEDGE_FILE)
        if not os.path.exists(kb_path):
            raise FileNotFoundError(f"Knowledge base not found: {kb_path}")

        with open(kb_path, "r") as f:
            content = f.read()

        # Chunk by section (split on ## headers)
        chunks = self._chunk_by_section(content)

        if not chunks:
            return 0

        # Add to ChromaDB
        ids = [f"chunk_{i}" for i in range(len(chunks))]
        documents = [c["text"] for c in chunks]
        metadatas = [{"source": c["source"], "section": c["section"]} for c in chunks]

        self._collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

        return len(chunks)

    def search(self, query: str, n_results: int = 3) -> list[RetrievedChunk]:
        """Search the knowledge base for relevant chunks. Uses in-memory cache."""
        cache_key = f"{query}_{n_results}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self._collection is None:
            self.initialize()

        results = self._collection.query(
            query_texts=[query],
            n_results=min(n_results, self._collection.count()),
        )

        chunks = []
        if results and results["documents"] and results["documents"][0]:
            for i, doc in enumerate(results["documents"][0]):
                distance = results["distances"][0][i] if results["distances"] else 1.0
                # Convert cosine distance to similarity score (0-1)
                score = max(0.0, 1.0 - distance)
                source = ""
                if results["metadatas"] and results["metadatas"][0]:
                    meta = results["metadatas"][0][i]
                    source = f"{meta.get('section', '')} ({meta.get('source', '')})"

                chunks.append(RetrievedChunk(
                    text=doc,
                    source=source,
                    score=round(score, 3),
                ))

        self._cache[cache_key] = chunks
        return chunks

    def _chunk_by_section(self, content: str) -> list[dict]:
        """Split markdown content into chunks by section headers."""
        chunks = []
        # Split on ## headers (keeping the header with its content)
        sections = re.split(r'\n(?=## )', content)

        for section in sections:
            if not section.strip():
                continue

            # Extract section title
            lines = section.strip().split('\n')
            title = lines[0].replace('#', '').strip() if lines else "Unknown"

            # Further split into subsections (### headers)
            subsections = re.split(r'\n(?=### )', section)

            for subsection in subsections:
                if not subsection.strip():
                    continue

                sub_lines = subsection.strip().split('\n')
                sub_title = sub_lines[0].replace('#', '').strip() if sub_lines else title

                text = subsection.strip()

                # If still too long, split into overlapping chunks
                if len(text) > settings.rag_chunk_size * 2:
                    for chunk_text in self._split_text(text, settings.rag_chunk_size, settings.rag_chunk_overlap):
                        chunks.append({
                            "text": chunk_text,
                            "source": "OWASP LLM Top 10",
                            "section": f"{title} > {sub_title}",
                        })
                else:
                    chunks.append({
                        "text": text,
                        "source": "OWASP LLM Top 10",
                        "section": f"{title} > {sub_title}",
                    })

        return chunks

    @staticmethod
    def _split_text(text: str, chunk_size: int, overlap: int) -> list[str]:
        """Split text into overlapping chunks."""
        chunks = []
        start = 0
        while start < len(text):
            end = start + chunk_size
            chunk = text[start:end]
            if chunk.strip():
                chunks.append(chunk.strip())
            start = end - overlap
        return chunks


# ── Module-level singleton ────────────────────────────────────────

_store: VectorStore | None = None


def get_store() -> VectorStore:
    """Get or create the singleton vector store."""
    global _store
    if _store is None:
        _store = VectorStore()
    return _store
