"""
SAIFE Capstone — Configuration
Uses pydantic-settings for env-based config.
LLM: Local Ollama (llama3.1) — same as katas/hello_agent/py/main.py
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.models.openai import OpenAIChatModel


class Settings(BaseSettings):
    """All configurable via environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── LLM (Local Ollama) ─────────────────────────────────────────
    ollama_model: str = "llama3.1"
    ollama_base_url: str = "http://localhost:11434/v1"

    # ── Scanner Defaults ───────────────────────────────────────────
    scan_timeout_seconds: int = 120
    max_concurrent_attacks: int = 5
    max_concurrent_agents: int = 3
    max_retries: int = 2
    llm_model: str = "llama3.1"

    # ── Scoring ────────────────────────────────────────────────────
    critical_threshold: float = 0.9
    high_threshold: float = 0.7
    medium_threshold: float = 0.4

    # ── Logging ────────────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Observability ─────────────────────────────────────────────
    enable_tracing: bool = False

    # ── Database Paths ────────────────────────────────────────────
    memory_db_path: str = "data/saife_memory.db"
    chroma_db_path: str = "data/chroma_db"

    # ── RAG Settings ──────────────────────────────────────────────
    rag_chunk_size: int = 1000
    rag_chunk_overlap: int = 200


# ── Singleton instance ─────────────────────────────────────────────
settings = Settings()


def get_llm_model() -> OpenAIChatModel:
    """Create the LLM model instance.
    factory function every agent will call. Single place to change the model.

    Returns an OpenAI-compatible model pointing at local Ollama.
    Same pattern as hello_agent/py/main.py:
        model = OpenAIChatModel(
            model_name='llama3.1',
            provider=OllamaProvider(base_url='http://localhost:11434/v1')
        )
    """
    return OpenAIChatModel(
        model_name=settings.ollama_model,
        provider=OllamaProvider(base_url=settings.ollama_base_url),
    )


# ── Auto-initialize OTEL tracing ──────────────────────────────────
from nodes.observability import setup_tracing
setup_tracing()
