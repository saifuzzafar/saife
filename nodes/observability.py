"""
SAIFE Observability — Arize Phoenix / OpenTelemetry Integration
===============================================================
Sends traces from all PydanticAI agents to Arize Phoenix for
real-time visualization of agent runs, tool calls, and LLM latency.

Enable with: SAIFE_ENABLE_TRACING=true
Phoenix endpoint (default): http://127.0.0.1:6006

Run Phoenix first:
    uvx arize-phoenix serve

Then start a scan — traces appear in the Phoenix UI automatically.

When enabled, every agent call produces OTEL spans with:
  - Agent name and model
  - Full prompt and response content
  - Tool invocations and their outputs
  - Duration and token usage
  - Error states and retries
"""
import os
import logging

logger = logging.getLogger("saife.observability")


def \
        setup_tracing() -> bool:
    """Initialize Arize Phoenix tracing if SAIFE_ENABLE_TRACING=true.

    Sends OpenTelemetry spans from all PydanticAI agents to a local
    Phoenix instance at http://127.0.0.1:6006 (or PHOENIX_ENDPOINT).

    Returns True if tracing was successfully initialized.
    """
    enabled = os.getenv("SAIFE_ENABLE_TRACING", "false").lower() in ("true", "1", "yes")

    if not enabled:
        logger.debug("OTEL tracing disabled (set SAIFE_ENABLE_TRACING=true to enable)")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from pydantic_ai import Agent

        endpoint = os.getenv("PHOENIX_ENDPOINT", "http://127.0.0.1:6006")

        resource = Resource.create({"openinference.project.name": "saife-security-scanner"})
        tracer_provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(tracer_provider)

        # OpenInference enrichment — adds conversation threading and session context
        # to spans so Phoenix can group them visually per scan.
        try:
            from openinference.instrumentation.pydantic_ai import OpenInferenceSpanProcessor
            tracer_provider.add_span_processor(OpenInferenceSpanProcessor())
            logger.info("OpenInference span enrichment enabled")
        except ImportError:
            logger.info("openinference-instrumentation-pydantic-ai not installed — using standard OTel spans")

        # Export spans to Phoenix via OTLP HTTP
        tracer_provider.add_span_processor(
            SimpleSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces"))
        )

        # Tell PydanticAI to emit spans for every agent run
        Agent.instrument_all()

        logger.info(f"OTEL tracing initialized → Phoenix at {endpoint}")
        return True

    except ImportError as e:
        logger.warning(
            f"OpenTelemetry packages not found ({e}). "
            "Install with: pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-http"
        )
        return False
    except Exception as e:
        logger.warning(f"Failed to initialize OTEL tracing: {e}")
        return False
