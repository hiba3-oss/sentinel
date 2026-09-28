"""Sentinel REST API."""

from fastapi import FastAPI

from sentinel import __version__
from sentinel.api.routes import router

app = FastAPI(
    title="Sentinel Security API",
    description=(
        "REST API for the Sentinel defensive cybersecurity "
        "monitoring and threat detection platform."
    ),
    version=__version__,
)

app.include_router(router)


@app.get("/")
def root() -> dict[str, str]:
    """Return basic Sentinel API information."""

    return {
        "name": "Sentinel Security API",
        "version": __version__,
        "status": "online",
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Return API health status."""

    return {
        "status": "healthy",
    }