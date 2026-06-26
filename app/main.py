from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import ROOT_DIR, settings
from app.detector import HybridDetector
from app.schemas import HealthResponse, Metrics, NetworkFlow, SecurityEvent, Severity, StatusUpdate
from app.simulator import TrafficSimulator
from app.storage import EventStore


detector = HybridDetector(settings.model_path, settings.random_seed)
store = EventStore(settings.database_path, settings.max_events)
simulator = TrafficSimulator(settings.random_seed)
subscribers: set[asyncio.Queue[SecurityEvent]] = set()


async def broadcast(event: SecurityEvent) -> None:
    stale: list[asyncio.Queue[SecurityEvent]] = []
    for queue in subscribers:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            stale.append(queue)
    for queue in stale:
        subscribers.discard(queue)


async def simulation_loop() -> None:
    while True:
        flow = simulator.next_flow()
        detection = detector.predict(flow)
        event = store.add(flow, detection)
        await broadcast(event)
        await asyncio.sleep(settings.simulator_interval_seconds)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(simulation_loop(), name="traffic-simulator")
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="Explainable hybrid network anomaly monitoring demo for equipment and maritime environments.",
    lifespan=lifespan,
)


@app.get("/api/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok", service=settings.app_name, model_ready=detector.ready,
        database_ready=store.ready, version=__version__,
    )


@app.post("/api/detect", response_model=SecurityEvent, status_code=201, tags=["detection"])
async def detect(flow: NetworkFlow) -> SecurityEvent:
    result = detector.predict(flow)
    event = store.add(flow, result)
    await broadcast(event)
    return event


@app.get("/api/events", response_model=list[SecurityEvent], tags=["events"])
def events(
    limit: int = Query(default=50, ge=1, le=250),
    alerts_only: bool = True,
    severity: Severity | None = None,
) -> list[SecurityEvent]:
    return store.list_events(limit, alerts_only, severity.value if severity else None)


@app.patch("/api/events/{event_id}/status", response_model=SecurityEvent, tags=["events"])
async def update_event_status(event_id: int, update: StatusUpdate) -> SecurityEvent:
    event = store.update_status(event_id, update.status)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    await broadcast(event)
    return event


@app.get("/api/metrics", response_model=Metrics, tags=["analytics"])
def metrics() -> Metrics:
    return store.metrics()


@app.websocket("/ws/events")
async def event_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=100)
    subscribers.add(queue)
    try:
        while True:
            event = await queue.get()
            await websocket.send_text(event.model_dump_json())
    except WebSocketDisconnect:
        pass
    finally:
        subscribers.discard(queue)


STATIC_DIR = ROOT_DIR / "app" / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
