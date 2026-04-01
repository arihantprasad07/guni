"""Threat intelligence routes."""

from __future__ import annotations

import asyncio
import json
import time

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from api.services.site import render_dashboard_page


router = APIRouter()


@router.get("/threats/feed", tags=["Threat Intelligence"])
def threat_feed():
    try:
        from api.database import db_get_threat_feed

        return db_get_threat_feed()
    except Exception as exc:
        return {
            "total_scans": 0,
            "total_blocked": 0,
            "block_rate": 0,
            "last_24h_scans": 0,
            "last_24h_blocked": 0,
            "threat_counts": {},
            "top_threat": "none",
            "hourly_trend": [],
            "error": str(exc),
        }


@router.get("/threats/stream", tags=["Threat Intelligence"])
async def threat_feed_stream(request: Request, once: bool = False):
    async def event_generator():
        last_payload = None

        while True:
            if await request.is_disconnected():
                break

            try:
                from api.database import db_get_threat_feed

                payload = db_get_threat_feed()
            except Exception as exc:
                payload = {
                    "total_scans": 0,
                    "total_blocked": 0,
                    "block_rate": 0,
                    "last_24h_scans": 0,
                    "last_24h_blocked": 0,
                    "threat_counts": {},
                    "top_threat": "none",
                    "hourly_trend": [],
                    "error": str(exc),
                }

            payload_json = json.dumps(payload, sort_keys=True)
            if payload_json != last_payload:
                yield f"event: snapshot\ndata: {payload_json}\n\n"
                last_payload = payload_json
                if once:
                    break
            else:
                yield f"event: heartbeat\ndata: {int(time.time())}\n\n"
                if once:
                    break

            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/threats", include_in_schema=False)
def threats_page():
    return render_dashboard_page("threats.html", "<h1>Threat Feed</h1>")
