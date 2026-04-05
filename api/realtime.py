"""
Guni Real-Time Scanner
WebSocket endpoint that streams threat analysis results as an agent browses.
Each page navigation triggers an immediate scan and streams results back.

Usage:
    ws = WebSocket("wss://guni.up.railway.app/ws/scan")
    ws.send(JSON.stringify({ html: pageHTML, goal: "Login", url: currentURL }))
    ws.onmessage = (e) => console.log(JSON.parse(e.data))
"""

import json
import os

from fastapi import WebSocket, WebSocketDisconnect


def _build_scan_result(result: dict, url: str, goal: str) -> dict:
    llm_summary = ""
    llm_analysis = result.get("llm_analysis")
    if llm_analysis and not llm_analysis.get("error"):
        llm_summary = llm_analysis.get("summary", "")

    return {
        "type": "result",
        "risk": result["risk"],
        "decision": result["decision"],
        "breakdown": result["breakdown"],
        "evidence": {k: v for k, v in result["evidence"].items() if v},
        "latency": result["total_latency"],
        "url": url,
        "goal": goal,
        "llm_summary": llm_summary,
    }


async def websocket_scan_endpoint(websocket: WebSocket, goal: str = "browse website"):
    """
    WebSocket endpoint for real-time agent scanning.
    Agent sends page HTML, Guni streams back threat analysis.
    """
    from guni import GuniScanner
    from api.auth import verify_api_key_for_connection
    from api.database import db_get_usage
    from api.services.scan_api import get_default_llm_api_key

    try:
        api_key = verify_api_key_for_connection(websocket)
    except Exception:
        await websocket.close(code=1008, reason="Authentication required")
        return

    await websocket.accept()

    scanner = GuniScanner(
        goal=goal,
        llm_api_key=get_default_llm_api_key(),
        llm_provider=os.environ.get("GUNI_LLM_PROVIDER", ""),
        llm_model=os.environ.get("GUNI_LLM_MODEL", ""),
        llm_base_url=os.environ.get("GUNI_LLM_BASE_URL", ""),
        tracking_key=api_key,
    )

    await websocket.send_json({
        "type":    "connected",
        "message": f"Guni real-time scanner active — goal: '{goal}'",
        "vectors": 8,
    })

    try:
        while True:
            raw = await websocket.receive_text()

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type":  "error",
                    "error": "Invalid JSON"
                })
                continue

            html    = data.get("html", "")
            url     = data.get("url", "")
            pg_goal = data.get("goal", goal)
            llm_api_key = data.get("llm_api_key")
            llm_provider = data.get("llm_provider")
            llm_model = data.get("llm_model")
            llm_base_url = data.get("llm_base_url")

            if not html:
                await websocket.send_json({
                    "type":  "error",
                    "error": "html field required"
                })
                continue

            # Send scanning status immediately
            await websocket.send_json({
                "type": "scanning",
                "url":  url,
            })

            usage = db_get_usage(api_key)
            if usage and int(usage.get("monthly_limit", 0)) > 0:
                if int(usage.get("scans_used", 0)) >= int(usage.get("monthly_limit", 0)):
                    await websocket.send_json({
                        "error": "quota_exceeded",
                        "message": "Monthly scan quota exhausted. Upgrade your plan."
                    })
                    await websocket.close()
                    return

            # Run scan
            if pg_goal != scanner.goal:
                scanner.goal = pg_goal
            if llm_api_key is not None:
                scanner.api_key = llm_api_key
            if llm_provider is not None:
                scanner.llm_provider = llm_provider
            if llm_model is not None:
                scanner.llm_model = llm_model
            if llm_base_url is not None:
                scanner.llm_base_url = llm_base_url

            result = scanner.scan(html=html, url=url)

            await websocket.send_json(_build_scan_result(result, url, pg_goal))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({
                "type":  "error",
                "error": str(e)
            })
        except Exception:
            pass
