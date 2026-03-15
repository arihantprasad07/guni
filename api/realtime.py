"""
Guni Real-Time Scanner
WebSocket endpoint that streams threat analysis results as an agent browses.
Each page navigation triggers an immediate scan and streams results back.

Usage:
    ws = WebSocket("wss://guni.up.railway.app/ws/scan")
    ws.send(JSON.stringify({ html: pageHTML, goal: "Login", url: currentURL }))
    ws.onmessage = (e) => console.log(JSON.parse(e.data))
"""

from fastapi import WebSocket, WebSocketDisconnect
import json
import time


async def websocket_scan_endpoint(websocket: WebSocket, goal: str = "browse website"):
    """
    WebSocket endpoint for real-time agent scanning.
    Agent sends page HTML, Guni streams back threat analysis.
    """
    from guni import GuniScanner
    import os

    await websocket.accept()

    scanner = GuniScanner(
        goal=goal,
        api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
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

            # Run scan
            if pg_goal != scanner.goal:
                scanner.goal = pg_goal

            result = scanner.scan(html=html, url=url)

            # Stream result back
            await websocket.send_json({
                "type":        "result",
                "risk":        result["risk"],
                "decision":    result["decision"],
                "breakdown":   result["breakdown"],
                "evidence":    {
                    k: v for k, v in result["evidence"].items() if v
                },
                "latency":     result["total_latency"],
                "url":         url,
                "goal":        pg_goal,
                "llm_summary": (
                    result["llm_analysis"].get("summary", "")
                    if result.get("llm_analysis") and not result["llm_analysis"].get("error")
                    else ""
                ),
            })

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
