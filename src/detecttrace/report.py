from __future__ import annotations
import json
from .models import TraceResult


LABELS = {
    "execution": "Execution",
    "source": "Source telemetry",
    "collector": "Collector",
    "normalization": "Normalization",
    "rule": "Rule",
    "alert": "Alert",
}


def render_text(result: TraceResult, verbose: bool = False) -> str:
    lines = [
        "DETECTION TRACE",
        "=" * 72,
        f"{result.spec_id} — {result.title}",
        f"Profile: {result.profile}",
        "",
    ]
    width = max(len(LABELS.get(s.name, s.name)) for s in result.stages)
    for stage in result.stages:
        label = LABELS.get(stage.name, stage.name)
        lines.append(f"{label:<{width}}   {stage.status.value:<8}  {stage.summary}")

    lines += ["", "ROOT CAUSE", "-" * 72]
    lines.append(result.root_cause or "No root cause available.")
    if result.confidence:
        lines.append(f"Confidence: {result.confidence}")

    if verbose:
        lines += ["", "EVIDENCE", "-" * 72]
        for stage in result.stages:
            if not stage.evidence:
                continue
            lines.append(f"[{LABELS.get(stage.name, stage.name)}]")
            for ev in stage.evidence:
                lines.append(f"- {ev.message}")
                if ev.data:
                    payload = json.dumps(ev.data, indent=2, sort_keys=True, default=str)
                    lines.extend(f"  {line}" for line in payload.splitlines())
    return "\n".join(lines)


def render_json(result: TraceResult) -> str:
    payload = {
        "spec_id": result.spec_id,
        "title": result.title,
        "profile": result.profile,
        "healthy": result.healthy,
        "root_cause": result.root_cause,
        "confidence": result.confidence,
        "stages": [
            {
                "name": s.name,
                "status": s.status.value,
                "summary": s.summary,
                "evidence": [{"message": e.message, "data": e.data} for e in s.evidence],
            }
            for s in result.stages
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, default=str)
