"""
OPTIONAL AI summarization of a single alert using a PRETRAINED Hugging Face
model. Nothing is trained here. Off by default - the rest of the app never
imports transformers unless ENABLE_AI_SUMMARY=true.

Environment variables:
    ENABLE_AI_SUMMARY   "true" to turn the feature on (default: false)
    AI_SUMMARY_BACKEND  "local" (transformers pipeline on this machine, default)
                        or "api" (Hugging Face Inference API)
    HF_SUMMARY_MODEL    model id (default: sshleifer/distilbart-cnn-12-6)
    HF_API_TOKEN        Hugging Face token, required for the "api" backend
"""

from __future__ import annotations

import os
import threading

DEFAULT_MODEL = "sshleifer/distilbart-cnn-12-6"


def ai_enabled() -> bool:
    return os.environ.get("ENABLE_AI_SUMMARY", "false").strip().lower() in ("1", "true", "yes", "on")


def alert_to_text(alert: dict) -> str:
    """Render an alert as prose - summarization models expect sentences, not JSON."""
    m = alert["mitre"][0]
    mitre = "not mapped to MITRE ATT&CK" if m["technique_id"] == "Unmapped" else (
        f"mapped to MITRE ATT&CK technique {m['technique_id']} ({m['technique_name']}), "
        f"tactic {m['tactic']}"
    )
    parts = [
        f"A {alert['severity']} severity security alert named '{alert['rule_name']}' "
        f"was raised on host {alert['host']} at {alert['timestamp'] or 'an unknown time'}.",
        f"The source IP address was {alert['source_ip']}." if alert["source_ip"] else "",
        f"The alert is {mitre}.",
        f"Category: {alert['category']}." if alert["category"] else "",
        f"Details: {alert['description'][:1500]}" if alert["description"] else "",
    ]
    return " ".join(p for p in parts if p)


class Summarizer:
    def __init__(self):
        self.backend = os.environ.get("AI_SUMMARY_BACKEND", "local").strip().lower()
        self.model = os.environ.get("HF_SUMMARY_MODEL", DEFAULT_MODEL)
        self._pipeline = None
        self._client = None
        self._lock = threading.Lock()

    def _load(self):
        """Lazy-load so the (large) model is only fetched on first use."""
        with self._lock:
            if self.backend == "api":
                if self._client is None:
                    token = os.environ.get("HF_API_TOKEN")
                    if not token:
                        raise RuntimeError("AI_SUMMARY_BACKEND=api requires the HF_API_TOKEN environment variable.")
                    from huggingface_hub import InferenceClient
                    self._client = InferenceClient(token=token)
            elif self._pipeline is None:
                from transformers import pipeline
                self._pipeline = pipeline("summarization", model=self.model)

    def summarize(self, alert: dict) -> str:
        self._load()
        text = alert_to_text(alert)
        if self.backend == "api":
            result = self._client.summarization(text, model=self.model)
            return getattr(result, "summary_text", None) or str(result)
        # Keep output shorter than input; short alerts otherwise trigger warnings.
        words = len(text.split())
        max_len = max(20, min(120, int(words * 0.8)))
        out = self._pipeline(text, max_length=max_len, min_length=min(15, max_len - 5), do_sample=False)
        return out[0]["summary_text"].strip()
