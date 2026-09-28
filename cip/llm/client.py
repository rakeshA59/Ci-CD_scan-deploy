"""Thin, provider-agnostic LLM client.

Supported providers: anthropic, openai, azure_openai. If the provider is "none" or its
API key is missing, `enabled` is False and every pipeline stage falls back to its
deterministic implementation – so the pipeline always runs end-to-end.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path

log = logging.getLogger("cip.llm")
PROMPT_DIR = Path(__file__).parent / "prompts"


def load_prompt(name: str) -> str:
    return (PROMPT_DIR / f"{name}.md").read_text(encoding="utf-8")


DEFAULT_MODELS = {"anthropic": "claude-sonnet-5", "openai": "gpt-4o"}
KEY_VARS = {"openai": ("OPENAI_API_KEY",), "anthropic": ("ANTHROPIC_API_KEY",),
            "azure_openai": ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT")}


def _env(*names: str) -> str:
    for n in names:
        v = os.getenv(n, "").strip()
        if v:
            return v
    return ""


def azure_settings() -> dict:
    """Azure OpenAI settings. The key may be in AZURE_OPENAI_API_KEY or (commonly) OPENAI_API_KEY."""
    endpoint = _env("AZURE_OPENAI_ENDPOINT")
    if not endpoint:
        base = _env("OPENAI_BASE_URL", "OPENAI_API_BASE")
        if "azure" in base:
            endpoint = base
    key = _env("AZURE_OPENAI_API_KEY") or (_env("OPENAI_API_KEY") if endpoint else "")
    version = _env("AZURE_OPENAI_API_VERSION", "OPENAI_API_VERSION")
    deployment = _env("AZURE_OPENAI_DEPLOYMENT")
    # Accept the portal's full "Target URI" too:
    #   https://<res>.cognitiveservices.azure.com/openai/deployments/<dep>/chat/completions?api-version=<v>
    import re
    from urllib.parse import parse_qs, urlparse
    if endpoint and ("/openai" in endpoint or "?" in endpoint):
        u = urlparse(endpoint)
        m = re.search(r"/deployments/([^/?]+)", u.path)
        deployment = deployment or (m.group(1) if m else "")
        version = version or (parse_qs(u.query).get("api-version") or [""])[0]
        endpoint = f"{u.scheme}://{u.netloc}"
    return {"endpoint": endpoint.rstrip("/"), "key": key, "version": version or "2025-04-01-preview",
            "deployment": deployment}


def looks_like_azure_key(key: str) -> bool:
    return bool(key) and not key.startswith("sk-")


def _has_key(provider: str) -> bool:
    if provider == "azure_openai":
        a = azure_settings()
        return bool(a["endpoint"] and a["key"])
    if provider == "openai":
        key = _env("OPENAI_API_KEY")
        # An Azure key in OPENAI_API_KEY (+ an Azure endpoint) belongs to azure_openai, not api.openai.com.
        return bool(key) and not (looks_like_azure_key(key) and azure_settings()["endpoint"])
    return all(os.getenv(v, "").strip() for v in KEY_VARS.get(provider, ("-",)))


def is_reasoning_model(model: str) -> bool:
    """GPT-5 family and o-series: no `temperature`, and `max_completion_tokens` instead of `max_tokens`."""
    m = (model or "").lower()
    return m.startswith(("gpt-5", "o1", "o3", "o4"))


def resolve_provider(requested: str) -> tuple[str, str]:
    """Pick the provider to use. 'auto' (default) = whichever API key is set: OpenAI, then Azure, then Anthropic.
    An explicit provider whose key is missing falls back to one whose key IS set."""
    requested = (requested or "auto").lower().strip()
    if requested == "none":
        return "none", ""
    order = ["openai", "azure_openai", "anthropic"]
    if requested == "openai" and not _has_key("openai") and _has_key("azure_openai"):
        return "azure_openai", ("OPENAI_API_KEY looks like an Azure OpenAI key and AZURE_OPENAI_ENDPOINT is set – "
                                "using azure_openai")
    if requested in KEY_VARS:
        if _has_key(requested):
            return requested, ""
        other = next((p for p in order if _has_key(p)), None)
        if other:
            return other, (f"LLM_PROVIDER={requested} but {'/'.join(KEY_VARS[requested])} is not set – "
                           f"using {other} because its key is set")
        return requested, ""
    found = next((p for p in order if _has_key(p)), None)
    return (found or "none"), ""


def _model_fits(provider: str, model: str) -> bool:
    m = (model or "").lower()
    if provider == "openai":
        return bool(m) and not m.startswith("claude")
    if provider == "anthropic":
        return m.startswith("claude")
    return True


class LLMClient:
    def __init__(self, cfg: dict):
        self.cfg = cfg or {}
        self.requested = (self.cfg.get("provider") or "auto").lower().strip()
        self.provider, self.note = resolve_provider(self.requested)
        self.model = (self.cfg.get("model") or "").strip()
        if self.provider in DEFAULT_MODELS and not _model_fits(self.provider, self.model):
            if self.model:
                self.note = (self.note + "; " if self.note else "") + \
                    f"model '{self.model}' is not a {self.provider} model – using {DEFAULT_MODELS[self.provider]} (set LLM_MODEL to change)"
            self.model = DEFAULT_MODELS[self.provider]
        self.temperature = float(self.cfg.get("temperature", 0.1))
        self.max_tokens = int(self.cfg.get("max_tokens", 8000))
        self.timeout = int(self.cfg.get("timeout_seconds", 180))
        self._client = None
        self.disabled_reason = ""
        self.calls = 0
        self.usage = {"input_tokens": 0, "output_tokens": 0}
        self._init()

    # ------------------------------------------------------------------ setup
    def _init(self) -> None:
        try:
            if self.provider == "anthropic":
                if not os.getenv("ANTHROPIC_API_KEY"):
                    self.disabled_reason = "ANTHROPIC_API_KEY not set"
                    return
                import anthropic
                self._client = anthropic.Anthropic(timeout=self.timeout)
            elif self.provider == "openai":
                key = _env("OPENAI_API_KEY")
                if not key:
                    self.disabled_reason = "OPENAI_API_KEY not set"
                    return
                if looks_like_azure_key(key):
                    self.disabled_reason = ("OPENAI_API_KEY does not start with 'sk-' – it looks like an Azure OpenAI key. "
                                            "Set LLM_PROVIDER=azure_openai and AZURE_OPENAI_ENDPOINT "
                                            "(https://<resource>.openai.azure.com or .cognitiveservices.azure.com)")
                    return
                import openai
                self._client = openai.OpenAI(api_key=key, timeout=self.timeout)
            elif self.provider == "azure_openai":
                a = azure_settings()
                if not (a["key"] and a["endpoint"]):
                    missing = [n for n, v in (("AZURE_OPENAI_ENDPOINT", a["endpoint"]),
                                              ("AZURE_OPENAI_API_KEY (or OPENAI_API_KEY)", a["key"])) if not v]
                    self.disabled_reason = f"Azure OpenAI needs {' and '.join(missing)} in .env"
                    return
                import openai
                self._client = openai.AzureOpenAI(api_key=a["key"], azure_endpoint=a["endpoint"],
                                                  api_version=a["version"], timeout=self.timeout)
                # For Azure the "model" is the DEPLOYMENT name (often, but not always, the model name).
                self.model = a["deployment"] or (self.cfg.get("model") or "").strip() or "gpt-4o"
                self.azure = {"endpoint": a["endpoint"], "version": a["version"]}
            elif self.provider == "none" and self.requested in ("auto", ""):
                self.disabled_reason = "no OPENAI_API_KEY / ANTHROPIC_API_KEY / AZURE_OPENAI_API_KEY set"
            else:
                self.disabled_reason = f"provider '{self.provider}' -> offline mode"
        except ImportError as e:
            self.disabled_reason = f"SDK not installed: {e}"
        if self.note:
            log.warning("LLM: %s", self.note)
        if self.disabled_reason:
            log.warning("LLM disabled (%s). Running deterministic fallbacks.", self.disabled_reason)

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def describe(self) -> str:
        if not self.enabled:
            return f"offline ({self.disabled_reason})"
        if self.provider == "azure_openai":
            host = self.azure.get("endpoint", "").split("//")[-1].split("/")[0]
            return f"azure_openai/{self.model} @ {host} (api {self.azure.get('version')})"
        return f"{self.provider}/{self.model}"

    # ------------------------------------------------------------------ calls
    def complete(self, system: str, user: str, max_tokens: int | None = None) -> str:
        if not self.enabled:
            raise RuntimeError("LLM not enabled")
        max_tokens = max_tokens or self.max_tokens
        last_err = None
        for attempt in range(3):
            try:
                self.calls += 1
                if self.provider == "anthropic":
                    kwargs = dict(model=self.model, max_tokens=max_tokens, system=system,
                                  messages=[{"role": "user", "content": user}])
                    # anthropic SDK >= 1.0 removed `temperature`; only send it where supported.
                    if self._supports("temperature"):
                        kwargs["temperature"] = self.temperature
                    resp = self._client.messages.create(**kwargs)
                    self.usage["input_tokens"] += getattr(resp.usage, "input_tokens", 0) or 0
                    self.usage["output_tokens"] += getattr(resp.usage, "output_tokens", 0) or 0
                    return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
                messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
                if is_reasoning_model(self.model) or not self._openai_max_tokens:
                    # GPT-5 / o-series: max_completion_tokens (includes hidden reasoning tokens), no temperature
                    kwargs = dict(model=self.model, messages=messages,
                                  max_completion_tokens=max(max_tokens * 2, 16000) if is_reasoning_model(self.model) else max_tokens)
                else:
                    kwargs = dict(model=self.model, max_tokens=max_tokens, messages=messages)
                    if self._openai_temperature:
                        kwargs["temperature"] = self.temperature
                try:
                    resp = self._client.chat.completions.create(**kwargs)
                except Exception as e:  # newer OpenAI models reject max_tokens / temperature
                    msg = str(e)
                    if ("max_tokens" in msg or "temperature" in msg) and "max_tokens" in kwargs:
                        kwargs["max_completion_tokens"] = kwargs.pop("max_tokens")
                        kwargs.pop("temperature", None)
                        self._openai_temperature = self._openai_max_tokens = False
                        resp = self._client.chat.completions.create(**kwargs)
                    else:
                        raise
                if resp.usage:
                    self.usage["input_tokens"] += resp.usage.prompt_tokens or 0
                    self.usage["output_tokens"] += resp.usage.completion_tokens or 0
                return resp.choices[0].message.content or ""
            except Exception as e:
                last_err = e
                if not self._is_transient(e):
                    # Wrong key, unknown model, bad parameter ... retrying will not help.
                    log.error("LLM call failed (not retrying): %s", e)
                    status = getattr(e, "status_code", None)
                    if status in (401, 403) and self._switch_provider(f"{self.provider} rejected the key ({status})"):
                        continue   # retry the same request with the other provider
                    if status in (401, 403, 404):
                        # Invalid key / no access / unknown model: every later call would fail the same way.
                        if self.provider == "azure_openai":
                            hint = {401: "Azure rejected the key – check AZURE_OPENAI_API_KEY/OPENAI_API_KEY belongs to "
                                         f"{self.azure.get('endpoint')}",
                                    403: "key has no access to this Azure resource/deployment",
                                    404: f"deployment '{self.model}' not found on {self.azure.get('endpoint')} "
                                         f"(api-version {self.azure.get('version')}) – set AZURE_OPENAI_DEPLOYMENT to the "
                                         "deployment name shown in Azure AI Foundry"}[status]
                        else:
                            hint = {401: "API key rejected – check the key in .env",
                                    403: "key has no access to this model/API",
                                    404: f"model '{self.model}' not found – set LLM_MODEL in .env"}[status]
                        self.disabled_reason = f"{self.provider} {status}: {hint}"
                        self._client = None
                        log.error("LLM switched OFF for the rest of this run (%s). Using deterministic fallbacks.",
                                  self.disabled_reason)
                    break
                log.warning("LLM call failed (attempt %d): %s", attempt + 1, e)
                time.sleep(2 ** attempt * 2)
        raise RuntimeError(f"LLM call failed: {last_err}")

    _openai_temperature = True
    _openai_max_tokens = True
    azure: dict = {}

    def _switch_provider(self, why: str) -> bool:
        """After an auth failure, move to another provider whose key is set (once per provider)."""
        tried = getattr(self, "_tried", {self.provider})
        for p in ("openai", "azure_openai", "anthropic"):
            if p not in tried and _has_key(p):
                tried.add(p)
                self._tried = tried
                old = f"{self.provider}/{self.model}"
                wanted = (self.cfg.get("model") or "").strip()
                self.provider = p
                self.model = wanted if wanted and _model_fits(p, wanted) else DEFAULT_MODELS.get(p, self.model)
                self._client, self.disabled_reason = None, ""
                self._init()
                if self.enabled:
                    log.warning("LLM: %s – switched from %s to %s/%s", why, old, self.provider, self.model)
                    return True
        self._tried = tried
        return False

    def _supports(self, param: str) -> bool:
        import inspect
        try:
            return param in inspect.signature(self._client.messages.create).parameters
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _is_transient(e: Exception) -> bool:
        if isinstance(e, (TypeError, ValueError, KeyError)):
            return False
        status = getattr(e, "status_code", None)
        if status is not None:
            return status in (408, 409, 429) or status >= 500
        name = type(e).__name__
        return any(k in name for k in ("Timeout", "Connection", "RateLimit", "Overloaded", "InternalServer"))

    def complete_json(self, system: str, user: str, max_tokens: int | None = None):
        text = self.complete(system + "\n\nRespond with ONLY valid JSON. No prose, no markdown fences.",
                             user, max_tokens)
        return extract_json(text)


def extract_json(text: str):
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = min([i for i in (text.find("{"), text.find("[")) if i != -1], default=-1)
        end = max(text.rfind("}"), text.rfind("]"))
        if start != -1 and end > start:
            return json.loads(text[start:end + 1])
        raise


def extract_code(text: str, lang: str = "python") -> str:
    m = re.search(rf"```(?:{lang})?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"
