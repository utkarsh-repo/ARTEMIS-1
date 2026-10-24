from __future__ import annotations
import json, os
import requests

class ProviderError(RuntimeError): pass

class LLMProvider:
    def __init__(self, provider="offline"):
        self.provider=provider.lower()
        if self.provider == "openai":
            self.model = os.environ.get("OPENAI_MODEL", "gpt-6-luna")
        elif self.provider == "anthropic":
            self.model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")
        else:
            self.model = "offline"
        self.last_usage = {"input_tokens": None, "output_tokens": None}
    def complete_json(self, system, payload, *, max_output_tokens=900):
        self.last_usage = {"input_tokens": None, "output_tokens": None}
        if self.provider=="offline": raise ProviderError("offline")
        prompt=json.dumps(payload,ensure_ascii=False)
        try:
            if self.provider=="openai":
                key=os.environ["OPENAI_API_KEY"]
                base_url=os.environ.get("OPENAI_BASE_URL","https://api.openai.com/v1").rstrip("/")
                r=requests.post(base_url+"/chat/completions",
                    headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"},
                    json={"model":self.model,"temperature":0,
                          "max_tokens":int(max_output_tokens),
                          "response_format":{"type":"json_object"},
                          "messages":[{"role":"system","content":system},{"role":"user","content":prompt}]},timeout=30)
                r.raise_for_status()
                body = r.json()
                usage = body.get("usage") or {}
                self.last_usage = {"input_tokens": usage.get("prompt_tokens"),
                                   "output_tokens": usage.get("completion_tokens")}
                return json.loads(body["choices"][0]["message"]["content"])
            if self.provider=="anthropic":
                key=os.environ["ANTHROPIC_API_KEY"]
                base_url=os.environ.get("ANTHROPIC_BASE_URL","https://api.anthropic.com/v1").rstrip("/")
                r=requests.post(base_url+"/messages",
                    headers={"x-api-key":key,"anthropic-version":"2023-06-01","content-type":"application/json"},
                    json={"model":self.model,"max_tokens":int(max_output_tokens),
                          "system":system,"messages":[{"role":"user","content":prompt}]},timeout=30)
                r.raise_for_status()
                body = r.json()
                usage = body.get("usage") or {}
                self.last_usage = {"input_tokens": usage.get("input_tokens"),
                                   "output_tokens": usage.get("output_tokens")}
                return json.loads(body["content"][0]["text"])
            raise ProviderError("AI_PROVIDER must be openai, anthropic or offline")
        except Exception as exc:
            raise ProviderError(type(exc).__name__) from exc
