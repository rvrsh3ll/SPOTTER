#!/usr/bin/env python3
"""
Focused smoke tests for upload_router format routing that does not have a
larger parser-specific smoke test.

Runs offline. Exit non-zero on any failed assertion.
"""

import os
import sys
import io
import zipfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import upload_router as ur  # noqa: E402


def main() -> int:
    ok = True

    def check(cond: bool, msg: str, detail=None) -> None:
        nonlocal ok
        print(("PASS" if cond else "FAIL") + ": " + msg)
        if not cond:
            if detail is not None:
                print(f"      got: {detail}")
            ok = False

    shareacl = (
        b"[shareacl] {\"event\":\"start\",\"host\":\"FILESERVER\"}\n"
        b"[shareacl] {\"host\":\"FILESERVER\",\"share_name\":\"Finance$\","
        b"\"acls\":[{\"trustee_name\":\"Alice\",\"trustee_domain\":\"CORP\","
        b"\"trustee_type\":\"user\",\"effective_access\":\"WRITE\","
        b"\"ace_type\":\"ACCESS_ALLOWED\",\"rights\":[\"FILE_WRITE\"]}]}\n"
        b"[shareacl] {\"event\":\"done\",\"count\":1}\n"
    )
    check(ur.detect_format(shareacl, "shareacl.txt") == "shareacl",
          "ShareACL console output is detected before generic text")
    shareacl_result = ur.route_bytes(shareacl, filename="shareacl.txt", ingest=False)
    check(shareacl_result["format"] == "shareacl", "ShareACL route reports its format")
    check(shareacl_result["nodes_count"] == 2 and shareacl_result["edges_count"] == 1,
          "ShareACL emits a share, trustee, and permission edge",
          (shareacl_result["nodes_count"], shareacl_result["edges_count"]))
    check(shareacl_result["errors"] == [],
          "valid ShareACL output has no parse errors", shareacl_result["errors"])
    check(any(edge["label"] == "SHARE_WRITE" for edge in shareacl_result["edges"]),
          "ShareACL preserves effective permission labels", shareacl_result["edges"])

    malformed_shareacl = b"[shareacl] {\"host\":\"FILESERVER\",\n"
    malformed_result = ur.route_bytes(malformed_shareacl, filename="shareacl.txt", ingest=False)
    check(malformed_result["format"] == "shareacl", "malformed ShareACL stays on its parser")
    check(any("invalid ShareACL JSON" in error for error in malformed_result["errors"]),
          "malformed ShareACL JSON is reported", malformed_result["errors"])

    sample = (
        b'{"host":"vpn.example.com","source":"crtsh"}\n'
        b'{"url":"https://admin.example.com:8443/login","status_code":200,"tech":["nginx"]}\n'
        b'{"input":"api.example.com","port":443}'
    )
    check(ur.detect_format(sample, "subfinder-example.json") == "subdomain_jsonl",
          "subfinder JSON-lines detected before generic JSON")

    res = ur.route_bytes(sample, filename="subfinder-example.json", ingest=False)
    check(res["format"] == "subdomain_jsonl", "route_bytes reports subdomain_jsonl")
    check(res["nodes_count"] == 3, "three unique Subdomain nodes emitted", res["nodes_count"])
    check(res["errors"] == [], "valid JSON-lines parses without errors", res["errors"])
    fqdns = {n["data"].get("fqdn") for n in res["nodes"]}
    check(fqdns == {"vpn.example.com", "admin.example.com", "api.example.com"},
          "host/url/input fields all produce FQDNs", fqdns)
    check(all(n["entity_type"] == "Subdomain" for n in res["nodes"]),
          "all emitted nodes are first-class Subdomain nodes")
    admin = next(n for n in res["nodes"] if n["data"].get("fqdn") == "admin.example.com")
    check(admin["data"].get("status_code") == 200 and admin["data"].get("tech") == ["nginx"],
          "httpx metadata is preserved on the Subdomain node", admin["data"])

    malformed = b'{"host":"ok.example.com"}\n{"host":'
    bad = ur.route_bytes(malformed, filename="subfinder-bad.json", ingest=False)
    check(bad["format"] == "subdomain_jsonl", "malformed hinted JSONL still routes to JSONL")
    check(bad["nodes_count"] == 0, "malformed JSONL emits zero nodes", bad["nodes_count"])
    check(any("invalid JSON object on line 2" in e for e in bad["errors"]),
          "malformed JSONL fails loudly", bad["errors"])

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.html", "<html><script src='jquery.js'></script></html>")
    unknown_zip = ur.route_bytes(zip_buf.getvalue(), filename="unknown-report.zip", ingest=False,
                                 context="EyeWitness Data")
    check(unknown_zip["format"] == "zip_unknown", "unknown ZIP remains zip_unknown")
    check(unknown_zip["nodes_count"] == 0, "unknown ZIP does not feed the LLM fallback",
          unknown_zip["nodes_count"])
    check(any("Archive format was not recognized" in e for e in unknown_zip["errors"]),
          "unknown ZIP fails loudly", unknown_zip["errors"])

    import llm_client
    real_client_backend = os.environ.get("SPOTTER_LLM_BACKEND")
    real_client_url = os.environ.get("VLLM_URL")
    real_client_key = os.environ.get("VLLM_API_KEY")
    real_client_model = os.environ.get("VLLM_MODEL")
    real_client_post = llm_client.requests.post
    client_calls = []

    class FakeClientResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": '{"ok":true}'}}]}

    def fake_client_post(url, **kwargs):
        client_calls.append((url, kwargs))
        return FakeClientResponse()

    try:
        os.environ["SPOTTER_LLM_BACKEND"] = "vllm"
        os.environ["VLLM_URL"] = "http://vllm:8000/v1"
        os.environ["VLLM_API_KEY"] = "smoke-key"
        os.environ["VLLM_MODEL"] = "Qwen/Qwen3-32B"
        llm_client.requests.post = fake_client_post
        client_content = llm_client.chat_completion([{"role": "user", "content": "return JSON"}])
        check(client_content == '{"ok":true}',
              "shared LLM client parses vLLM chat content", client_content)
        check(client_calls and client_calls[0][0] == "http://vllm:8000/v1/chat/completions",
              "shared LLM client targets the vLLM chat endpoint", client_calls)
        check(client_calls[0][1]["json"]["response_format"] == {"type": "json_object"},
              "shared LLM client requests a JSON object", client_calls[0][1]["json"])
    finally:
        llm_client.requests.post = real_client_post
        if real_client_backend is None:
            os.environ.pop("SPOTTER_LLM_BACKEND", None)
        else:
            os.environ["SPOTTER_LLM_BACKEND"] = real_client_backend
        for key, value in (("VLLM_URL", real_client_url), ("VLLM_API_KEY", real_client_key),
                           ("VLLM_MODEL", real_client_model)):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    # The vLLM branch must use the OpenAI-compatible request/response shape,
    # while preserving the same low-confidence extraction contract.
    real_backend = os.environ.get("SPOTTER_LLM_BACKEND")
    real_vllm_url = os.environ.get("VLLM_URL")
    real_vllm_key = os.environ.get("VLLM_API_KEY")
    real_vllm_model = os.environ.get("VLLM_MODEL")
    real_requests = sys.modules.get("requests")
    vllm_calls = []

    class FakeVLLMResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": '[{"type":"Domain","label":"vpn.example.com"}]'}}]}

    class FakeVLLMRequests:
        @staticmethod
        def post(url, **kwargs):
            vllm_calls.append((url, kwargs))
            return FakeVLLMResponse()

    try:
        os.environ["SPOTTER_LLM_BACKEND"] = "vllm"
        os.environ["VLLM_URL"] = "http://vllm:8000/v1"
        os.environ["VLLM_API_KEY"] = "smoke-key"
        os.environ["VLLM_MODEL"] = "Qwen/Qwen3-32B"
        sys.modules["requests"] = FakeVLLMRequests
        vllm_nodes, vllm_edges = ur._parse_text_via_llm("vpn.example.com is in scope")
        check(len(vllm_nodes) == 1 and not vllm_edges,
              "vLLM extraction returns the normalised entity contract", vllm_nodes)
        check(vllm_calls and vllm_calls[0][0] == "http://vllm:8000/v1/chat/completions",
              "vLLM extraction uses /v1/chat/completions", vllm_calls)
        request = vllm_calls[0][1]
        check(request["headers"]["Authorization"] == "Bearer smoke-key",
              "vLLM extraction sends the configured API key", request.get("headers"))
        check(request["json"]["model"] == "Qwen/Qwen3-32B"
              and request["json"]["messages"][0]["role"] == "user"
              and request["json"]["stream"] is False,
              "vLLM extraction sends model, messages, and non-streaming options",
              request.get("json"))
    finally:
        if real_backend is None:
            os.environ.pop("SPOTTER_LLM_BACKEND", None)
        else:
            os.environ["SPOTTER_LLM_BACKEND"] = real_backend
        if real_vllm_url is None:
            os.environ.pop("VLLM_URL", None)
        else:
            os.environ["VLLM_URL"] = real_vllm_url
        if real_vllm_key is None:
            os.environ.pop("VLLM_API_KEY", None)
        else:
            os.environ["VLLM_API_KEY"] = real_vllm_key
        if real_vllm_model is None:
            os.environ.pop("VLLM_MODEL", None)
        else:
            os.environ["VLLM_MODEL"] = real_vllm_model
        if real_requests is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = real_requests

    real_parse_text = ur._parse_text_via_llm
    real_mode = os.environ.get("SPOTTER_LLM_TEXT_INGEST_MODE")
    real_flowsint = sys.modules.get("flowsint_client")
    calls = []

    def fake_parse_text(_text, context=""):
        return [ur._typed_node("llm:0", "Domain", "vpn.example.com", {}, "llm_extraction")], []

    fake_fc = types.SimpleNamespace(
        batch_import=lambda nodes, edges, sketch_id=None: calls.append((nodes, edges, sketch_id)) or {"nodes_created": len(nodes)}
    )
    ur._parse_text_via_llm = fake_parse_text
    sys.modules["flowsint_client"] = fake_fc
    try:
        os.environ["SPOTTER_LLM_TEXT_INGEST_MODE"] = "preview"
        preview = ur.route_bytes(b"vpn.example.com is in scope", filename="notes.txt", ingest=True)
        check(preview["format"] == "text_llm", "plain text still routes through LLM extraction")
        check(preview["nodes_count"] == 1, "LLM preview returns parsed nodes", preview["nodes_count"])
        check(preview.get("ingestion", {}).get("skipped") is True,
              "LLM preview skips graph import", preview.get("ingestion"))
        check(preview.get("report", {}).get("review_required") is True,
              "LLM preview reports review-required status", preview.get("report"))
        check(calls == [], "LLM preview does not call batch_import", calls)

        os.environ.pop("SPOTTER_LLM_TEXT_INGEST_MODE", None)
        normal = ur.route_bytes(b"vpn.example.com is in scope", filename="notes.txt", ingest=True)
        check(normal.get("ingest_ok") is True, "default LLM text mode still imports", normal)
        check(len(calls) == 1, "default LLM text mode calls batch_import once", calls)
    finally:
        ur._parse_text_via_llm = real_parse_text
        if real_mode is None:
            os.environ.pop("SPOTTER_LLM_TEXT_INGEST_MODE", None)
        else:
            os.environ["SPOTTER_LLM_TEXT_INGEST_MODE"] = real_mode
        if real_flowsint is None:
            sys.modules.pop("flowsint_client", None)
        else:
            sys.modules["flowsint_client"] = real_flowsint

    print()
    print("SMOKE " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())