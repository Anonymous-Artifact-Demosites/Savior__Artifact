"""Backend-agnostic CAPTCHA resolution command-line handler."""

import sys
import json
import os


sys.modules.setdefault("savior.handler", sys.modules[__name__])


class CaptchaBackend:
    """Base interface for CAPTCHA resolution backends."""

    def solve(self, captcha_type, **params):
        raise NotImplementedError

    def balance(self):
        raise NotImplementedError


class ManualBackend(CaptchaBackend):
    """Interactive backend for manual CAPTCHA resolution.

    Pauses execution and waits for human input. Intended for:
    - Interactive development runs
    - Manual step-by-step tool execution
    - Environments where automated resolution is not configured

    For fully automated LLM-driven execution, configure an external
    backend via the CAPTCHA_BACKEND environment variable.
    """

    def _request_payload(self, captcha_type, params):
        return {
            "captcha_type": captcha_type,
            "params": params,
            "message": "Complete the challenge manually, then confirm completion.",
        }

    def _wait_for_signal_file(self, payload):
        request_file = os.environ.get(
            "CAPTCHA_MANUAL_REQUEST_FILE",
            os.path.join(os.getcwd(), ".savior_captcha", "manual_required.json"),
        )
        signal_file = os.environ.get(
            "CAPTCHA_MANUAL_SIGNAL_FILE",
            os.path.join(os.getcwd(), ".savior_captcha", "manual_done.txt"),
        )
        poll_seconds = float(os.environ.get("CAPTCHA_MANUAL_POLL_SECONDS", "1"))
        timeout_seconds = float(os.environ.get("CAPTCHA_MANUAL_TIMEOUT_SECONDS", "0"))

        os.makedirs(os.path.dirname(os.path.abspath(request_file)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(signal_file)), exist_ok=True)

        with open(request_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    **payload,
                    "signal_file": signal_file,
                    "instructions": (
                        "Complete the CAPTCHA or verification challenge in the browser, "
                        "then create the signal file to resume execution."
                    ),
                },
                f,
                indent=2,
            )

        print(
            json.dumps(
                {
                    "manual_intervention_required": True,
                    "request_file": request_file,
                    "signal_file": signal_file,
                    "message": "Complete the challenge in the browser, then create the signal file to continue.",
                }
            ),
            file=sys.stderr,
        )

        import time

        started = time.time()
        while True:
            if os.path.exists(signal_file):
                try:
                    with open(signal_file, "r", encoding="utf-8") as f:
                        value = f.read().strip()
                    return value or "manual_solved"
                finally:
                    try:
                        os.remove(signal_file)
                    except OSError:
                        pass
            if timeout_seconds > 0 and time.time() - started > timeout_seconds:
                raise TimeoutError("Timed out waiting for manual CAPTCHA completion")
            time.sleep(max(poll_seconds, 0.01))

    def _wait_for_gui_confirmation(self, payload):
        if os.environ.get("CAPTCHA_MANUAL_DISABLE_GUI") == "1":
            raise RuntimeError("GUI confirmation disabled")

        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(
            "CAPTCHA Resolution Required",
            (
                "Complete the CAPTCHA or verification challenge in the browser, "
                "then click OK to resume SAVIOR execution.\n\n"
                f"Type: {payload['captcha_type']}"
            ),
        )
        root.destroy()
        return "manual_solved"

    def solve(self, captcha_type, **params):
        payload = self._request_payload(captcha_type, params)
        print(
            json.dumps(payload),
            file=sys.stderr,
        )
        print("CAPTCHA result: ", end="", file=sys.stderr, flush=True)
        try:
            return input().strip() or "manual_solved"
        except EOFError:
            try:
                return self._wait_for_gui_confirmation(payload)
            except Exception:
                return self._wait_for_signal_file(payload)

    def balance(self):
        return None


def _get_backend():
    """Instantiate the configured backend.

    Reads CAPTCHA_BACKEND environment variable:
    - "manual" (default): uses ManualBackend for human-in-the-loop resolution
    - Python module path: dynamically imports the module and instantiates
      the first CaptchaBackend subclass found

    To implement a custom backend, create a module containing a class
    that extends CaptchaBackend and set CAPTCHA_BACKEND to its module path.
    """
    backend_name = os.environ.get("CAPTCHA_BACKEND", "manual").strip()

    if backend_name == "manual" or not backend_name:
        return ManualBackend()

    try:
        import importlib

        for path in (os.getcwd(), os.path.dirname(os.getcwd())):
            if path and path not in sys.path:
                sys.path.insert(0, path)

        module = importlib.import_module(backend_name)
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, CaptchaBackend)
                and attr is not CaptchaBackend
            ):
                return attr()
        raise ImportError(f"No CaptchaBackend subclass found in {backend_name}")
    except ImportError as exc:
        print(json.dumps({"success": False, "error": f"Backend not found: {exc}"}), file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    try:
        backend = _get_backend()
        command = sys.argv[1].lower()

        def code(result):
            return result["code"] if isinstance(result, dict) and "code" in result else result

        if command == "balance":
            balance = backend.balance()
            print(json.dumps({"success": True, "balance": balance}))

        elif command == "normal":
            if len(sys.argv) < 3:
                raise ValueError("Missing image_path")
            result = backend.solve("normal", file=sys.argv[2])
            print(json.dumps({"success": True, "text": code(result)}))

        elif command == "text":
            if len(sys.argv) < 3:
                raise ValueError("Missing question")
            result = backend.solve("text", question=sys.argv[2])
            print(json.dumps({"success": True, "text": code(result)}))

        elif command == "recaptcha_v2":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = backend.solve("recaptcha_v2", sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "recaptcha_v3":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            action = sys.argv[4] if len(sys.argv) > 4 else "verify"
            min_score = float(sys.argv[5]) if len(sys.argv) > 5 else 0.3
            result = backend.solve(
                "recaptcha_v3",
                sitekey=sys.argv[2],
                url=sys.argv[3],
                action=action,
                min_score=min_score,
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "recaptcha_enterprise":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = backend.solve(
                "recaptcha_enterprise", sitekey=sys.argv[2], url=sys.argv[3]
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "hcaptcha":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = backend.solve("hcaptcha", sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "funcaptcha":
            if len(sys.argv) < 4:
                raise ValueError("Missing public_key and page_url")
            result = backend.solve(
                "funcaptcha", public_key=sys.argv[2], url=sys.argv[3]
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "geetest":
            if len(sys.argv) < 5:
                raise ValueError("Missing gt, challenge, and page_url")
            result = backend.solve(
                "geetest", gt=sys.argv[2], challenge=sys.argv[3], url=sys.argv[4]
            )
            print(json.dumps({"success": True, "response": result}))

        elif command == "geetest_v4":
            if len(sys.argv) < 4:
                raise ValueError("Missing captcha_id and page_url")
            result = backend.solve("geetest_v4", captcha_id=sys.argv[2], url=sys.argv[3])
            print(json.dumps({"success": True, "response": result}))

        elif command == "turnstile":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")

            params = {"sitekey": sys.argv[2], "url": sys.argv[3]}
            if len(sys.argv) > 4 and sys.argv[4]:
                params["action"] = sys.argv[4]
            if len(sys.argv) > 5 and sys.argv[5]:
                params["data"] = sys.argv[5]
            if len(sys.argv) > 6 and sys.argv[6]:
                params["pagedata"] = sys.argv[6]

            result = backend.solve("turnstile", **params)
            response = {"success": True, "token": code(result)}
            if isinstance(result, dict) and "userAgent" in result:
                response["userAgent"] = result["userAgent"]
            print(json.dumps(response))

        elif command == "turnstile_json":
            if len(sys.argv) < 3:
                raise ValueError("Missing JSON parameters")

            params = json.loads(sys.argv[2])
            if "sitekey" not in params or "url" not in params:
                raise ValueError("Missing required fields: sitekey and url")

            result = backend.solve(
                "turnstile_json",
                sitekey=params["sitekey"],
                url=params["url"],
                action=params.get("action"),
                data=params.get("data"),
                pagedata=params.get("pagedata"),
            )
            response = {"success": True, "token": code(result)}
            if isinstance(result, dict) and "userAgent" in result:
                response["userAgent"] = result["userAgent"]
            print(json.dumps(response))

        elif command == "keycaptcha":
            if len(sys.argv) < 7:
                raise ValueError("Missing parameters")
            result = backend.solve(
                "keycaptcha",
                s_s_c_user_id=sys.argv[2],
                s_s_c_session_id=sys.argv[3],
                s_s_c_web_server_sign=sys.argv[4],
                s_s_c_web_server_sign2=sys.argv[5],
                url=sys.argv[6],
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "capy":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = backend.solve("capy", sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "grid":
            if len(sys.argv) < 3:
                raise ValueError("Missing image_path")
            result = backend.solve("grid", file=sys.argv[2])
            print(json.dumps({"success": True, "coordinates": code(result)}))

        elif command == "rotate":
            if len(sys.argv) < 3:
                raise ValueError("Missing image_path")
            result = backend.solve("rotate", file=sys.argv[2])
            print(json.dumps({"success": True, "angle": code(result)}))

        elif command == "amazon_waf":
            if len(sys.argv) < 6:
                raise ValueError("Missing parameters")
            result = backend.solve(
                "amazon_waf",
                sitekey=sys.argv[2],
                iv=sys.argv[3],
                context=sys.argv[4],
                url=sys.argv[5],
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "lemin":
            if len(sys.argv) < 5:
                raise ValueError("Missing captcha_id, div_id, and page_url")
            result = backend.solve(
                "lemin", captcha_id=sys.argv[2], div_id=sys.argv[3], url=sys.argv[4]
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "atb":
            if len(sys.argv) < 5:
                raise ValueError("Missing app_id, service_endpoint, and page_url")
            result = backend.solve(
                "atb", app_id=sys.argv[2], service_endpoint=sys.argv[3], url=sys.argv[4]
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "datadome":
            if len(sys.argv) < 4:
                raise ValueError("Missing captcha_url and page_url")
            result = backend.solve(
                "datadome", captcha_url=sys.argv[2], url=sys.argv[3]
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "cybersiara":
            if len(sys.argv) < 4:
                raise ValueError("Missing master_url_id and page_url")
            result = backend.solve(
                "cybersiara", master_url_id=sys.argv[2], url=sys.argv[3]
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "mtcaptcha":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = backend.solve("mtcaptcha", sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "friendly":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = backend.solve("friendly", sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "cutcaptcha":
            if len(sys.argv) < 5:
                raise ValueError("Missing misery_key, client_token, and page_url")
            result = backend.solve(
                "cutcaptcha", misery_key=sys.argv[2], client_token=sys.argv[3], url=sys.argv[4]
            )
            print(json.dumps({"success": True, "token": code(result)}))

        elif command == "tencent":
            if len(sys.argv) < 4:
                raise ValueError("Missing app_id and page_url")
            result = backend.solve("tencent", app_id=sys.argv[2], url=sys.argv[3])
            print(json.dumps({"success": True, "response": result}))

        elif command == "audio":
            if len(sys.argv) < 3:
                raise ValueError("Missing audio_path")
            result = backend.solve("audio", file=sys.argv[2])
            print(json.dumps({"success": True, "text": code(result)}))

        elif command == "yandex":
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = backend.solve("yandex", sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({"success": True, "token": code(result)}))

        else:
            raise ValueError(f"Unknown command: {command}")

    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}), file=sys.stderr)
        sys.exit(1)


def print_usage():
    """Print usage instructions."""
    usage = """
CAPTCHA Resolution Handler
Multi-type CAPTCHA resolution handler

Usage: python handler.py <command> [arguments...]

Top 12 Most Common:
  balance                                            - Check balance
  normal <image_path>                                - Normal captcha
  text <question>                                    - Text captcha
  recaptcha_v2 <site_key> <page_url>                - reCAPTCHA v2
  recaptcha_v3 <site_key> <page_url>                - reCAPTCHA v3
  recaptcha_enterprise <site_key> <page_url>        - reCAPTCHA Enterprise
  hcaptcha <site_key> <page_url>                    - hCaptcha
  funcaptcha <public_key> <page_url>                - FunCaptcha
  geetest <gt> <challenge> <page_url>               - GeeTest v3
  geetest_v4 <captcha_id> <page_url>                - GeeTest v4
  turnstile <site_key> <page_url>                   - Cloudflare Turnstile (Standalone)
  turnstile <site_key> <page_url> [action] [data] [pagedata]
                                                     - Cloudflare Turnstile (Challenge Page)
  turnstile_json '<json>'                           - Cloudflare Turnstile (JSON mode)
  keycaptcha <params...> <page_url>                 - KeyCaptcha
  capy <site_key> <page_url>                        - Capy Puzzle

Additional Types:
  grid <image_path>                                  - Grid/Click captcha
  rotate <image_path>                                - Rotate captcha
  amazon_waf <site_key> <iv> <context> <page_url>   - Amazon WAF
  lemin <captcha_id> <div_id> <page_url>            - Lemin
  atb <app_id> <service_endpoint> <page_url>        - Atb Captcha
  datadome <captcha_url> <page_url>                 - DataDome
  cybersiara <master_url_id> <page_url>             - CyberSiARA
  mtcaptcha <site_key> <page_url>                   - MTCaptcha
  friendly <site_key> <page_url>                    - Friendly Captcha
  cutcaptcha <misery_key> <client_token> <page_url> - Cutcaptcha
  tencent <app_id> <page_url>                       - Tencent Captcha
  audio <audio_path>                                - Audio captcha
  yandex <site_key> <page_url>                      - Yandex SmartCaptcha

Turnstile Examples:
  # Standalone (simple)
  python handler.py turnstile 3x00000000000000000000FF https://example.com

  # Challenge Page (with parameters)
  python handler.py turnstile 3x00000000000000000000FF https://example.com managed 80001aa1affffc21 3gAFo2l...UVTO=

  # JSON mode (recommended for Challenge Page)
  python handler.py turnstile_json '{"sitekey":"3x00000000000000000000FF","url":"https://example.com","action":"managed","data":"80001aa1affffc21","pagedata":"3gAFo2l...UVTO="}'

"""
    print(usage)


if __name__ == "__main__":
    main()
