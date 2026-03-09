import base64
import csv
import io
import threading
import time
from collections import deque
from functools import wraps
from typing import Any

from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, session, url_for

from core.alert_engine import send_alert_popup, should_alert
from core.behavior_engine import analyze_behavior
from core.logging_engine import log_security_event
from core.paths import BASE_DIR, USERS_FILE, ensure_directories
from core.policy_engine import load_policies, save_policies
from core.prevention_engine import terminate_process
from core.process_monitor import monitor_processes
from core.storage import write_json
from core.user_store import create_user, get_user, verify_credentials

try:
    import pyotp
except Exception:
    pyotp = None

try:
    import qrcode
except Exception:
    qrcode = None

app = Flask(__name__)
app.secret_key = "change-me-in-production"


class EngineState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=2000)
        self._next_id = 1
        self._threats = 0
        self._blocked = 0
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> bool:
        with self._lock:
            if self._running:
                return False
            self._stop_event.clear()
            self._thread = threading.Thread(target=monitor_processes, args=(self.handle_event, self._stop_event), daemon=True)
            self._thread.start()
            self._running = True
            return True

    def stop(self) -> bool:
        with self._lock:
            if not self._running:
                return False
            self._stop_event.set()
            thread = self._thread
            self._running = False

        if thread:
            thread.join(timeout=2)
        return True

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "threats": self._threats,
                "blocked": self._blocked,
                "event_count": len(self._events),
            }

    def events_since(self, since_id: int) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self._events if int(e["id"]) > since_id]

    def all_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def handle_event(self, event: dict[str, Any]) -> None:
        policies = load_policies()
        analysis = analyze_behavior(event, policies)
        risk = int(analysis.get("risk_score", 0))
        threshold = int(policies.get("risk_threshold", 70))
        mode = str(policies.get("mode", "monitor"))

        if risk <= 0 and not bool(policies.get("show_safe", False)):
            return

        action = "logged"
        if risk > 0:
            self._threats += 1

        if risk >= threshold:
            if mode == "prevention":
                blocked = terminate_process(int(event.get("pid", 0)))
                action = "blocked" if blocked else "prevent_failed"
                if blocked:
                    self._blocked += 1
            elif mode == "monitor":
                alert_key = f"{event.get('name')}:{event.get('parent_name')}"
                cooldown = int(policies.get("alert_cooldown_seconds", 15))
                action = "alerted" if should_alert(alert_key, cooldown) else "logged"
            elif mode == "silent":
                action = "logged"

        if action in {"alerted", "blocked", "prevent_failed"}:
            reason_text = ", ".join(analysis.get("reasons", [])[:2]) or "Suspicious behavior detected"
            popup_title = f"InvisiShield {action.upper()}"
            popup_msg = (
                f"{event.get('name', 'process')} (PID {event.get('pid', '-')}) | "
                f"Risk {risk} | Parent {event.get('parent_name', 'unknown')} | {reason_text}"
            )
            send_alert_popup(popup_title, popup_msg)

        log_security_event(event, analysis, action)

        with self._lock:
            payload = {
                "id": self._next_id,
                "timestamp": int(time.time()),
                "pid": event.get("pid"),
                "name": event.get("name"),
                "parent_name": event.get("parent_name"),
                "cmdline": event.get("cmdline"),
                "risk_score": risk,
                "reasons": analysis.get("reasons", []),
                "decoded_command": analysis.get("decoded_command"),
                "action": action,
            }
            self._events.append(payload)
            self._next_id += 1


engine = EngineState()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user") or not session.get("otp_verified"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def init_files() -> None:
    ensure_directories()
    if not USERS_FILE.exists():
        write_json(USERS_FILE, {})
    save_policies({})


@app.route("/")
def root() -> Response:
    if session.get("user") and session.get("otp_verified"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, msg = verify_credentials(username, password)
        if ok:
            session.clear()
            session["pending_user"] = username
            return redirect(url_for("otp"))
        return render_template("login.html", error=msg)
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not pyotp:
            return render_template("signup.html", error="Install pyotp to enable OTP signup.")

        secret = pyotp.random_base32()
        ok, msg = create_user(username, password, secret)
        if not ok:
            return render_template("signup.html", error=msg)

        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="InvisiShield")
        qr_data_url = None
        if qrcode:
            qr_img = qrcode.make(otp_uri)
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")
            encoded = base64.b64encode(buf.getvalue()).decode("ascii")
            qr_data_url = f"data:image/png;base64,{encoded}"

        return render_template("signup.html", success="User created.", qr_data_url=qr_data_url)

    return render_template("signup.html")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    pending = session.get("pending_user")
    if not pending:
        return redirect(url_for("login"))

    if request.method == "POST":
        token = request.form.get("token", "").strip()
        user = get_user(pending)
        if not user:
            return redirect(url_for("login"))
        if not pyotp:
            return render_template("otp.html", error="Install pyotp to verify OTP.")

        totp = pyotp.TOTP(user.get("otp_secret", ""))
        if totp.verify(token, valid_window=1):
            session.clear()
            session["user"] = pending
            session["otp_verified"] = True
            return redirect(url_for("dashboard"))
        return render_template("otp.html", error="Invalid OTP.")

    return render_template("otp.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session.get("user"), policies=load_policies())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/status")
@login_required
def api_status():
    data = engine.status()
    data["policies"] = load_policies()
    return jsonify(data)


@app.route("/api/engine/start", methods=["POST"])
@login_required
def api_engine_start():
    started = engine.start()
    return jsonify({"started": started, "status": engine.status()})


@app.route("/api/engine/stop", methods=["POST"])
@login_required
def api_engine_stop():
    stopped = engine.stop()
    return jsonify({"stopped": stopped, "status": engine.status()})


@app.route("/api/events")
@login_required
def api_events():
    try:
        since_id = int(request.args.get("since_id", "0"))
    except ValueError:
        since_id = 0
    return jsonify({"events": engine.events_since(since_id)})


@app.route("/api/policies", methods=["GET", "POST"])
@login_required
def api_policies():
    if request.method == "GET":
        return jsonify(load_policies())

    payload = request.get_json(silent=True) or {}
    updated = save_policies(payload)
    return jsonify(updated)


@app.route("/api/export/visible.csv")
@login_required
def api_export_visible():
    data = engine.all_events()

    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["id", "timestamp", "pid", "name", "parent_name", "risk_score", "action", "cmdline", "reasons"])
    for event in data:
        writer.writerow(
            [
                event.get("id"),
                event.get("timestamp"),
                event.get("pid"),
                event.get("name"),
                event.get("parent_name"),
                event.get("risk_score"),
                event.get("action"),
                event.get("cmdline"),
                " | ".join(event.get("reasons", [])),
            ]
        )

    return Response(
        stream.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=invishield_events.csv"},
    )


@app.route("/logo")
def logo_file():
    logo = BASE_DIR / "logo.jpeg"
    if logo.exists():
        return send_file(logo)
    return Response(status=404)


if __name__ == "__main__":
    init_files()
    app.run(host="0.0.0.0", port=5000, debug=True)
