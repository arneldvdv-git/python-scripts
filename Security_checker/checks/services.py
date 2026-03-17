import platform
import subprocess

def _run(cmd):
    """Voer een command uit en vang output af voor parsing.

    We behandelen non-zero exit codes niet als uitzonderingen: service tooling kan
    ontbreken of beperkte rechten hebben.
    """
    return subprocess.run(cmd, capture_output=True, text=True)

def service_running_linux(name):
    # Systemd-only: detecteert geen SysV/init.d of containers zonder systemd.
    result = _run(["systemctl", "is-active", name])
    return "active" in result.stdout

def service_running_windows(name):
    # `sc query` is best-effort: output kan verschillen per locale/Windows-versie.
    result = _run(["sc", "query", name])
    return "RUNNING" in result.stdout

def check_services(baseline, env):
    """Controleer services t.o.v. de baseline.

    Baseline keys:
      - services.must_run: list[str]
      - services.forbidden: list[str]
    """
    findings = []
    os_name = env["os"]

    cfg = baseline.get("services", {})
    must_run = cfg.get("must_run", [])
    forbidden = cfg.get("forbidden", [])

    for svc in must_run:
        if os_name == "linux":
            running = service_running_linux(svc)
        elif os_name == "windows":
            running = service_running_windows(svc)
        else:
            running = False

        if running:
            findings.append(("OK", f"Vereiste service draait: {svc}"))
        else:
            findings.append(("ALERT", f"Vereiste service draait NIET: {svc}"))

    for svc in forbidden:
        if os_name == "linux":
            running = service_running_linux(svc)
        elif os_name == "windows":
            running = service_running_windows(svc)
        else:
            running = False

        if running:
            findings.append(("ALERT", f"Verboden service draait: {svc}"))
        else:
            findings.append(("OK", f"Verboden service draait niet: {svc}"))

    return findings
