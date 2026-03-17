import subprocess
import platform

def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def get_open_ports_linux():
    result = _run(["ss", "-tuln"])
    ports = set()
    for line in result.stdout.splitlines():
        if ":" in line:
            part = line.split()[-1]
            if ":" in part:
                try:
                    port = int(part.split(":")[-1])
                    ports.add(port)
                except ValueError:
                    pass
    return ports

def get_open_ports_windows():
    result = _run(["netstat", "-ano"])
    ports = set()
    for line in result.stdout.splitlines():
        if "LISTENING" in line:
            parts = line.split()
            if len(parts) >= 2:
                addr = parts[1]
                if ":" in addr:
                    try:
                        port = int(addr.split(":")[-1])
                        ports.add(port)
                    except ValueError:
                        pass
    return ports

def firewall_enabled_linux():
    # heel basic: probeer ufw, anders firewalld
    ufw = _run(["which", "ufw"])
    if ufw.returncode == 0:
        status = _run(["ufw", "status"])
        return "Status: active" in status.stdout
    # firewalld check
    fw = _run(["systemctl", "is-active", "firewalld"])
    return "active" in fw.stdout

def firewall_enabled_windows():
    cmd = ["netsh", "advfirewall", "show", "allprofiles"]
    result = _run(cmd)
    return "State ON" in result.stdout or "State                  ON" in result.stdout

def check_firewall_and_ports(baseline, env):
    findings = []
    os_name = env["os"]
    is_container = env["is_container"]

    fw_cfg = baseline.get("firewall", {})
    required = fw_cfg.get("required", False)
    allowed_ports = set(fw_cfg.get("allowed_ports", []))

    # Containers: eventueel firewall-checks overslaan of versoepelen
    container_cfg = baseline.get("containers", {})
    if is_container and container_cfg.get("relaxed_firewall_checks", False):
        findings.append(("INFO", "Container gedetecteerd: firewall-checks zijn versoepeld volgens baseline."))
        # Alleen poorten checken, geen firewall-status
        firewall_required = False
    else:
        firewall_required = required

    # Firewall status
    if firewall_required:
        if os_name == "linux":
            enabled = firewall_enabled_linux()
        elif os_name == "windows":
            enabled = firewall_enabled_windows()
        else:
            enabled = False

        if enabled:
            findings.append(("OK", "Firewall is actief."))
        else:
            findings.append(("ALERT", "Firewall is vereist maar lijkt niet actief."))

    # Open poorten
    if os_name == "linux":
        open_ports = get_open_ports_linux()
    elif os_name == "windows":
        open_ports = get_open_ports_windows()
    else:
        open_ports = set()

    for port in sorted(open_ports):
        if port in allowed_ports:
            findings.append(("OK", f"Toegestane poort open: {port}"))
        else:
            findings.append(("ALERT", f"Ongeautoriseerde poort open: {port}"))

    return findings
