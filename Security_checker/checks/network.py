import subprocess
import platform

def _run(cmd):
    """Voer een command uit en vang output af om te parsen.

    Let op: we gooien bewust géén exception op een non-zero exit code; tools kunnen
    ontbreken of falen door beperkte rechten. Callers kunnen lege/partiële output
    vervolgens conservatief interpreteren.
    """
    return subprocess.run(cmd, capture_output=True, text=True)

def get_open_ports_linux():
    # Gebruikt `ss -tuln` (TCP/UDP, luisteren, numeriek). Dit is best-effort:
    # outputformaten verschillen per distro/versie, en container/netns kan host-
    # poorten verbergen.
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
    # Gebruikt `netstat -ano` en filtert op LISTENING. Dit kan onderrapporteren
    # bij gelokaliseerde output of wanneer rechten/beleid zicht beperken.
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
    # Best-effort detectie: pak ufw als die bestaat, anders systemd firewalld.
    # Dit dekt géén nftables/iptables setups die niet via deze services lopen.
    ufw = _run(["which", "ufw"])
    if ufw.returncode == 0:
        status = _run(["ufw", "status"])
        return "Status: active" in status.stdout
    # firewalld check
    fw = _run(["systemctl", "is-active", "firewalld"])
    return "active" in fw.stdout

def firewall_enabled_windows():
    # `netsh advfirewall` rapporteert per profiel; we zien elke "ON" als actief.
    # (Sommige systemen formatteren spaties anders, vandaar twee string checks.)
    cmd = ["netsh", "advfirewall", "show", "allprofiles"]
    result = _run(cmd)
    return "State ON" in result.stdout or "State                  ON" in result.stdout

def check_firewall_and_ports(baseline, env):
    """Controleer firewallstatus en blootgestelde poorten tegen de baseline.

    Verwachte baseline-structuur:
      - firewall.required: bool
      - firewall.allowed_ports: list[int]
      - containers.relaxed_firewall_checks: bool

    Verwacht in `env`:
      - os: "linux" | "windows" (andere waarden tellen als onbekend/unsupported)
      - is_container: bool
    """
    findings = []
    os_name = env["os"]
    is_container = env["is_container"]

    fw_cfg = baseline.get("firewall", {})
    required = fw_cfg.get("required", False)
    allowed_ports = set(fw_cfg.get("allowed_ports", []))


    # Containers delegeren firewalling vaak naar host/orchestratie. Indien zo
    # geconfigureerd, versoepelen we alleen de firewall-eis; open poorten blijven
    # relevant voor exposure-auditing.
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
