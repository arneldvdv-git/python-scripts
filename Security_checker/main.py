import platform
import yaml
import os
from checks import system, network, services, files

def load_baseline(path="baseline.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def detect_environment():
    info = {
        "os": platform.system().lower(),  # 'windows', 'linux', 'darwin'
        "is_container": False,
    }

    # Eenvoudige container-detectie
    try:
        # 1) Omgevingsvariabelen (Kubernetes)
        if "KUBERNETES_SERVICE_HOST" in os.environ:
            info["is_container"] = True

        # 2) cgroup check (Docker/K8s)
        if os.path.exists("/proc/1/cgroup"):
            with open("/proc/1/cgroup") as f:
                data = f.read()
                if "docker" in data or "kubepods" in data:
                    info["is_container"] = True
    except Exception:
        pass

    return info

def run_checks(baseline, env):
    findings = []

    findings += system.check_os_version(baseline, env)
    findings += network.check_firewall_and_ports(baseline, env)
    findings += services.check_services(baseline, env)
    findings += files.check_files(baseline, env)

    return findings

def print_report(findings):
    print("=== Security Baseline Report ===")
    if not findings:
        print("[OK] Geen afwijkingen gevonden t.o.v. baseline.")
        return

    for level, msg in findings:
        print(f"[{level}] {msg}")

if __name__ == "__main__":
    baseline = load_baseline()
    env = detect_environment()
    findings = run_checks(baseline, env)
    print_report(findings)
