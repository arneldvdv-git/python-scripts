import os
import stat

def mode_to_str(mode):
    # bijv. 0o644 -> "644"
    return oct(mode)[-3:]

def check_files(baseline, env):
    findings = []
    os_name = env["os"]

    # Voor nu: alleen Linux-bestanden, maar je kunt hier Windows-paths toevoegen
    cfg = baseline.get("files", {}).get("check", [])
    if os_name != "linux":
        if cfg:
            findings.append(("INFO", "Bestandspermissie-checks zijn alleen geconfigureerd voor Linux in deze baseline."))
        return findings

    for item in cfg:
        path = item.get("path")
        expected_mode = item.get("mode")
        if not path or not expected_mode:
            continue

        if not os.path.exists(path):
            findings.append(("ALERT", f"Bestand ontbreekt: {path}"))
            continue

        st = os.stat(path)
        actual_mode = mode_to_str(st.st_mode)
        if actual_mode == expected_mode:
            findings.append(("OK", f"Permissies OK voor {path}: {actual_mode}"))
        else:
            findings.append(("ALERT", f"Permissies afwijkend voor {path}: {actual_mode} (verwacht {expected_mode})"))

    return findings
