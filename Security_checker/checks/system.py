import platform

def version_to_tuple(v):
    """Zet een versie-string om naar een tuple met ints voor vergelijking.

    Dit is bewust tolerant: niet-numerieke delen worden genegeerd.
    """
    return tuple(int(x) for x in v.split(".") if x.isdigit())

def check_os_version(baseline, env):
    """Controleer of de OS-versie minimaal de baseline haalt."""
    findings = []
    os_name = env["os"]

    min_os = baseline.get("general", {}).get("min_os_version", {})
    required = min_os.get(os_name)
    if not required:
        return findings  # geen baseline voor dit OS

    current_version = platform.release()
    try:
        # Let op: platform.release() verschilt per OS en kan non-server waarden
        # teruggeven; daarom gebruiken we `version_to_tuple` en vangen we fouten af.
        if version_to_tuple(current_version) < version_to_tuple(required):
            findings.append((
                "ALERT",
                f"OS-versie te laag: {current_version} < vereist {required} ({os_name})"
            ))
        else:
            findings.append((
                "OK",
                f"OS-versie voldoet: {current_version} (min {required})"
            ))
    except Exception as e:
        findings.append(("WARN", f"Kon OS-versie niet goed vergelijken: {e}"))

    return findings
