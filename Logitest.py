#!/usr/bin/env python3

import os
import subprocess
import re

SCRIPT_DIR = os.getcwd()
OUTPUT_ROOT = os.path.join(SCRIPT_DIR, "Logpull_Findings")

CATEGORIES = [
    "WIFI_CLIENT",
    "BACKHAUL",
    "BAND_STEERING",
    "WAN",
    "CLOUD_MQTT",
    "SYSTEM_HEALTH",
    "RADIO",
    "DRIVER",
    "SECURITY",
    "OVSDB",
    "DPI_FLOW",
    "HEALTHCHECK",
]

CATEGORY_MAP = {
    "1": "WIFI_CLIENT",
    "2": "BACKHAUL",
    "3": "BAND_STEERING",
    "4": "WAN",
    "5": "CLOUD_MQTT",
    "6": "SYSTEM_HEALTH",
    "7": "RADIO",
    "8": "DRIVER",
    "9": "SECURITY",
    "10": "OVSDB",
    "11": "DPI_FLOW",
    "12": "HEALTHCHECK",
}

CATEGORY_DISPLAY = {
    "1": ("WIFI_CLIENT", "Client cannot connect, authentication failures, disconnections"),
    "2": ("BACKHAUL", "Nodes cannot connect or mesh link unstable"),
    "3": ("BAND_STEERING", "Clients not switching between 2.4GHz / 5GHz"),
    "4": ("WAN", "Router cannot reach internet, WAN DHCP/PPPoE problems"),
    "5": ("CLOUD_MQTT", "Cloud controller or MQTT connection failures"),
    "6": ("SYSTEM_HEALTH", "Reboots, watchdog triggers, crashes"),
    "7": ("RADIO", "Radio initialization or calibration errors"),
    "8": ("DRIVER", "Firmware crash, WMI timeout, driver failure"),
    "9": ("SECURITY", "WPA authentication or certificate issues"),
    "10": ("OVSDB", "Configuration database or sync problems"),
    "11": ("DPI_FLOW", "Traffic inspection or flow classification errors"),
    "12": ("HEALTHCHECK", "Internal health monitoring failures"),
}

PATTERNS = {
    "WIFI_CLIENT": r"CTRL-EVENT-(DISCONNECTED|SSID-TEMP-DISABLED|ASSOC-REJECT|AUTH-REJECT)|deauth(entication)?|disassoc(iation|iated)?|not associated|association rejected|auth(entication)? rejected|roam(ing)? failed|beacon loss|sa query timeout|pmksa.*fail|pmkid.*mismatch|eapol.*(timeout|failed)|osw_sta_cqm: assoc: .*troubled changed: from=no to=yes: low_(rx_mbps|snr)|osw_sta_cqm: assoc: .*troubled=yes: low_(rx_mbps|snr)|osw_sta_cqm: assoc: .*troubled changed: from=yes: low_(rx_mbps|snr) to=no|client.*(disconnect(ed)?|deauth(entication)?|disassoc(iation|iated)?|auth(entication)? failed|assoc(iation)? failed|roam(ing)? failed)|sta.*(disconnect(ed)?|deauth(entication)?|disassoc(iation|iated)?|auth(entication)? failed|assoc(iation)? failed|roam(ing)? failed)|station.*(disconnect(ed)?|deauth(entication)?|disassoc(iation|iated)?|auth(entication)? failed|assoc(iation)? failed|roam(ing)? failed)|supplicant.*(disconnect(ed)?|deauth(entication)?|disassoc(iation|iated)?|auth(entication)? failed|assoc(iation)? failed|roam(ing)? failed)",
    "BACKHAUL": r"disconnect|disconnected",
    "BAND_STEERING": r"steer|steering|band steering|sticky client|btm|11v|11k|transition request|roam candidate",
    "WAN": r"Timeout waiting for PADO|PPPoE discovery failed|Unable to complete PPPoE Discovery|PAP peer authentication failed|PAP: Received Authentication NAK|CHAP authentication failed|Received Failure|LCP: timeout sending Config-Requests|No Echo Reply received|Serial link appears to be disconnected|Connection terminated|DHCP failed to obtain lease|udhcpc: no lease|sending discover|DNS resolution failed|dns.*fail|dns.*timeout|lease lost, entering rebind state|reconnecting PPPoE",
    "SYSTEM_HEALTH": r"system health|healthcheck|health check|watchdog|wdog|reboot|power cycle|power-on|cold boot|reset reason|crash|core[- ]?dump|CORE-DUMP-MANAGER|fatal error|fatal exception|kernel panic|segmentation fault|SIG[ ]?(6|11)|oom|out of memory|OutOfMemoryError|heap space|GC overhead limit exceeded|allocation failure|PSYoungGen|memory utilization|mem usage|low memory|disk full|no space left|file system utilization|filesystem full|read-only filesystem|cpu utilization|cpu load|load average|high load|uptime|device stats|telemetry|watchdog triggered reboot|spontaneous reset|system hang|unresponsive|timeout waiting for|hung task|I/O error|I/O failure|disk error|flash error|flash manager|duplicate messages check|S3 - Check number of harvested logs|logpull - check|logpull - crash files|healthcheck - manager offline|DNS Healthcheck|manager online with ICMP enabled|manager offline with ICMP enabled",
    "CLOUD_MQTT": r"mqtt|mosquitto|broker|subscribe|subscription|publish|puback|suback|qos[0-2]|retain(ed)? message|will message|last will|keepalive|keep-alive|pingreq|pingresp|connect ack|connack|connect packet|disconnect packet|session present|clean session|client id|clientid|topic|wildcard topic|shared subscription|bridge connection|bridge mode|cloud connect|cloud connection|cloud disconnect|cloud status|cloud link|cloud gateway|cloud service|cloud backend|cloud endpoint|iot hub|device shadow|shadow update|telemetry publish|uplink|downlink|upstream|downstream|message queue|queue depth|pending messages|offline queue|resend|duplicate message|dup flag|reconnect(ing)?|connection lost|connection refused|network error|socket error|tcp reset|broken pipe|timeout|read timed out|write timed out|unreachable host|dns resolve|name resolution|auth failed|authentication failed|authorization failed|bad username or password|not authorized|invalid client id|protocol error|malformed packet|unexpected packet|unsupported protocol|retain not supported|qos not supported|max inflight|inflight messages|backpressure|throttl(e|ed|ing)|rate limit|rate limited|quota exceeded|credits exhausted|throughput|latency|round[- ]trip|ack delay|delivery failure|delivery failed|message dropped|dropped message|discarded message|retry limit|resend limit|store and forward|persisted message|persistence store|offline storage|cloud reconnect policy|backoff|exponential backoff|jitter|bridge disconnect|bridge reconnect|remote broker|remote endpoint|gateway node|edge node|edge gateway|broker cluster|cluster member|cluster state|leader election|primary node|secondary node|replication|sync state|out of sync|desync|heartbeat|keepalive timeout|lwt|last will and testament",
    "SECURITY": r"auth|authentication|authorize|authorization|login|logout|signin|sign[- ]in|session|token|password|passwd|credential|secret|keychain|mfa|2fa|two[- ]factor|otp|totp|hotp|sms code|push notification|sso|saml|idp|sp-initiated|idp-initiated|oauth|oidc|openid connect|bearer|AuthenticationServiceException|AuthenticationProvider|HttpAuthenticator|SecurityServerClientImpl|XFireFault|SocketTimeoutException|Read timed out|access denied|permission denied|not authorized|unauthorized|forbidden|insufficient permission|policy violation|account lock|locked out|too many attempts|rate limit|brute[- ]force|suspicious|anomalous login|ip block|throttle|tls|ssl|handshake|certificate|cert|x509|truststore|keystore|cipher|encryption|decryption|fail|failed|denied|error|invalid|expired|timeout|unauthorized|forbidden|mismatch|revoked|untrusted|unknown ca|signature|issuer|audience",
    "RADIO": r"temperature high|thermal throttling|thermal protection|therm_state:[234]|radio disabled - thermal emergency|shutting down wifi[0-9] for thermal protection|DFS-RADAR-DETECTED|Radar detected on channel|Radar pulse detected|channel utilization high|considering channel change|reducing channel width from .* to .*|secondary channel interference|Tx excessive retries|Rx invalid nwid|Missed beacon",
    "DPI_FLOW": r"flow classification failed|category=unknown|no SNI|flow table 80% full|flow table 90% full|flow table full, dropping new flows|fsm.*segfault|process fsm .* died unexpectedly|restarting fsm|nf_conntrack: table full, dropping packet|nfqueue drops detected|queue_dropped",
    "DRIVER": r"probe failed with error|failed to init core|firmware boot timeout|failed to boot firmware|failed to load firmware|Direct firmware load .* failed( with error -?[0-9]+)?|firmware version mismatch|signature verification failed|WMI command.*timeout|wmi_timeout_work|driver command timeout|Firmware ASSERT|FATAL: Firmware assert|firmware crash detected|crash dump collected|initiating SSR|scan failed|Failed to get scan results|Invalid station info|Invalid peer mac address|scan abort failed|set.*(key|beacon|channel|tx queue|wiphy|interface).*(failed|error)|bss.*not up|vap.*(create|delete|up|down).*(failed|error)|rekey.*(failed|error)|gtk.*(failed|error)|osw: drv: nl80211: hostap: scheduling configuration task|osw: drv: nl80211: hostap: configuration task complete|osw: drv: nl80211/.+: acl: (adding|removing)|osw: drv: nl80211.*(fail|failed|error|timeout)|wlan: \[[^]]*:(E|W):[^]]*\].*|(dhd|wl|ath11k|ath10k|ath|qcacld|qca|mt76|mt7915|iwlwifi).*(error|failed|warn(ing)?|assert(ion)?|crash(ed)?)",
    "OVSDB": r"ovsdb|config apply failed|transaction failed|schema mismatch|monitor cancelled|jsonrpc|database connection lost|ovsdb-server|ovsdb-client",
    "HEALTHCHECK": r"healthcheck|health check|selftest failed|self-test failed|sanity check failed|periodic check failed|monitor check failed",
}


def find_log_folders():
    folders = []

    for name in os.listdir(SCRIPT_DIR):
        full = os.path.join(SCRIPT_DIR, name)

        if os.path.isdir(full) and name != "Logpull_Findings":
            folders.append(full)

    return sorted(folders)


def find_message_files(log_dir):
    """
    Search ONLY in the selected folder, not in subfolders.
    """
    message_files = []

    for file in os.listdir(log_dir):
        full_path = os.path.join(log_dir, file)
        if os.path.isfile(full_path) and file.startswith("messages"):
            message_files.append(full_path)

    return sorted(message_files)


def print_menu():
    print("Select problem category:\n")

    print("1  WiFi Client Issues -> Client cannot connect, authentication failures, disconnections\n")

    print("2  Mesh & Backhaul Issues -> Nodes cannot connect or mesh link unstable\n")

    print("3  Band Steering Issues -> Clients not switching between 2.4GHz / 5GHz\n")

    print("4  WAN & Internet Issues -> Router cannot reach internet, WAN DHCP/PPPoE problems\n")

    print("5  Cloud & MQTT Issues -> Cloud controller or MQTT connection failures\n")

    print("6  System Health Issues -> Reboots, watchdog triggers, crashes\n")

    print("7  Radio & Hardware Issues -> Radio initialization or calibration errors\n")

    print("8  Driver Issues -> Firmware crash, WMI timeout, driver failure\n")

    print("9  Security & Auth Issues -> WPA authentication or certificate issues\n")

    print("10 OVSDB Config Issues -> Configuration database or sync problems\n")

    print("11 DPI & Flow Issues -> Traffic inspection or flow classification errors\n")

    print("12 Healthcheck Scripts -> Internal health monitoring failures\n")

    print("You can choose one or more numbers separated by spaces.")
    print("Example: 1 4 8")
    print()


def run_grep_grouped(pattern, log_dir):
    message_files = find_message_files(log_dir)

    if not message_files:
        return ""

    cmd = [
        "grep",
        "-inH",
        "-E",
        "--color=never",
        pattern
    ] + message_files

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    if result.returncode not in (0, 1):
        return f"Grep error:\n{result.stderr}\n"

    lines = result.stdout.splitlines()

    if not lines:
        return ""

    grouped = {}

    for line in lines:
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue

        file_name = os.path.basename(parts[0])
        finding_text = parts[2].strip()

        if file_name not in grouped:
            grouped[file_name] = []

        grouped[file_name].append(finding_text)

    output = []

    for file_name in sorted(grouped.keys()):
        output.append("======================================")
        output.append(f"FILE: {file_name}")
        output.append("======================================")
        output.append("")

        output.extend(grouped[file_name])
        output.append("")

    return "\n".join(output)


def write_category_file(path, category, pattern, findings):
    with open(path, "w", encoding="utf-8") as f:
        f.write("==================================================\n")
        f.write(f"CATEGORY: {category}\n")
        f.write("==================================================\n\n")
        f.write("PATTERN USED:\n")
        f.write(pattern + "\n\n")
        f.write("FINDINGS:\n\n")

        if findings.strip():
            f.write(findings)
            if not findings.endswith("\n"):
                f.write("\n")
        else:
            f.write("No findings.\n")


def append_to_your_problem(path, category, findings):
    with open(path, "a", encoding="utf-8") as f:
        f.write("==================================================\n")
        f.write(f"YOUR PROBLEM: {category}\n")
        f.write("==================================================\n\n")

        if findings.strip():
            f.write(findings)
            if not findings.endswith("\n"):
                f.write("\n")
        else:
            f.write("No findings.\n")

        f.write("\n")


def normalize_mac(mac):
    mac = mac.strip().lower()
    mac = mac.replace("-", "").replace(":", "").replace(".", "")

    if len(mac) != 12:
        return None

    if not re.fullmatch(r"[0-9a-f]{12}", mac):
        return None

    return mac


def get_mac_variants(mac_normalized):
    colon = ":".join(mac_normalized[i:i + 2] for i in range(0, 12, 2))
    dash = "-".join(mac_normalized[i:i + 2] for i in range(0, 12, 2))
    plain = mac_normalized
    dotted = ".".join([mac_normalized[0:4], mac_normalized[4:8], mac_normalized[8:12]])

    return {
        colon.lower(),
        colon.upper(),
        dash.lower(),
        dash.upper(),
        plain.lower(),
        plain.upper(),
        dotted.lower(),
        dotted.upper(),
    }


def filter_grouped_findings_by_mac(findings, mac_input):
    if not findings.strip():
        return ""

    mac_normalized = normalize_mac(mac_input)
    if not mac_normalized:
        return ""

    mac_variants = get_mac_variants(mac_normalized)
    lines = findings.splitlines()

    filtered_output = []
    current_file_header = []
    current_file_findings = []

    def flush_current_block():
        if current_file_findings:
            filtered_output.extend(current_file_header)
            filtered_output.append("")
            filtered_output.extend(current_file_findings)
            filtered_output.append("")

    i = 0
    while i < len(lines):
        line = lines[i]

        if line == "======================================" and i + 1 < len(lines) and lines[i + 1].startswith("FILE: "):
            flush_current_block()

            current_file_header = [
                lines[i],
                lines[i + 1],
            ]

            if i + 2 < len(lines) and lines[i + 2] == "======================================":
                current_file_header.append(lines[i + 2])
                i += 3
            else:
                i += 2

            current_file_findings = []
            continue

        line_lower = line.lower()
        if any(variant.lower() in line_lower for variant in mac_variants):
            current_file_findings.append(line)

        i += 1

    flush_current_block()

    return "\n".join(filtered_output).strip()


def safe_mac_filename(mac_input):
    return re.sub(r"[^0-9A-Fa-f]", "_", mac_input.strip())


def main():
    print("==================================================")
    print("LOGPULL GREP ANALYZER")
    print("==================================================")
    print()

    folders = find_log_folders()

    if not folders:
        print("No log folders found in the same folder as this script.")
        return

    print("Log folders found:")
    for i, folder in enumerate(folders, 1):
        print(f"  {i}) {os.path.basename(folder)}")
    print()

    folder_choice = input("Select the folder number to scan: ").strip()

    if not folder_choice.isdigit():
        print("Invalid selection.")
        return

    folder_index = int(folder_choice) - 1

    if folder_index < 0 or folder_index >= len(folders):
        print("Invalid selection.")
        return

    log_dir = folders[folder_index]

    message_files = find_message_files(log_dir)

    if not message_files:
        print("No messages files found in that folder.")
        return

    print()
    print(f"Selected folder: {os.path.basename(log_dir)}")
    print(f"Found {len(message_files)} messages files.")
    print()

    print_menu()

    user_input = input("Select categories: ").strip()

    if not user_input:
        print("No categories selected.")
        return

    selected_categories = []

    for num in user_input.split():
        category = CATEGORY_MAP.get(num)

        if category and category not in selected_categories:
            selected_categories.append(category)

    if not selected_categories:
        print("No valid categories selected.")
        return

    print()
    mac_input = input("Do you want to add a MAC address filter? Type MAC address or no: ").strip()

    use_mac_filter = False

    if mac_input.lower() != "no":
        normalized_mac = normalize_mac(mac_input)

        if normalized_mac is None:
            print("Invalid MAC address format.")
            print("Continuing without MAC filter.")
        else:
            use_mac_filter = True

    run_name = os.path.basename(log_dir)
    output_dir = os.path.join(OUTPUT_ROOT, run_name)
    os.makedirs(output_dir, exist_ok=True)

    your_problem_path = os.path.join(output_dir, "Your_Problem.txt")

    with open(your_problem_path, "w", encoding="utf-8") as f:
        f.write("==================================================\n")
        f.write("YOUR PROBLEM FINDINGS\n")
        f.write("==================================================\n\n")
        f.write("SELECTED CATEGORIES:\n")
        f.write(", ".join(selected_categories) + "\n\n")

    selected_findings_for_mac = []

    for category in CATEGORIES:
        pattern = PATTERNS[category]
        findings = run_grep_grouped(pattern, log_dir)

        category_file = os.path.join(output_dir, f"{category}.txt")
        write_category_file(category_file, category, pattern, findings)

        if category in selected_categories:
            append_to_your_problem(your_problem_path, category, findings)
            selected_findings_for_mac.append((category, findings))

    mac_file_path = None

    if use_mac_filter:
        safe_name = safe_mac_filename(mac_input)
        mac_file_path = os.path.join(output_dir, f"your_mac_{safe_name}.txt")

        with open(mac_file_path, "w", encoding="utf-8") as f:
            f.write("==================================================\n")
            f.write(f"MAC FILTER: {mac_input}\n")
            f.write("==================================================\n\n")
            f.write("SELECTED CATEGORIES:\n")
            f.write(", ".join(selected_categories) + "\n\n")

        for category, findings in selected_findings_for_mac:
            filtered = filter_grouped_findings_by_mac(findings, mac_input)

            with open(mac_file_path, "a", encoding="utf-8") as f:
                f.write("==================================================\n")
                f.write(f"CATEGORY: {category}\n")
                f.write("==================================================\n\n")

                if filtered.strip():
                    f.write(filtered)
                    if not filtered.endswith("\n"):
                        f.write("\n")
                else:
                    f.write("No findings for this MAC address in this category.\n")

                f.write("\n")

    print()
    print("Done.")
    print()
    print("Created files:")
    for category in CATEGORIES:
        print(f"  - {os.path.join(output_dir, category + '.txt')}")
    print(f"  - {your_problem_path}")

    if mac_file_path:
        print(f"  - {mac_file_path}")

    print()


if __name__ == "__main__":
    main()
