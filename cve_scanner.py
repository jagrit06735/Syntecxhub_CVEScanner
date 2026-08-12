import socket
import requests
import json
import re
from datetime import datetime

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

print("=" * 60)
print("        VULNERABILITY / CVE SCANNER")
print("             Developed by Jagrit")
print("=" * 60)

target = input("\nEnter Target IP/Host: ").strip()

ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

open_services = []


def get_banner(target, port):
    banner = ""

    try:
        sock = socket.socket()
        sock.settimeout(2)

        if port == 80:
            sock.connect((target, port))
            sock.sendall(
                b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
            )
            banner = sock.recv(2048).decode(errors="ignore")

            server_match = re.search(
                r"Server:\s*([^\r\n]+)",
                banner,
                re.IGNORECASE
            )

            if server_match:
                return server_match.group(1).strip()

        elif port == 3306:
            sock.connect((target, port))
            banner = sock.recv(1024).decode(
                errors="ignore"
            ).strip()

            return banner

        else:
            sock.connect((target, port))
            banner = sock.recv(1024).decode(
                errors="ignore"
            ).strip()

            return banner

    except:
        return ""

    finally:
        try:
            sock.close()
        except:
            pass


def extract_version(banner):
    if not banner:
        return None

    # MariaDB banner:
    # 5.5.5-10.4.32-MariaDB
    mariadb = re.search(
        r"(\d+\.\d+\.\d+)-MariaDB",
        banner,
        re.IGNORECASE
    )

    if mariadb:
        return mariadb.group(1)

    # Apache banner:
    # Apache/2.4.58
    apache = re.search(
        r"Apache/(\d+\.\d+\.\d+)",
        banner,
        re.IGNORECASE
    )

    if apache:
        return apache.group(1)

    # General version
    match = re.search(
        r"\b\d+\.\d+\.\d+\b",
        banner
    )

    if match:
        return match.group(0)

    return None


print(f"\nScanning target: {target}")
print("-" * 60)

for port, service in ports.items():

    sock = socket.socket()
    sock.settimeout(0.5)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:

            print(f"[OPEN] {port:<5} {service}")

            banner = get_banner(target, port)

            open_services.append({
                "port": port,
                "service": service,
                "banner": banner
            })

    except socket.gaierror:
        print("[ERROR] Invalid hostname/IP address")
        break

    except Exception as e:
        print(f"[ERROR] Port {port}: {e}")

    finally:
        sock.close()


print("\n" + "=" * 60)
print("SERVICE DETECTION COMPLETE")
print("=" * 60)

if not open_services:
    print("No open services detected.")

for item in open_services:

    print(f"\nPort    : {item['port']}")
    print(f"Service : {item['service']}")
    print(
        f"Banner  : "
        f"{item['banner'] or 'Not detected'}"
    )


# ---------------------------------------------------------
# CVE LOOKUP
# ---------------------------------------------------------

print("\n" + "=" * 60)
print("CVE DATABASE LOOKUP")
print("=" * 60)

cve_results = []


def search_cves(service, banner):

    version = extract_version(banner)

    if not version:
        print(
            f"[INFO] {service}: version not detected - "
            "CVE lookup skipped."
        )
        return []

    # Use service + version for NVD keyword search
    keyword = f"{service} {version}"

    print(
        f"\n[SEARCH] Searching NVD for: {keyword}"
    )

    try:

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5
        }

        response = requests.get(
            NVD_API,
            params=params,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        print(
            f"[FOUND] {len(vulnerabilities)} "
            "potential CVE match(es)"
        )

        results = []

        for vulnerability in vulnerabilities:

            cve = vulnerability.get(
                "cve",
                {}
            )

            cve_id = cve.get(
                "id",
                "Unknown"
            )

            description = "No description available."

            descriptions = cve.get(
                "descriptions",
                []
            )

            for desc in descriptions:

                if desc.get("lang") == "en":

                    description = desc.get(
                        "value",
                        description
                    )

                    break

            severity = "UNKNOWN"
            score = "N/A"

            metrics = cve.get(
                "metrics",
                {}
            )

            # CVSS v3.1
            if metrics.get("cvssMetricV31"):

                metric = metrics[
                    "cvssMetricV31"
                ][0]

                cvss_data = metric.get(
                    "cvssData",
                    {}
                )

                severity = cvss_data.get(
                    "baseSeverity",
                    "UNKNOWN"
                )

                score = cvss_data.get(
                    "baseScore",
                    "N/A"
                )

            # CVSS v3.0
            elif metrics.get("cvssMetricV30"):

                metric = metrics[
                    "cvssMetricV30"
                ][0]

                cvss_data = metric.get(
                    "cvssData",
                    {}
                )

                severity = cvss_data.get(
                    "baseSeverity",
                    "UNKNOWN"
                )

                score = cvss_data.get(
                    "baseScore",
                    "N/A"
                )

            result = {
                "service": service,
                "version": version,
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": score,
                "description": description
            }

            results.append(result)

            print(
                f"  {cve_id} | "
                f"Severity: {severity} | "
                f"CVSS: {score}"
            )

        return results

    except requests.exceptions.RequestException as e:

        print(
            f"[ERROR] NVD API request failed: {e}"
        )

        return []

    except Exception as e:

        print(
            f"[ERROR] CVE processing failed: {e}"
        )

        return []


for item in open_services:

    results = search_cves(
        item["service"],
        item["banner"]
    )

    cve_results.extend(results)


# ---------------------------------------------------------
# SEVERITY SUMMARY
# ---------------------------------------------------------

severity_summary = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "UNKNOWN": 0
}

for result in cve_results:

    severity = result["severity"].upper()

    if severity in severity_summary:
        severity_summary[severity] += 1

    else:
        severity_summary["UNKNOWN"] += 1


print("\n" + "=" * 60)
print("SEVERITY SUMMARY")
print("=" * 60)

for severity, count in severity_summary.items():

    print(
        f"{severity:<10}: {count}"
    )


# ---------------------------------------------------------
# REPORT
# ---------------------------------------------------------

scan_time = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)

report = {
    "scanner": "Syntecxhub Vulnerability / CVE Scanner",
    "target": target,
    "scan_time": scan_time,
    "services": open_services,
    "severity_summary": severity_summary,
    "cve_results": cve_results
}


# JSON REPORT

with open(
    "cve_report.json",
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        report,
        file,
        indent=4
    )


# TEXT REPORT

with open(
    "scan_report.txt",
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "VULNERABILITY / CVE SCANNER REPORT\n"
    )

    file.write(
        "=" * 60 + "\n"
    )

    file.write(
        f"Target: {target}\n"
    )

    file.write(
        f"Scan Time: {scan_time}\n\n"
    )

    file.write(
        "DETECTED SERVICES\n"
    )

    file.write(
        "-" * 60 + "\n"
    )

    for item in open_services:

        file.write(
            f"Port: {item['port']}\n"
        )

        file.write(
            f"Service: {item['service']}\n"
        )

        file.write(
            f"Banner: "
            f"{item['banner'] or 'Not detected'}\n\n"
        )

    file.write(
        "SEVERITY SUMMARY\n"
    )

    file.write(
        "-" * 60 + "\n"
    )

    for severity, count in severity_summary.items():

        file.write(
            f"{severity}: {count}\n"
        )

    file.write(
        "\nCVE RESULTS\n"
    )

    file.write(
        "-" * 60 + "\n"
    )

    if cve_results:

        for result in cve_results:

            file.write(
                f"CVE ID: {result['cve_id']}\n"
            )

            file.write(
                f"Service: {result['service']}\n"
            )

            file.write(
                f"Version: {result['version']}\n"
            )

            file.write(
                f"Severity: {result['severity']}\n"
            )

            file.write(
                f"CVSS Score: "
                f"{result['cvss_score']}\n"
            )

            file.write(
                f"Description: "
                f"{result['description']}\n"
            )

            file.write(
                "-" * 60 + "\n"
            )

    else:

        file.write(
            "No potential CVE matches found.\n"
        )


# ---------------------------------------------------------
# FINAL OUTPUT
# ---------------------------------------------------------

print("\n" + "=" * 60)
print("SCAN COMPLETED")
print("=" * 60)

print(
    f"Open Services : {len(open_services)}"
)

print(
    f"Potential CVEs: {len(cve_results)}"
)

print(
    "Text Report   : scan_report.txt"
)

print(
    "JSON Report   : cve_report.json"
)

print("=" * 60)