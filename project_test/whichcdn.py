"""Local CDN fingerprinting demo. Results are heuristic, not authoritative."""
import csv
import io
import ipaddress
import re
import subprocess
from pathlib import Path
from flask import Flask, render_template, request, send_file, abort
import dns.resolver

app = Flask(__name__, root_path=str(Path(__file__).resolve().parent))
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
MAX_DOMAINS = 25
competitors = {'Akamai': ['Akamai','akamai','edgekey','akam', 'akadns'],
    'Digital Ocean': ['digital ocean','digitalocean'],
    'Google': ['googl'],
    'Incapsula': ['incapsu','incapsula', 'incapdns'],
    'Rackspace': ['racks'],
    'CenturyLink': ['centurylink'],
    'DreamHost': ['dreamhost'],
    'Fastly': ['fastly','fastly'],
    'Limelight': ['limelight','lldns','x-llid'],
    'Softlayer': ['softlayer'],
    'Azure': ['msft','microsoft','azure'],
    'Stackpath': ['stackpath','x-hw','netdna'],
    'Cloudflare': ['cloudflare','cf-cache-status','cf-ray'],
    'Bunny CDN': ['bunny'],
    'CDN-77': ['CDN77'],
    'Radware': ['radware'],
    'Sucuri': ['sucuri'],
    'Wpengine': ['wpengine'],
    'Hubspot': ['hubspot'],
    'Heroku': ['heroku'],
    'Footprint': ['footprint'],
    'Pantheon': ['pantheon'],
    'Squarespace': ['squarespace'],
    'Wix': ['wix'],
    'Pagely': ['pagely'],
    'Trafficmanager': ['trafficmanager'],
    'Cloudapp': ['cloudapp'],
    'Msft': ['msft'],
    'Q4Web': ['q4web'],
    'Cdngc': ['cdngc'],
    'Verizon': ['elasticbean','edgecas', 'verizon'],
    'Yotta': ['yotta'],
    'Omegacdn': ['omegacdn'],
    'Oracle': ['oracle'],
    'Sitelockcdn': ['sitelockcdn'],
    'Instart': ['instart'],
    'Netlify': ['x-nf-request-id'],
    'Keycdn': ['keycdn'],
    'Aliyun': ['aliyun'],
    'AWS EC2': ['amazon ec2'],
    'AWS ELB': ['elb.amazon', 'awselb'],
    'AWS S3': ['x-amz-version-id', 'x-amz-request-id', 's3-'],
    'AWS EKS': ['eks'],
    'AWS': ['awsdns', 'amazonaws'],
    'Amazon CloudFront': ['cloudfront', 'x-amz-cf-id']}


def find_key(signatures, evidence):
    evidence = evidence.casefold()
    # Prefer specific CloudFront evidence over generic AWS ownership.
    ordered = sorted(signatures, key=lambda k: k != "Amazon CloudFront")
    return next((name for name in ordered
                 if any(marker.casefold() in evidence for marker in signatures[name])), None)

def validate_domain(value):
    domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if len(domain) > 253 or "." not in domain or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", domain
    ):
        raise ValueError("Enter a domain name only, such as www.example.com.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("Use a public domain name, not an IP address.")

def resolve_public(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    addresses, evidence = [], []
    for kind in ("A", "AAAA"):
        try:
            answer = resolver.resolve(domain, kind)
        except dns.resolver.NoAnswer:
            continue
        evidence.append(str(answer.response))
        addresses.extend(str(record) for record in answer)
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError("The domain must resolve exclusively to public IP addresses.")
    return addresses[0], "\n".join(evidence)

def run_command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=12, check=True)
    return result.stdout

def analyze(value):
    domain = validate_domain(value)
    address, dns_evidence = resolve_public(domain)
    target = "[" + address + "]" if ":" in address else address
    # Pin the validated IP; do not follow redirects or use environment proxies.
    headers = run_command([
        "curl", "-q", "--silent", "--show-error", "--head", "--noproxy", "*",
        "--connect-timeout", "4", "--max-time", "8", "--proto", "=https",
        "--resolve", f"{domain}:443:{target}", "--write-out",
        "\n__TTFB__:%{time_starttransfer}", "--", f"https://{domain}/"
    ])
    header_text, _, timing = headers.rpartition("\n__TTFB__:")
    try:
        owner = find_key(competitors, run_command(["whois", address]))
    except (OSError, subprocess.SubprocessError):
        owner = "Unavailable"
    return {"domain": domain, "cdn": find_key(competitors, dns_evidence) or "Unknown",
            "dns": owner or "Unknown", "ip_owner": find_key(competitors, header_text) or "Unknown",
            "time": timing.strip() + "s" if timing else "Unavailable"}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")
    try:
        result = analyze(request.form.get("wdname", ""))
    except (ValueError, UnicodeError):
        abort(400, description="Enter a valid domain that resolves to public IP addresses.")
    except (dns.exception.DNSException, OSError, subprocess.SubprocessError):
        abort(502, description="Lookup failed or timed out. Check the domain and required tools.")
    return render_template("cdn_name.html", domain_name=result["domain"],
                           CDN=result["cdn"], DNS=result["dns"],
                           IP_owner=result["ip_owner"], time=result["time"])

@app.route("/csvcdn", methods=["GET", "POST"])
def csvcdn():
    if request.method == "GET":
        return render_template("csv_cdn.html")
    upload = request.files.get("csvfile")
    if not upload or not upload.filename.lower().endswith(".csv"):
        abort(400, description="Upload a UTF-8 CSV file.")
    try:
        rows = [r for r in csv.reader(io.StringIO(upload.read().decode("utf-8-sig"))) if r]
        if rows and rows[0][0].strip().lower() == "domain":
            rows = rows[1:]
        if not rows or len(rows) > MAX_DOMAINS:
            raise ValueError("Upload between 1 and 25 domains.")
        domains = [validate_domain(row[0]) for row in rows]
    except (ValueError, UnicodeError, csv.Error):
        abort(400, description="Use a UTF-8 CSV with 1–25 valid domains in the first column.")
    results = []
    for domain in domains:
        try:
            result = analyze(domain)
            result["error"] = ""
        except (ValueError, UnicodeError, dns.exception.DNSException, OSError, subprocess.SubprocessError):
            result = {"domain": domain, "error": "Lookup failed, timed out, or target is not public."}
        results.append(result)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=["domain", "cdn", "dns", "ip_owner", "time", "error"])
    writer.writeheader()
    writer.writerows(results)
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv",
                     as_attachment=True, download_name="result.csv")

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
