import requests

# Security headers every website should have
SECURITY_HEADERS = {
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-XSS-Protection": "Enables browser XSS filtering",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "Content-Security-Policy": "Prevents XSS and injection attacks",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser feature access"
}

def scan_headers(url):
    """Scan a URL for missing security headers"""
    print(f"\n🔍 Scanning security headers: {url}")
    print("=" * 50)

    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers

        results = {
            "url": url,
            "status_code": response.status_code,
            "missing_headers": [],
            "present_headers": [],
            "vulnerabilities": []
        }

        for header, description in SECURITY_HEADERS.items():
            if header not in headers:
                results["missing_headers"].append(header)
                results["vulnerabilities"].append({
                    "type": "Missing Security Header",
                    "header": header,
                    "severity": "MEDIUM",
                    "description": description,
                    "recommendation": f"Add {header} header to your server response"
                })
                print(f"❌ MISSING: {header} — {description}")
            else:
                results["present_headers"].append(header)
                print(f"✅ PRESENT: {header}")

        print(f"\n📊 Results: {len(results['missing_headers'])} missing, "
              f"{len(results['present_headers'])} present")

        return results

    except requests.exceptions.ConnectionError:
        print(f"❌ Could not connect to {url}")
        return None
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return None


if __name__ == "__main__":
    # Test against DVWA
    scan_headers("http://127.0.0.1:8080")
