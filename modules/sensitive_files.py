import requests

# Common sensitive files and directories
SENSITIVE_PATHS = [
    # Config and environment files
    ".env",
    ".env.backup",
    "config.php",
    "config.yml",
    "config.json",
    "database.yml",
    "settings.py",

    # Admin panels
    "admin/",
    "admin.php",
    "administrator/",
    "phpmyadmin/",
    "wp-admin/",

    # Backup files
    "backup.zip",
    "backup.sql",
    "db_backup.sql",
    "site_backup.zip",

    # Log files
    "error.log",
    "access.log",
    "debug.log",

    # Common sensitive pages
    "robots.txt",
    "sitemap.xml",
    "server-status",
    "phpinfo.php",
    ".git/HEAD",
    ".htaccess",
]

def scan_sensitive_files(url):
    """Scan for exposed sensitive files and directories"""
    print(f"\n🔍 Scanning for sensitive files: {url}")
    print("=" * 50)

    # Clean up URL
    if url.endswith("/"):
        url = url[:-1]

    results = {
        "url": url,
        "found": [],
        "vulnerabilities": []
    }

    for path in SENSITIVE_PATHS:
        target = f"{url}/{path}"
        try:
            response = requests.get(
                target,
                timeout=5,
                verify=False,
                allow_redirects=False
            )

            if response.status_code == 200:
                results["found"].append(path)
                results["vulnerabilities"].append({
                    "type": "Sensitive File Exposed",
                    "path": target,
                    "severity": "HIGH",
                    "status_code": response.status_code,
                    "recommendation": f"Restrict access to {path}"
                })
                print(f"🚨 FOUND: {target} (Status: {response.status_code})")

            elif response.status_code == 403:
                print(f"🔒 FORBIDDEN: {target} (exists but protected)")

        except requests.exceptions.ConnectionError:
            pass
        except Exception as e:
            pass

    if not results["found"]:
        print("✅ No sensitive files exposed")
    else:
        print(f"\n📊 Found {len(results['found'])} exposed sensitive files!")

    return results


if __name__ == "__main__":
    scan_sensitive_files("http://127.0.0.1:8080")
