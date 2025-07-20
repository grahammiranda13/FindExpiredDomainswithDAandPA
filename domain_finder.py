# -*- coding: utf-8 -*-
"""
Expired Domain Finder with DA/PA Checker

This script helps you find potentially expired domains that are linked to from a
high-authority seed URL. For each expired domain it finds, it fetches the
Domain Authority (DA) and Page Authority (PA) using the Moz API.

-------------------------------------------------------------------------------
** HOW TO USE THIS SCRIPT **
-------------------------------------------------------------------------------

1.  **INSTALL REQUIRED LIBRARIES:**
    You need to install a few Python libraries. Open your Terminal (on Mac/Linux)
    or Command Prompt (on Windows) and run the following command:

    pip install requests beautifulsoup4 python-whois

2.  **GET YOUR FREE MOZ API KEY:**
    Domain Authority (DA) and Page Authority (PA) are metrics created by Moz.
    You'll need to get a free API key from them to use this script.

    a. Go to: https://moz.com/community/join
    b. Create a free community account.
    c. Go to: https://moz.com/products/api/keys
    d. Generate your API credentials (Access ID and Secret Key).

3.  **UPDATE THE CONFIGURATION BELOW:**
    Scroll down to the "CONFIGURATION" section in this file and paste your
    Moz Access ID and Secret Key into the appropriate variables. You can also
    change the SEED_URL to any website you want to start crawling from.

4.  **RUN THE SCRIPT:**
    Save this file (e.g., as `domain_finder.py`) and run it from your Terminal
    or Command Prompt:

    python domain_finder.py

5.  **CHECK THE RESULTS:**
    The script will print its progress in the terminal. When it's finished, it
    will create a file named `expired_domains_with_metrics.csv` in the same

    directory. You can open this file with any spreadsheet program (like Excel,
    Google Sheets, or Numbers on a Mac).

-------------------------------------------------------------------------------
"""
import requests
import whois
import time
import hmac
import hashlib
import base64
import csv
from urllib.parse import urlparse, urljoin

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("BeautifulSoup4 is not installed. Please run: pip install beautifulsoup4")
    exit()

# ============================================================================
# CONFIGURATION - !!!!!!!!!! UPDATE THIS SECTION !!!!!!!!!!
# ============================================================================

# --- Moz API Credentials ---
# Paste your Access ID and Secret Key here.
MOZ_ACCESS_ID = "YOUR_MOZ_ACCESS_ID"  # <-- PASTE YOUR ACCESS ID HERE
MOZ_SECRET_KEY = "YOUR_MOZ_SECRET_KEY" # <-- PASTE YOUR SECRET KEY HERE

# --- Crawl Settings ---
# The script will start by finding all external links on this URL.
# A large site like a Wikipedia page or a major news outlet is a good start.
SEED_URL = "https://en.wikipedia.org/wiki/List_of_defunct_amusement_parks"

# --- Output File ---
# The results will be saved to this file.
OUTPUT_CSV_FILE = "expired_domains_with_metrics.csv"

# ============================================================================
# SCRIPT LOGIC - (No need to edit below this line)
# ============================================================================

def get_links_from_url(url):
    """
    Fetches the content of a URL and extracts all unique external domain names.
    """
    print(f"[*] Crawling seed URL: {url}")
    found_domains = set()
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        soup = BeautifulSoup(response.text, 'html.parser')
        base_domain = urlparse(url).netloc

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('http') or href.startswith('//'):
                domain = urlparse(href).netloc
                # Ensure it's not a link back to the base domain or a subdomain
                if domain and base_domain not in domain:
                    # Clean up domain (e.g., 'www.example.com' -> 'example.com')
                    if domain.startswith('www.'):
                        domain = domain[4:]
                    found_domains.add(domain)

    except requests.RequestException as e:
        print(f"[!] Error crawling seed URL: {e}")
    except Exception as e:
        print(f"[!] An unexpected error occurred during crawling: {e}")

    print(f"[*] Found {len(found_domains)} unique external domains to check.")
    return list(found_domains)


def is_domain_available(domain):
    """
    Checks if a domain is available for registration using a WHOIS lookup.
    Returns True if it seems available, False otherwise.
    """
    try:
        w = whois.whois(domain)
        # If a domain has no expiration date, it's often a sign it's available
        # or there's an issue with the WHOIS record. We treat it as potentially available.
        if not w.expiration_date:
            return True
        return False
    except whois.parser.PywhoisError:
        # This error often means the domain does not exist (is available).
        return True
    except Exception as e:
        # Other exceptions might occur (e.g., network issues, rate limiting).
        # We'll assume it's not available to be safe.
        print(f"[!] Could not check WHOIS for {domain}: {e}")
        return False


def get_moz_metrics(domain, access_id, secret_key):
    """
    Fetches Domain Authority (DA) and Page Authority (PA) from the Moz API.
    """
    if not domain or not access_id or not secret_key or "YOUR_MOZ" in access_id:
        return None, None

    # Moz API requires a specific authentication signature.
    expires = int(time.time() + 300)
    string_to_sign = f"{access_id}\n{expires}".encode('utf-8')
    signature = hmac.new(secret_key.encode('utf-8'), string_to_sign, hashlib.sha1).digest()
    encoded_signature = base64.b64encode(signature).decode('utf-8')
    
    # We want both domain authority and page authority.
    # Bitmask: 32 (DA) + 65536 (PA) = 65568
    cols = "65568"
    
    api_url = f"https://lsapi.seomoz.com/v2/url_metrics?target={domain}&cols={cols}"
    
    headers = {
        "Authorization": f"mozscape {access_id}:{encoded_signature}"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Extract the metrics from the JSON response
        page_authority = data.get('results', [{}])[0].get('page_authority')
        domain_authority = data.get('results', [{}])[0].get('domain_authority')
        
        return domain_authority, page_authority
        
    except requests.RequestException as e:
        print(f"[!] Error fetching Moz metrics for {domain}: {e}")
        # Handle common 401 Unauthorized error specifically
        if e.response and e.response.status_code == 401:
            print("[!] CRITICAL: Moz API authentication failed (401 Unauthorized).")
            print("[!] Please double-check your MOZ_ACCESS_ID and MOZ_SECRET_KEY.")
    except Exception as e:
        print(f"[!] An unexpected error occurred with the Moz API: {e}")
        
    return None, None


def main():
    """
    Main function to orchestrate the domain finding and checking process.
    """
    print("--- Expired Domain Finder Initializing ---")

    if "YOUR_MOZ" in MOZ_ACCESS_ID or "YOUR_MOZ" in MOZ_SECRET_KEY:
        print("\n[!] FATAL ERROR: You have not configured your Moz API credentials.")
        print("[!] Please edit the script and add your Access ID and Secret Key.\n")
        return

    domains_to_check = get_links_from_url(SEED_URL)
    if not domains_to_check:
        print("[!] No domains found to check. Exiting.")
        return

    found_expired_domains = []
    total_domains = len(domains_to_check)

    print("\n[*] Starting to check domains for availability...")
    for i, domain in enumerate(domains_to_check):
        print(f"[*] Checking domain {i+1}/{total_domains}: {domain}")
        if is_domain_available(domain):
            print(f"  [+] SUCCESS: Domain '{domain}' appears to be expired! Fetching metrics...")
            
            # Add a small delay to be respectful to the Moz API
            time.sleep(1)
            
            da, pa = get_moz_metrics(domain, MOZ_ACCESS_ID, MOZ_SECRET_KEY)
            
            if da is not None and pa is not None:
                print(f"  [+] METRICS: DA: {da}, PA: {pa}")
                found_expired_domains.append({
                    "domain": domain,
                    "domain_authority": da,
                    "page_authority": pa
                })
            else:
                print(f"  [-] Could not retrieve metrics for {domain}.")
                # Still add it to the list, but with empty metrics
                found_expired_domains.append({
                    "domain": domain,
                    "domain_authority": "N/A",
                    "page_authority": "N/A"
                })

    if not found_expired_domains:
        print("\n--- Process Complete: No expired domains were found. ---")
        return

    print(f"\n--- Process Complete: Found {len(found_expired_domains)} potentially expired domains. ---")
    print(f"[*] Saving results to '{OUTPUT_CSV_FILE}'...")

    # Save the results to a CSV file
    try:
        with open(OUTPUT_CSV_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['domain', 'domain_authority', 'page_authority']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for entry in found_expired_domains:
                writer.writerow(entry)
        print("[*] Successfully saved results.")
    except IOError as e:
        print(f"[!] Error saving CSV file: {e}")


if __name__ == "__main__":
    main()
