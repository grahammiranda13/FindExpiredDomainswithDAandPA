Expired Domain Finder with DA/PA Checker
This Python script helps you discover valuable, expired domains by crawling a "seed" website (like Wikipedia) for external links. It then checks each discovered domain for availability and fetches its Domain Authority (DA) and Page Authority (PA) using the Moz API.

The results are saved in a clean, easy-to-use CSV file.

Key Features
Crawls any URL: Start your search from any website to find linked domains.

Checks Domain Availability: Uses WHOIS lookups to identify domains that are likely expired and available for registration.

Fetches SEO Metrics: Automatically retrieves Domain Authority (DA) and Page Authority (PA) for each expired domain from the Moz Links API.

Simple CSV Output: Saves all found domains and their metrics to a expired_domains_with_metrics.csv file for easy analysis.

Easy to Configure: Simply add your free Moz API key and choose a seed URL to start.

How It Works
Crawl: The script begins at the SEED_URL you provide and gathers a list of all unique domains linked externally from that page.

Check: It iterates through the list of found domains and performs a WHOIS lookup on each one to determine if it's available.

Analyze: For every domain that appears to be available, the script makes a call to the Moz API to get its DA and PA scores.

Report: All potentially expired domains, along with their metrics, are compiled and saved into a CSV file.

Setup and Installation
This script is designed to run on macOS, Windows, or Linux.

1. Prerequisites

Make sure you have Python 3 installed on your system.

2. Install Required Libraries

Open your terminal or command prompt and run the following command to install the necessary Python packages:

pip install requests beautifulsoup4 python-whois

3. Get a Free Moz API Key

To get Domain Authority and Page Authority metrics, you need a free API key from Moz.

Create an account: Go to moz.com/community/join and sign up.

Get your credentials: Once registered, navigate to moz.com/products/api/keys to generate your free API Access ID and Secret Key.

Configuration and Usage
Edit the Script: Open the domain_finder.py script in a text editor.

Add Your Credentials: Find the CONFIGURATION section and replace the placeholder values with your actual Moz Access ID and Secret Key.

# --- Moz API Credentials ---
MOZ_ACCESS_ID = "mozscape-xxxxxxxxxx"  # <-- PASTE YOUR ACCESS ID HERE
MOZ_SECRET_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" # <-- PASTE YOUR SECRET KEY HERE

(Optional) Change the Seed URL: You can change the SEED_URL to any website you want to start crawling from. High-authority sites or relevant directories are a great place to start.

# --- Crawl Settings ---
SEED_URL = "https://en.wikipedia.org/wiki/List_of_defunct_amusement_parks"

Run the Script: Execute the script from your terminal:

python domain_finder.py

Output
The script will print its progress in the terminal. Once it completes, you will find a file named expired_domains_with_metrics.csv in the same directory. This file will contain the following columns:

domain: The expired domain name.

domain_authority: The Domain Authority score (0-100).

page_authority: The Page Authority score (0-100).

You can open this file with Microsoft Excel, Apple Numbers, Google Sheets, or any other spreadsheet software.

Disclaimer: The accuracy of WHOIS data can vary. A domain appearing "available" is a strong indicator but not a 100% guarantee. Always double-check availability with a domain registrar.

Made by https://grahammiranda.com | https://tech.grahammiranda.com

