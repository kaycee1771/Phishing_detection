import re
import requests
import socket
from urllib.parse import urlparse
from html import unescape


def extract_links(email_body):
    """
    Extracts and cleans URLs from the email body (plain text and HTML).

    :param email_body: Dictionary containing plain text and HTML body.
    :return: List of cleaned and valid URLs.
    """
    urls = set()
    url_pattern = r'(https?://[^\s"]+)' 

    # Extract from plain text
    if email_body.get("plain_text"):
        plain_text = " ".join(email_body["plain_text"]) if isinstance(email_body["plain_text"], list) else email_body["plain_text"]
        urls.update(re.findall(url_pattern, plain_text))

    # Extract from HTML
    if email_body.get("html"):
        html_content = " ".join(email_body["html"]) if isinstance(email_body["html"], list) else email_body["html"]
        urls.update(re.findall(url_pattern, html_content))

    # Clean and normalize URLs
    cleaned_urls = set()
    for url in urls:
        clean_url = unescape(url).strip(' "><')
        # Ensure URL starts with http:// or https://
        if clean_url.startswith("http://") or clean_url.startswith("https://"):
            cleaned_urls.add(clean_url)

    return list(cleaned_urls)




def dns_lookup(domain):
    """
    Performs a DNS lookup to validate the domain's existence.

    :param domain: Domain name to validate.
    :return: True if domain resolves, False otherwise.
    """
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def follow_redirects(url):
    """
    Follows HTTP redirects to determine the final destination of a URL.

    :param url: URL string.
    :return: Final URL after following redirects.
    """
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except requests.RequestException:
        return url  # If unable to follow, return the original URL


def check_ssl(url):
    """
    Validates whether the URL uses HTTPS and has a valid SSL/TLS certificate.

    :param url: URL string.
    :return: True if SSL is valid, False otherwise.
    """
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            return False

        # Attempt an HTTPS connection to validate SSL
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False


def analyze_link(url):
    """
    Performs advanced analysis on a URL to flag potential issues.
    :param url: URL string.
    :return: Dictionary with analysis results.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # List of trusted but potentially abused domains
        trusted_but_abused_domains = [
            "docs.google.com",
            "dropbox.com",
            "wetransfer.com",
            "onedrive.live.com",
        ]

        # Advanced checks
        resolved = dns_lookup(domain)
        final_url = follow_redirects(url)
        ssl_valid = check_ssl(url)

        # Check for suspicious patterns
        suspicious = {
            "ip_based": re.match(r'\d+\.\d+\.\d+\.\d+', domain) is not None,
            "shortened": domain in ["bit.ly", "tinyurl.com", "goo.gl"],
            "suspicious_tld": domain.endswith((".ru", ".cn", ".tk", ".biz")),
            "unresolvable_domain": not resolved,
            "invalid_ssl": not ssl_valid,
            "trusted_abuse": domain in trusted_but_abused_domains,
        }

        # Check if the final destination is suspicious
        if final_url != url:
            final_domain = urlparse(final_url).netloc
            suspicious["redirects_to_suspicious"] = final_domain.endswith((".ru", ".cn", ".tk", ".biz")) or not dns_lookup(final_domain)

        return {
            "original_url": url,
            "final_url": final_url,
            "domain": domain,
            "resolved": resolved,
            "ssl_valid": ssl_valid,
            "suspicious": suspicious,
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

if __name__ == "__main__":
    # Example usage
    email_body_example = {
        "plain_text": "Check this link: http://bit.ly/test.",
        "html": "<a href='http://phishing.com'>Click here</a>",
    }

    links = extract_links(email_body_example)
    print("Extracted Links:", links)

    for link in links:
        analysis = analyze_link(link)
        print("Link Analysis:", analysis)
