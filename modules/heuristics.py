import re
from modules.link_analyzer import extract_links, analyze_link
import dns.resolver


def check_spf(domain):
    """
    Check the SPF record for the sender's domain.
    :param domain: Domain name to check.
    :return: True if SPF is valid, False otherwise.
    """
    try:
        answers = dns.resolver.resolve(f"{domain}", "TXT")
        for record in answers:
            if "v=spf1" in record.to_text():
                return True
        return False
    except dns.resolver.NoAnswer:
        return False
    except Exception:
        return False


def check_dkim(domain):
    """
    Check for the presence of DKIM TXT records.
    :param domain: Domain name to check.
    :return: True if DKIM is valid, False otherwise.
    """
    dkim_selector = "default"  
    dkim_domain = f"{dkim_selector}._domainkey.{domain}"
    try:
        dns.resolver.resolve(dkim_domain, "TXT")
        return True
    except dns.resolver.NoAnswer:
        return False
    except Exception:
        return False


def analyze_sender_with_auth(headers):
    """
    Analyze the sender's email address with SPF/DKIM checks.
    :param headers: Dictionary containing email headers.
    :return: Dictionary with sender authentication results.
    """
    from_address = headers.get("from", "N/A")
    try:
        from_domain = re.search(r"@([\w.-]+)", from_address).group(1) if "@" in from_address else None
        spf_valid = check_spf(from_domain) if from_domain else False
        dkim_valid = check_dkim(from_domain) if from_domain else False
    except Exception:
        spf_valid = dkim_valid = False

    return {
        "from_address": from_address,
        "spf_valid": spf_valid,
        "dkim_valid": dkim_valid,
    }

def analyze_sender(headers):
    """
    Analyze the sender's email address and related headers.
    :param headers: Dictionary containing email headers.
    :return: Dictionary with sender analysis results.
    """
    from_address = headers.get("from", "N/A")
    reply_to = headers.get("reply_to", "N/A")

    # Check if the "From" and "Reply-To" domains match
    try:
        from_domain = re.search(r"@([\w.-]+)", from_address).group(1) if "@" in from_address else None
        reply_domain = re.search(r"@([\w.-]+)", reply_to).group(1) if "@" in reply_to else None
        domain_mismatch = from_domain != reply_domain if from_domain and reply_domain else False
    except Exception:
        from_domain = reply_domain = None
        domain_mismatch = False

    return {
        "from_address": from_address,
        "reply_to": reply_to,
        "domain_mismatch": domain_mismatch,
    }


def analyze_subject(subject):
    """
    Analyze the email subject for phishing-related patterns.
    :param subject: The subject line of the email.
    :return: Dictionary with subject analysis results.
    """
    phishing_keywords = ["urgent", "verify", "limited time", "action required", "password reset", "crypto", "withdrawal", "approved"]
    lower_subject = subject.lower() if subject else ""
    contains_phishing_keywords = any(keyword in lower_subject for keyword in phishing_keywords)

    return {
        "subject": subject,
        "contains_phishing_keywords": contains_phishing_keywords,
    }

def analyze_body(body):
    """
    Analyze the email body for phishing-related patterns using weighted keywords.
    :param body: Dictionary containing plain text and HTML body.
    :return: Dictionary with body analysis results.
    """
    links = extract_links(body)
    link_analysis = [analyze_link(link) for link in links]

    # Weighted phishing keywords
    phishing_keywords = {
        "click here": 1,
        "verify your account": 3,
        "update your information": 2,
        "log in": 2,
        "reset your password": 3,
        "action required": 2,
        "urgent": 3,
    }

    plain_text = " ".join(body.get("plain_text", [])) if isinstance(body.get("plain_text"), list) else body.get("plain_text", "")
    body_score = sum(weight for keyword, weight in phishing_keywords.items() if keyword in plain_text.lower())

    return {
        "links": links,
        "link_analysis": link_analysis,
        "body_score": body_score,
    }

def calculate_score(sender_analysis, subject_analysis, body_analysis):
    """
    Combine analysis results to calculate an overall heuristic score with SPF/DKIM checks.
    :param sender_analysis: Results from analyze_sender_with_auth.
    :param subject_analysis: Results from analyze_subject.
    :param body_analysis: Results from analyze_body_with_weights.
    :return: Heuristic score and classification (safe/suspicious).
    """
    score = 0

    if not sender_analysis["spf_valid"]:
        score += 1  
    if not sender_analysis["dkim_valid"]:
        score += 3 


    # Increment score for suspicious subject keywords
    if subject_analysis["contains_phishing_keywords"]:
        score += 2

    score += body_analysis["body_score"]

    # Increment score for suspicious links
    for link in body_analysis["link_analysis"]:
        if link["suspicious"]["shortened"]:
            score += 2
        if link["suspicious"]["unresolvable_domain"]:
            score += 3
        if link["suspicious"]["invalid_ssl"]:
            score += 2
        if link["suspicious"]["trusted_abuse"]:
            score += 3  
        if link["suspicious"].get("redirects_to_suspicious", False):
            score += 3  

    # Classification based on score
    classification = "suspicious" if score >= 6 else "safe"
    return {
        "score": score,
        "classification": classification,
    }


def analyze_email(email_data):
    """
    Perform refined heuristic analysis on an email.
    :param email_data: Parsed email data (headers and body).
    :return: Complete analysis results.
    """
    headers = email_data["headers"]
    body = email_data["body"]

    sender_analysis = analyze_sender_with_auth(headers)
    subject_analysis = analyze_subject(headers.get("subject", ""))
    body_analysis = analyze_body(body)

    overall_score = calculate_score(sender_analysis, subject_analysis, body_analysis)

    return {
        "sender_analysis": sender_analysis,
        "subject_analysis": subject_analysis,
        "body_analysis": body_analysis,
        "overall_score": overall_score,
    }

