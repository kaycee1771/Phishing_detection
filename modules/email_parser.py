import os
import logging
from email import policy
from email.parser import BytesParser
from mailparser import MailParser

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    filename="email_parser_debug.log",
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def parse_email_with_mailparser(file_path):
    """
    Parse email using MailParser library.
    """
    try:
        mail = MailParser()
        mail.parse_from_file(file_path)

        # Ensure the parsed message is valid
        if not mail.message:
            raise ValueError("Failed to parse: Email content is empty or malformed.")

        # Extract headers
        headers = {
            "from": mail.from_ or "N/A",
            "to": mail.to or "N/A",
            "cc": mail.cc or "N/A",
            "subject": mail.subject or "N/A",
            "reply_to": mail.reply_to or "N/A",
        }

        # Extract body content
        body = {
            "plain_text": mail.text_plain or ["N/A"],
            "html": mail.text_html or ["N/A"],
        }

        # Extract URLs
        links = mail.urls if mail.urls else []

        return {"headers": headers, "body": body, "links": links}

    except Exception as e:
        logging.error(f"MailParser failed: {e}", exc_info=True)
        raise


def parse_email_with_email_library(file_path):
    """
    Fallback parsing using Python's built-in email library.
    """
    try:
        with open(file_path, "rb") as file:
            msg = BytesParser(policy=policy.default).parse(file)

        # Extract headers
        headers = {
            "from": msg["From"] or "N/A",
            "to": msg["To"] or "N/A",
            "cc": msg["Cc"] or "N/A",
            "subject": msg["Subject"] or "N/A",
            "reply_to": msg["Reply-To"] or "N/A",
        }

        # Extract body content
        if msg.is_multipart():
            plain_text = []
            html = []
            for part in msg.iter_parts():
                content_type = part.get_content_type()
                content_disposition = part.get("Content-Disposition", None)

                if content_type == "text/plain" and content_disposition != "attachment":
                    plain_text.append(part.get_content())
                elif content_type == "text/html" and content_disposition != "attachment":
                    html.append(part.get_content())
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                plain_text = [msg.get_content()]
                html = []
            elif content_type == "text/html":
                html = [msg.get_content()]
                plain_text = []

        return {"headers": headers, "body": {"plain_text": plain_text, "html": html}}

    except Exception as e:
        logging.error(f"Email library failed: {e}", exc_info=True)
        raise ValueError(f"Failed to parse email with fallback: {e}")


def parse_email(file_path):
    """
    Main function to parse email using MailParser with fallback to email library.
    """
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        # Attempt to parse with MailParser
        return parse_email_with_mailparser(file_path)
    except Exception:
        # Fallback to email library
        logging.info("Falling back to email library for parsing.")
        return parse_email_with_email_library(file_path)


if __name__ == "__main__":
    # Example email path
    sample_email = os.path.join("data", "sample_email.eml")

    try:
        parsed_email = parse_email(sample_email)
        print("Parsed Email:")
        print(parsed_email)
    except Exception as e:
        print(f"Error: {e}")
