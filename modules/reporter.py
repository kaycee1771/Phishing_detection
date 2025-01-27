import os
import json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    filename="reporter.log",
    format="%(asctime)s - %(levelname)s - %(message)s"
)

REPORTS_DIR = "reports"

# Ensure the reports directory exists
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)


def save_analysis_results(email_id, analysis_results):
    """
    Save the analysis results to a JSON file for future reference.
    :param email_id: Unique identifier for the email (e.g., timestamp or hash).
    :param analysis_results: Dictionary containing the email analysis results.
    """
    try:
        file_path = os.path.join(REPORTS_DIR, f"{email_id}.json")
        with open(file_path, "w") as file:
            json.dump(analysis_results, file, indent=4)
        logging.info(f"Analysis results saved to {file_path}")
    except Exception as e:
        logging.error(f"Failed to save analysis results: {e}")


def generate_summary_report():
    """
    Generate a summary of all suspicious emails analyzed.
    :return: Summary report as a dictionary.
    """
    summary = {
        "total_emails_analyzed": 0,
        "suspicious_emails": 0,
        "safe_emails": 0,
        "detailed_results": []
    }

    try:
        for file_name in os.listdir(REPORTS_DIR):
            if file_name.endswith(".json"):
                with open(os.path.join(REPORTS_DIR, file_name), "r") as file:
                    analysis = json.load(file)
                    summary["total_emails_analyzed"] += 1
                    if analysis["overall_score"]["classification"] == "suspicious":
                        summary["suspicious_emails"] += 1
                    else:
                        summary["safe_emails"] += 1
                    summary["detailed_results"].append({
                        "email_id": file_name.replace(".json", ""),
                        "classification": analysis["overall_score"]["classification"],
                        "score": analysis["overall_score"]["score"]
                    })
        logging.info("Summary report generated successfully.")
    except Exception as e:
        logging.error(f"Failed to generate summary report: {e}")

    return summary


def notify_admin(email_id, analysis_results):
    """
    Placeholder function to send a notification to an admin about a suspicious email.
    :param email_id: Unique identifier for the email.
    :param analysis_results: Detailed analysis results.
    """
    try:
        # Example notification placeholder
        logging.info(f"Admin notified about suspicious email: {email_id}")
    except Exception as e:
        logging.error(f"Failed to notify admin: {e}")
