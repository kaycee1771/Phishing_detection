from modules.email_parser import parse_email
from modules.link_analyzer import extract_links, analyze_link
from modules.heuristics import analyze_email
from modules.reporter import save_analysis_results, generate_summary_report, notify_admin
import time

if __name__ == "__main__":
    # Parse the sample email
    email_data = parse_email("data/sample_email.eml")

    # Perform heuristic analysis
    analysis_results = analyze_email(email_data)
    
    links = extract_links(email_data["body"])

    print("Extracted Links:", links)

    for link in links:
        analysis = analyze_link(link)
        print("Detailed Analysis:", analysis)
    
    print("Refined Heuristic Analysis Results:")
    print(analysis_results)

    # Generate a unique identifier for the email
    email_id = str(int(time.time()))

    # Save analysis results to a report
    save_analysis_results(email_id, analysis_results)

    # Notify admin if the email is flagged as suspicious
    if analysis_results["overall_score"]["classification"] == "suspicious":
        notify_admin(email_id, analysis_results)

    # Print the results
    print("Analysis Results Saved.")
    print(f"Email ID: {email_id}")

    # Generate and print the summary report
    summary_report = generate_summary_report()
    print("\nSummary Report:")
    print(summary_report)
