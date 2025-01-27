# Phishing Detection System

A Python-based phishing email detection system designed to analyze email headers, extract and evaluate links, and flag suspicious emails using heuristic-based methods. This project aims to protect users from phishing scams by identifying patterns commonly associated with malicious emails.

---

## **Features**

1. **Email Parsing:**

   - Extract headers, plain text, and HTML content from email files (.eml).
   - Analyze email metadata such as sender information (e.g., SPF/DKIM validation).

2. **Link Analysis:**

   - Extract and analyze URLs from email content (plain text and HTML).
   - Perform advanced checks for:
     - Suspicious domains (e.g., IP-based URLs, invalid SSL certificates).
     - Trusted but abused domains (e.g., Google Docs, Dropbox).
     - Unresolvable domains and redirection chains.

3. **Heuristic-Based Scoring:**

   - Classify emails as **safe** or **suspicious** based on weighted scoring of various features (e.g., link analysis, sender authenticity).

4. **Reporting Mechanism:**

   - Save analysis results in structured JSON files.
   - Generate summary reports of all analyzed emails.

5. **Future Integration:**

   - Placeholder for machine learning-based phishing detection (see "Long-Term Goals").

---

## **Installation**

### **1. Clone the Repository**

```bash
git clone https://github.com/your-username/Phishing_detection.git
cd Phishing_detection
```

### **2. Set Up the Environment**

#### Using Virtual Environment (Recommended):

```bash
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate
```

### **3. Install Dependencies**

Install all required Python libraries:

```bash
pip install -r requirements.txt
```

### **4. Run the Tool**

Analyze the provided sample email:

```bash
python main.py
```

---

## **Usage**

### **1. Analyze an Email**

Place an email file (.eml format) in the `data/` directory (there's a sample file in the data directory of this repository), then run:

```bash
python main.py
```

### **2. Review Results**

- **Detailed Analysis Results:** Saved in the `reports/` folder as JSON files (there's a sample file for reference in this repository).
- **Summary Report:** A summary of analyzed emails is printed to the console.

### **Example Output**

```plaintext
Refined Heuristic Analysis Results:
{
    "sender_analysis": {
        "from_address": "example@phishing.com",
        "spf_valid": false,
        "dkim_valid": false
    },
    "subject_analysis": {
        "subject": "Urgent: Verify Your Account",
        "contains_phishing_keywords": true
    },
    "body_analysis": {
        "links": ["http://phishing-link.com"],
        "link_analysis": [
            {
                "original_url": "http://phishing-link.com",
                "final_url": "http://phishing-link.com",
                "domain": "phishing-link.com",
                "resolved": false,
                "ssl_valid": false,
                "suspicious": {
                    "ip_based": false,
                    "shortened": false,
                    "suspicious_tld": true,
                    "unresolvable_domain": true,
                    "invalid_ssl": true,
                    "trusted_abuse": false,
                    "redirects_to_suspicious": false
                }
            }
        ],
        "body_score": 5
    },
    "overall_score": {
        "score": 12,
        "classification": "suspicious"
    }
}
```

---

## **Long-Term Goals**

### **1. Machine Learning Model**

- **Objective:** Train a supervised ML model to complement heuristic analysis.
- **Planned Features:**
  - Train on labeled datasets of phishing and legitimate emails.
  - Leverage features like email text, headers, and link patterns.
  - Use pre-trained models (e.g., BERT) for improved accuracy in text analysis.

### **2. Real-Time Notification System**

- Notify administrators of suspicious emails via email or messaging platforms.

### **3. Database Integration**

- Store analysis results in a scalable database for better query and reporting capabilities.

### **4. Web Interface**

- Develop a front-end interface to allow users to upload emails and view results visually.

---

## **Contributing**

Contributions are welcome! Please contact: [kelechi.okpala13@yahoo.com](mailto\:kelechi.okpala13@yahoo.com)

---

## **License**

This project is licensed under the MIT License.&#x20;

---

## **Acknowledgments**

- Libraries used: `mailparser`, `requests`, `re`.
- Inspiration: Protecting users from phishing scams aligns with broader cybersecurity goals.

