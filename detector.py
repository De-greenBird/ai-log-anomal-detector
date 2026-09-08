import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest

def generate_mock_logs():
    """Generates a mixture of normal and malicious server logs for demonstration."""
    normal_logs = [
        "2026-09-08 10:00:01 INFO User login successful for admin",
        "2026-09-08 10:05:23 INFO GET /index.html HTTP/1.1 200",
        "2026-09-08 10:12:11 INFO GET /about.html HTTP/1.1 200",
        "2026-09-08 10:15:45 INFO User logout successful for admin",
        "2026-09-08 10:20:00 INFO GET /styles.css HTTP/1.1 200",
        "2026-09-08 10:22:15 INFO GET /favicon.ico HTTP/1.1 200",
    ] * 15  # Duplicate to create a baseline pattern
    
    anomalous_logs = [
        "2026-09-08 10:30:00 WARN Unauthorized access attempt on /admin/config.php",
        "2026-09-08 10:31:12 ERROR SQL injection detected: SELECT * FROM users WHERE '1'='1",
        "2026-09-08 10:32:05 WARN Password brute force attempt from IP 192.168.1.105",
    ]
    
    all_logs = normal_logs + anomalous_logs
    return pd.DataFrame(all_logs, columns=["log_message"])

def detect_anomalies():
    print("🤖 Emmanuel's AI Log Anomaly Detector starting up...")
    df = generate_mock_logs()
    
    # 1. Feature Engineering: Convert text log entries into numerical data using TF-IDF
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(df["log_message"])
    
    # 2. AI Modeling: Train an Isolation Forest (Unsupervised Outlier Detection)
    # contamination=0.03 expects roughly 3% of the logs to be anomalies
    model = IsolationForest(contamination=0.03, random_state=42)
    model.fit(X.toarray())
    
    # 3. Predict anomalies (-1 indicates an anomaly, 1 indicates normal)
    df["anomaly_score"] = model.predict(X.toarray())
    
    # 4. Display Results
    anomalies = df[df["anomaly_score"] == -1]
    
    print(f"\n📊 Scanned {len(df)} log lines.")
    print(f"🚨 Found {len(anomalies)} suspicious security threats:\n")
    
    for idx, row in anomalies.iterrows():
        print(f"➔ [SUSPICIOUS] {row['log_message']}")

if __name__ == "__main__":
    detect_anomalies()
