# Project: Physical Access Log Analyzer
# Author: Satish Jega
# Purpose: Detects if a single user ID attempts to enter a secure door too many times in a short period (Brute Force on a physical door).

import csv

# This is a dummy function to simulate reading a log file
# In a real scenario, this would read a CSV file exported from the Access Control System
def analyze_logs(log_data):
    suspicious_activity = []
    
    print("--- Generating Report ---")
    
    for entry in log_data:
        user_id = entry['user_id']
        attempts = entry['attempts']
        location = entry['location']
        
        # LOGIC: If there are more than 3 attempts, flag it as a suspicious behaviour
        # Basically, if they tap on more than 3 times in a minute then flag as suspicious behaviour
        if attempts > 3:
            alert = f"[ALERT] Suspicious Activity: User {user_id} attempted entry {attempts} times at {location}."
            suspicious_activity.append(alert)
            print(alert)
        else:
            print(f"[OK] User {user_id} at {location} is normal.")
            
    print("--- SCAN COMPLETE ---")
    
    if not suspicious_activity:
        print("No Anomoly Detected.")
    else:
        print(f"Action Required: {len(suspicious_activity)} threats found.")

# Dummy Data (Simulating a CSV export from the security system)
dummy_logs = [
    {'user_id': 'MBS001', 'location': 'Server Room A', 'attempts': 1},
    {'user_id': 'MBS002', 'location': 'Casino Vault', 'attempts': 5}, # This guy is suspicious!
    {'user_id': 'MBS003', 'location': 'Staff Exit', 'attempts': 1},
    {'user_id': 'MBS004', 'location': 'Hotel Ops', 'attempts': 12}  # Very suspicious!
]

# Run the tool
if __name__ == "__main__":
    analyze_logs(dummy_logs)
