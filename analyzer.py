import csv

def analyze_logs(csv_file_path, attempt_threshold=3):
    print("--- Generating Security Report ---")
    
    try:
        with open(csv_file_path, mode='r') as file:
            csv_reader = csv.DictReader(file)
            for entry in csv_reader:
                user_id = entry['user_id']
                location = entry['location']
                attempts = int(entry['attempts']) 
                
                if attempts > attempt_threshold:
                    print(f"[ALERT] Suspicious Activity: User {user_id} attempted entry {attempts} times at {location}.")
                else:
                    print(f"[OK] User {user_id} at {location} is normal.")
                    
    except FileNotFoundError:
        print(f"[ERROR] Could not find the file: {csv_file_path}")
        return

    print("--- SCAN COMPLETE ---")

if __name__ == "__main__":
    # We are telling it to look for the 'real_logs.csv' file you created!
    analyze_logs('real_logs.csv', attempt_threshold=4)