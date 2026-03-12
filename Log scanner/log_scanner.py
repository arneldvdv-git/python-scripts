import glob
import pandas as pd

log_dir = '.\\'  # Directory where log files are stored

def analyze_logs ():
    log_files = glob.glob(log_dir + '*.log')
    errors = []
    
    for log_file in log_files:
        with open(log_file, 'r') as f:
            for line in f:
                if "ERROR" in line or "CRITICAL" in line or "EXCEPTION" in line or "SEVERE" in line or "FATAL" in line:
                    errors.append({'log_file': log_file, 'error_message': line.strip()})
    
    df = pd.DataFrame(errors)
    if df.empty:
        print("No errors found in log files.")
    else:
        df.to_csv("error_report.csv", index=False)

analyze_logs()
    
 