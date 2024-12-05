# log_analysis_project
This Python script processes log files to detect suspicious activity, including:
- Counting requests per IP address.
- Identifying the most accessed endpoint.
- Detecting failed login attempts exceeding a given threshold.

## How to Run
1. Run the script: python log_analysis.py
2. The results will be saved in: log_analysis_results.csv.
 OR 
 if you want to specify a custom threshold for suspicious activity (e.g., 5 failed login attempts): python log_analysis.py --threshold 5


