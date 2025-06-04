import os
import gzip
import shlex
import boto3
import pandas as pd
import numpy as np
import requests
import time

from io import BytesIO
from urllib.parse import urlparse
from datetime import datetime
from pytz import timezone, utc
from dotenv import load_dotenv
from user_agents import parse as ua_parse

load_dotenv()

# Set up AWS S3 client 
s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

# Read bucket and prefix from .env
s3_bucket = os.getenv('S3_BUCKET')
prefix = os.getenv('S3_PREFIX', '')

# ELB log fields based on AWS documentation
ELB_COLUMNS = [
    'type', 'time', 'elb', 'client_ip_port', 'target_ip_port',
    'request_processing_time', 'target_processing_time', 'response_processing_time',
    'elb_status_code', 'target_status_code', 'received_bytes', 'sent_bytes',
    'request', 'user_agent', 'ssl_cipher', 'ssl_protocol',
    'target_group_arn', 'trace_id', 'domain_name', 'chosen_cert_arn',
    'matched_rule_priority', 'request_creation_time', 'actions_executed',
    'redirect_url', 'error_reason', 'target_port_list', 'target_status_code_list',
    'classification', 'classification_reason'
]

# Directory constants
GEO_CACHE_PATH        = "output/ip_geolocation_cache.parquet"
OUTPUT_CLEANED        = "output/cleaned_logs"
OUTPUT_AGG            = "output/aggregated_stats"
OUTPUT_REPORTS        = "output/reports"
os.makedirs(OUTPUT_CLEANED, exist_ok=True)
os.makedirs(OUTPUT_AGG, exist_ok=True)
os.makedirs(OUTPUT_REPORTS, exist_ok=True)

# Extract .gz log keys from S3
def extract_log_keys(bucket, prefix=''):
    response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    keys = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'].endswith('.gz')]

    # print(f"Found {len(keys)} log file(s) in S3 bucket '{bucket}' with prefix '{prefix}':")
    # for key in keys:
    #     print(f" - {key}")
    return keys

# Parse a single ELB log line
def parse_log_line(line, source_file):
    try:
        parts = shlex.split(line)
        if len(parts) < len(ELB_COLUMNS):
            return None

        record = dict(zip(ELB_COLUMNS, parts[:len(ELB_COLUMNS)]))

        # Timestamp
        record['time'] = utc.localize(datetime.strptime(record['time'], "%Y-%m-%dT%H:%M:%S.%fZ")).astimezone(timezone('US/Eastern'))
        
        try:
            record['request_creation_time'] = pd.to_datetime(record['request_creation_time'], utc=True).tz_convert('US/Eastern')
        except:
            record['request_creation_time'] = pd.NaT

        # Convert numeric fields
        float_columns = ['request_processing_time', 'target_processing_time', 'response_processing_time']
        int_columns = ['elb_status_code', 'target_status_code', 'received_bytes', 'sent_bytes']

        for col in float_columns:
            record[col] = float(record[col]) if record[col] != '-' else np.nan
        for col in int_columns:
            record[col] = int(record[col]) if record[col].isdigit() else np.nan

        # Extract client IP
        record['client_ip'] = record['client_ip_port'].split(':')[0]

        # Request Details Extraction
        try:
            http_method, full_url, http_version = shlex.split(record['request'])
            parsed_url = urlparse(full_url)
            record['http_method'] = http_method
            record['full_url'] = full_url
            record['http_version'] = http_version
            
            record['protocol'] = parsed_url.scheme
            record['hostname'] = parsed_url.hostname
            record['port'] = parsed_url.port
            record['path'] = parsed_url.path
            record['query_params'] = parsed_url.query
        except:
            pass

        # User Agent Parsing
        ua = ua_parse(record['user_agent'].strip('"'))
        record['ua_browser_family'] = ua.browser.family or 'Other'
        record['ua_os_family'] = ua.os.family or 'Other'
        record['is_bot'] = any(bot in record['user_agent'].lower() for bot in ['bot', 'crawler', 'spider', 'googlebot', 'python-urllib'])

        record['log_source_file'] = source_file
        return record
    except Exception as e:
        print(f"Failed to parse line in {source_file}: {e}")
        return None

# Transform log files into a DataFrame
def transform_logs(bucket, keys):
    parsed_logs = []
    for key in keys:
        print(f"- Processing: {key}")
        obj = s3.get_object(Bucket=bucket, Key=key)
        with gzip.GzipFile(fileobj=BytesIO(obj['Body'].read())) as gz:
            for line in gz:
                parsed = parse_log_line(line.decode('utf-8').strip(), key)
                if parsed:
                    parsed_logs.append(parsed)
    df = pd.DataFrame(parsed_logs)
    print(f"Parsed {len(df)} rows from {len(keys)} files.")
    return df

# GEOLOCATION : Load parquet cache if available
def load_geolocation_cache(cache_path=GEO_CACHE_PATH):
    try:
        # Try loading existing cache
        df = pd.read_parquet(cache_path)
        return df
    except FileNotFoundError:
        # If cache doesn't exist, return an empty DataFrame
        columns = [
            'countryCode', 'countryName', 'regionName', 'city',
            'lat', 'lon', 'isp', 'api_fetch_timestamp'
        ]
        df = pd.DataFrame(columns=columns)
        df.index.name = 'client_ip'  # Set client_ip as index
        return df

# GEOLOCATION : Fetch geolocation data for a new IP
def fetch_geolocation_data(new_ip):
    url = f'http://ip-api.com/json/{new_ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,isp,query'

    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        print(f"🌍 Geolocation data for {new_ip}: {data}")
        if data['status'] == 'success':
            return {
                'client_ip': data['query'],
                'countryCode': data.get('countryCode'),
                'countryName': data.get('country'),
                'regionName': data.get('regionName'),
                'city': data.get('city'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'isp': data.get('isp'),
                'api_fetch_timestamp': pd.Timestamp.now()
            }
        else:
            return {
                'client_ip': new_ip,
                'countryCode': "Error",
                'countryName': "Error",
                'regionName': "Error",
                'city': "Error",
                'lat': np.nan,
                'lon': np.nan,
                'isp': "Error",
                'api_fetch_timestamp': pd.Timestamp.now()
            }
    except Exception as e:
        print(f"Error fetching geolocation for {new_ip}: {e}")
        return {
            'client_ip': new_ip,
            'countryCode': "Error",
            'countryName': "Error",
            'regionName': "Error",
            'city': "Error",
            'lat': np.nan,
            'lon': np.nan,
            'isp': "Error",
            'api_fetch_timestamp': pd.Timestamp.now()
        }
        
# GEOLOCATION: Update and save new geolocation entries
def update_geolocation_cache(new_geo_entry, cache_path=GEO_CACHE_PATH):
    geo_cache = load_geolocation_cache()
    print("CACHE:", geo_cache)
    
    # If single result (dict), wrap in list
    if isinstance(new_geo_entry, dict):
        new_geo_entry = [new_geo_entry]
    
    new_geo_df = pd.DataFrame(new_geo_entry).set_index('client_ip')
    
    print("NEW GEO:", new_geo_df)
    
    updated_cache = pd.concat([geo_cache, new_geo_df])
    
    # Drop duplicates by client_ip, keeping the most recent
    updated_cache.sort_values('api_fetch_timestamp', ascending=False, inplace=True)
    updated_cache = updated_cache[~updated_cache.index.duplicated(keep='first')]
    updated_cache.to_parquet(cache_path)

    print("✅ Geolocation cache updated and saved.")
    return updated_cache

# Merge geocached DataFrame with ELB DataFrame
def merge_geocachedf_with_elbdf(elb_df, geo_cache):
    df_enriched = elb_df.merge(
        geo_cache,
        how='left',
        left_on='client_ip',
        right_index=True,
    )
    return df_enriched

# Filter and categorize 
def filter_categorize_df(df):
    df = df[df['client_ip'].notna()]
    df = df[df['request'].notna()]

    health_check_agents = ['datadog', 'healthchecker', 'kube-probe', 'aws-elb']
    df = df[
        ~df['user_agent'].str.lower().str.contains('|'.join(health_check_agents), na=False)
    ]

    # Create status_code_type column
    df['status_code_type'] = df['elb_status_code'].apply(categorize_status)

    # Categorize WAF blocks
    df['waf_blocked'] = df['classification_reason'].str.contains(
        'waf|blocked|deny', case=False, na=False
    )
    return df

# Categorize status_code_type column based on elb_status_code
def categorize_status(code):
    if pd.isna(code): return 'Unknown'
    code = int(code)
    if 100 <= code < 200: return '1xx_Informational'
    elif 200 <= code < 300: return '2xx_Success'
    elif 300 <= code < 400: return '3xx_Redirection'
    elif 400 <= code < 500: return '4xx_ClientError'
    elif 500 <= code < 600: return '5xx_ServerError'
    else: return 'Other'

# Rolling Aggregations
def add_rolling_features(df):
    df = df.sort_values(['client_ip', 'time'])

    rolling_count = (
        df.groupby('client_ip')
          .rolling(window='5min', on='time')['request']
          .count()
          .rename('rolling_5min_request_count')
          .reset_index()
    )

    rolling_avg = (
        df.groupby('client_ip')
          .rolling(window='1h', on='time')['total_processing_time']
          .mean()
          .rename('rolling_1h_avg_processing')
          .reset_index()
    )

    df = df.merge(rolling_count, on=['client_ip', 'time'], how='left')
    df = df.merge(rolling_avg, on=['client_ip', 'time'], how='left')
    return df
# --------------------------------------------------------------#
# Feature Engineering & Advanced Transformations:
def extract_time_features(df):
    df['request_year'] = df['time'].dt.year
    df['request_month'] = df['time'].dt.month
    df['request_day'] = df['time'].dt.day
    df['request_hour'] = df['time'].dt.hour
    df['request_day_of_week'] = df['time'].dt.day_name()
    df['request_day_of_week_num'] = df['time'].dt.weekday
    df['request_week_of_year'] = df['time'].dt.isocalendar().week
    return df

def calculate_processing_times(df):
    cols = ['request_processing_time', 'target_processing_time', 'response_processing_time']
    df['total_processing_time'] = df[cols].fillna(0).sum(axis=1)
    return df

def sessionize_logs(df, session_gap_minutes=30):
    df = df.sort_values(by=['client_ip', 'time'])
    df['time_diff'] = df.groupby('client_ip')['time'].diff().fillna(pd.Timedelta(seconds=0))
    df['new_session'] = df['time_diff'] > pd.Timedelta(minutes=session_gap_minutes)
    df['session_number'] = df.groupby('client_ip')['new_session'].cumsum()
    df['session_id'] = df['client_ip'] + '_s' + df['session_number'].astype(str)
    return df

# Request Path Analysis
def add_path_features(df):
    df['path_depth'] = df['path'].fillna('').apply(lambda x: len([seg for seg in x.split('/') if seg]))

    # Extract main path segment (the first segment of the path).
    df['path_main_segment'] = df['path'].fillna('').apply(lambda x: x.split('/')[1] if len(x.split('/')) > 1 else '')
    return df

# Data Type Optimization
def optimize_dtypes(df):
    int_cols = df.select_dtypes(include=['int64']).columns
    float_cols = df.select_dtypes(include=['float64']).columns

    df[int_cols] = df[int_cols].apply(pd.to_numeric, downcast='integer')
    df[float_cols] = df[float_cols].apply(pd.to_numeric, downcast='float')

    # Convert low-cardinality strings to category
    cat_candidates = ['http_method', 'status_code_type', 'countryCode', 'countryName', 'ua_browser_family', 'ua_os_family']
    for col in cat_candidates:
        if col in df.columns:
            df[col] = df[col].astype('category')
    return df

# --------------------------------------------------------------#
# Output Functions
def export_cleaned_logs(df, base_path="output/cleaned_logs"):
    df.to_parquet(
        base_path,
        partition_cols=["request_year", "request_month", "request_day", "countryCode"],
        index=False
    )
    print(f"✅ Cleaned logs saved to: {base_path}")

def export_hourly_aggregates(df, output_path="output/aggregated_stats/hourly_traffic_by_geo.parquet"):
    agg = df.groupby([
        "request_year", "request_month", "request_day", "request_hour",
        "countryName", "city"
    ]).agg(
        request_count=('client_ip', 'count'),
        unique_client_ips_count=('client_ip', 'nunique'),
        average_total_processing_time=('total_processing_time', 'mean'),
        median_total_processing_time=('total_processing_time', 'median'),
        sum_sent_bytes=('sent_bytes', 'sum'),
        sum_received_bytes=('received_bytes', 'sum'),
        count_2xx=('status_code_type', lambda x: (x == "2xx_Success").sum()),
        count_4xx=('status_code_type', lambda x: (x == "4xx_ClientError").sum()),
        count_5xx=('status_code_type', lambda x: (x == "5xx_ServerError").sum()),
    ).reset_index()
    
    agg.to_parquet(output_path, index=False)
    print(f"📊 Aggregates saved to: {output_path}")

def export_error_summary(df, output_path="output/reports/error_summary_geo.csv"):
    err_df = df[df["status_code_type"].isin(["4xx_ClientError", "5xx_ServerError"])]
    cols = [
        "time", "client_ip", "city", "countryName", "isp", "http_method", "full_url",
        "elb_status_code", "target_status_code_list", "user_agent",
        "ua_browser_family", "ua_os_family", "error_reason"
    ]
    err_df[cols].to_csv(output_path, index=False)
    print(f"❗ Error summary saved to: {output_path}")
    
def export_bot_traffic(df, detail_path="output/reports/bot_traffic_details.parquet", summary_path="output/reports/bot_traffic_by_origin_summary.csv"):
    bots = df[df['is_bot'] == True]
    
    detail_cols = ["time", "client_ip", "city", "countryName", "isp", "full_url", "user_agent"]
    summary = bots.groupby(["countryName", "isp"]).size().reset_index(name="bot_request_count")

    bots[detail_cols].to_parquet(detail_path, index=False)
    summary.to_csv(summary_path, index=False)
    
    print(f"🤖 Bot details saved to: {detail_path}")
    print(f"📈 Bot summary saved to: {summary_path}")
# --------------------------------------------------------------#
# Main ETL Process
def main():
    print("Starting ELB log transformation and geolocation")

    # Step 1: Load and parse logs
    df = transform_logs(s3_bucket, extract_log_keys(s3_bucket, prefix))

    # Step 2: Load existing cache
    geo_cache = load_geolocation_cache()

    # Step 3: Identify new IPs
    unique_ips = df['client_ip'].unique()
    new_ips = [ip for ip in unique_ips if ip not in geo_cache.index]
    print(f"🆕 Found {len(new_ips)} IPs needing geolocation lookup.")

    # Step 4: Fetch new geolocations
    geo_results = []
    for i, ip in enumerate(new_ips):
        print(f"📍[{i+1}/{len(new_ips)}] Looking up: {ip}")
        geo_results.append(fetch_geolocation_data(ip))
        time.sleep(1)
    if geo_results:
        geo_cache = update_geolocation_cache(geo_results)

    # Step 5: Merge and filter
    df_enriched = merge_geocachedf_with_elbdf(df, geo_cache)
    df_enriched = filter_categorize_df(df_enriched)

    # Step 6: Feature engineering
    df_enriched = extract_time_features(df_enriched)
    df_enriched = calculate_processing_times(df_enriched)
    df_enriched = sessionize_logs(df_enriched)
    df_enriched = add_rolling_features(df_enriched)
    df_enriched = add_path_features(df_enriched)
    df_enriched = optimize_dtypes(df_enriched)

    # Step 7: Output
    export_cleaned_logs(df_enriched)
    export_hourly_aggregates(df_enriched)
    export_error_summary(df_enriched)
    export_bot_traffic(df_enriched)

if __name__ == "__main__":
    main()
