## Project Overview: ELB Log Transformation & Enrichment

This project demonstrates an advanced data engineering task focused on analyzing AWS Elastic Load Balancer (ELB) access logs stored in S3. The goal is to process these logs for insights into web traffic patterns and potential issues.

### Scenario

As a Data Engineer, you're responsible for building a Python ETL pipeline that:

- Ingests ELB logs from S3
- Cleans and transforms the data
- Enriches logs with IP geolocation via a web API
- Implements **local caching** to optimize API calls
- Outputs structured datasets for analysis

### Goals

- Use **Pandas** for parsing and transformations  
- Cache API responses to avoid redundant lookups  
- Export multiple outputs: cleaned logs, bot traffic summaries, error reports, and aggregations  
- Automate the ETL process via a **cron job**  
- Implement robust **logging** for traceability  
- Validate logic with **pytest** unit tests  
