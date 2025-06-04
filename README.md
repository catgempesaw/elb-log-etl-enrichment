# Advanced Exercise: AWS ELB Logs Transformation & Optimized Dynamic Enrichment

## Scenario: You are a Data Engineer tasked with a comprehensive analysis of web traffic patterns and potential issues using AWS Elastic Load Balancer (ELB) access logs. These logs are stored in an S3 bucket and require significant transformation and dynamic enrichment. To optimize external API calls, you'll implement a caching strategy for geolocation data.

## Goal: Write a Python script using Pandas to ingest, clean, transform, and dynamically enrich (via a web API with a local cache) raw AWS ELB access logs, and then aggregate the results. The output should consist of multiple structured datasets ready for different types of analysis.
