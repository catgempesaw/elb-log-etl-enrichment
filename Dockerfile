FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system-level dependencies for fastparquet and pandas
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Upgrade pip and install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy the rest of your app
COPY elb_logs.py .
COPY .env .
COPY output ./output 

# Entrypoint
CMD ["python", "elb_logs.py"]
