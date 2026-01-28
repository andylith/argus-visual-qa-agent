# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Set work directory
WORKDIR /app

# Install system dependencies required for Playwright
# We install the "browsers" later, but we need the OS libs now
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium only to save space)
RUN playwright install chromium --with-deps

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p screenshots config

# Command to run the scheduler
CMD ["python", "scheduler.py"]