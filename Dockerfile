# Base image
FROM python:3.12-slim

WORKDIR /app

# Copy pre-built library into the image
COPY libagora_allosaurus_rs.so /usr/local/lib/

# update the library cache
RUN ldconfig

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libssl-dev \
    pkg-config \
    python3-venv  # Ensure the venv module is installed

# Copy the entire project into the container
COPY . /app

# Create a virtual environment
RUN python3 -m venv venv \
    && . venv/bin/activate \
    && pip3 install --upgrade pip \
    && pip3 install --no-cache-dir -r requirements.txt


# Clean up unnecessary packages and files
RUN apt-get remove -y build-essential curl \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Expose port
EXPOSE 80

# Run  application
CMD ["/app/venv/bin/uvicorn", "revocation-manager-py.main:app", "--host", "0.0.0.0", "--port", "80"]
