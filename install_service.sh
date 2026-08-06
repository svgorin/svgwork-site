#!/bin/bash

# Setup script for Node.js Subscription Server on Linux
# This script copies the service configuration, enables, and starts the systemd service.

set -e

SERVICE_NAME="simple_sub"
INSTALL_DIR="/var/www/svgwork-site"

echo "=== Deploying $SERVICE_NAME Service ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run this script with sudo or as root."
  exit 1
fi

# Check if simple_sub.service exists locally
if [ ! -f "simple_sub.service" ]; then
  echo "Error: simple_sub.service file not found in current directory."
  exit 1
fi

# Copy service descriptor
echo "Copying simple_sub.service to /etc/systemd/system/..."
cp simple_sub.service /etc/systemd/system/${SERVICE_NAME}.service

# Reload systemd
echo "Reloading systemd configuration..."
systemctl daemon-reload

# Enable service
echo "Enabling $SERVICE_NAME service to start on boot..."
systemctl enable ${SERVICE_NAME}.service

# Start service
echo "Starting $SERVICE_NAME service..."
systemctl restart ${SERVICE_NAME}.service

# Check status
echo "Checking service status..."
systemctl status ${SERVICE_NAME}.service --no-pager

echo "=== Deployment Successful! ==="
