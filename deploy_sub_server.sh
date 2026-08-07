#!/bin/bash
# Script to deploy/refresh the subscription server from git and set up a systemd service

REPO_URL="https://github.com/svgorin/svgwork-site.git"
TARGET_DIR="/opt/svgwork-site"
SERVICE_NAME="svg-sub"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "======================================================="
echo "        DEPLOYING SUBSCRIPTION SERVER ON VPS"
echo "======================================================="

# 1. Install prerequisites (Node.js, Git) if missing
if ! command -v git &> /dev/null; then
    echo "Installing Git..."
    apt-get update && apt-get install -y git
fi

if ! command -v node &> /dev/null; then
    echo "Installing Node.js & NPM..."
    apt-get update
    apt-get install -y nodejs npm
fi

# Find node binary path
NODE_PATH=$(which node)
if [ -z "$NODE_PATH" ]; then
    NODE_PATH="/usr/bin/node"
fi

# 2. Clone or refresh the repository
if [ ! -d "$TARGET_DIR" ]; then
    echo "Cloning repository to $TARGET_DIR..."
    git clone "$REPO_URL" "$TARGET_DIR"
else
    echo "Directory exists. Refreshing from Git..."
    cd "$TARGET_DIR" || exit 1
    git fetch --all
    # Reset to master or main
    git reset --hard origin/main || git reset --hard origin/master
fi

cd "$TARGET_DIR" || exit 1

# Install npm dependencies if package.json exists
if [ -f "package.json" ]; then
    echo "Installing dependencies..."
    npm install
fi

# 3. Create/update systemd service file
echo "Configuring systemd service..."
cat << EOF > "$SERVICE_FILE"
[Unit]
Description=SVG Subscription Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$TARGET_DIR
ExecStart=$NODE_PATH simple_sub.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# 4. Reload and start/restart service
echo "Starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# 5. Output status
echo "-------------------------------------------------------"
systemctl status "$SERVICE_NAME" --no-pager
echo "-------------------------------------------------------"
echo "Deployment completed successfully!"
echo "Server is running on port 33130."
echo "======================================================="

