#!/bin/bash

# Shai-Hulud Scanner Launcher for macOS/Linux

# 1. Check if Node is installed
if ! command -v node &> /dev/null
then
    echo "❌ Error: Node.js is not installed or not in your PATH."
    exit 1
fi

# 2. Get the directory where this script is located
# This ensures the script works even if you run it from a different folder
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# 3. Run the scanner
# "$@" passes any arguments (like --upload or a path) to the node script
echo "🚀 Launching Shai-Hulud Scanner..."
node "$SCRIPT_DIR/scan-shai.js" "$@"

# 4. Check exit status
if [ $? -eq 0 ]; then
    echo "✅ Scan complete."
else
    echo "⚠️ Scan finished with errors."
fi
