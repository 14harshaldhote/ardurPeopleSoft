#!/bin/bash
# Attendance System Cron Setup Script
# This script runs django-cron every minute to check for scheduled jobs

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Activate virtual environment if it exists
if [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
elif [ -f "$SCRIPT_DIR/../venv/bin/activate" ]; then
    source "$SCRIPT_DIR/../venv/bin/activate"
fi

# Change to project directory
cd "$SCRIPT_DIR"

# Run django-cron
python manage.py runcrons >> logs/cron_output.log 2>&1
