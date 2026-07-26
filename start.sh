#!/bin/bash

echo "🚀 Starting Firebase Extractor Bot..."

# Install Java for APK analysis
apt-get update
apt-get install -y openjdk-17-jdk

# Install Python dependencies
pip install -r requirements.txt

# Run the bot
python bot.py