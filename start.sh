#!/bin/bash

# Secure Web Authentication System Start Script

echo "🔐 Starting Secure Web Authentication System..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found. Please run 'npm run setup' first."
    exit 1
fi

# Check if MongoDB is running (optional check)
# Uncomment the following lines if you want to check MongoDB connection
# echo "🔍 Checking MongoDB connection..."
# mongosh --eval "db.runCommand('ping')" --quiet > /dev/null 2>&1
# if [ $? -ne 0 ]; then
#     echo "⚠️  Warning: Cannot connect to MongoDB. Make sure it's running."
# fi

# Start the application
if [ "$NODE_ENV" = "production" ]; then
    echo "🚀 Starting in production mode..."
    npm start
else
    echo "🛠️  Starting in development mode..."
    npm run dev
fi
