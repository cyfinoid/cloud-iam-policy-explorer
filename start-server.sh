#!/bin/bash

###############################################################################
# Quick Start Web Server
# Starts a local web server to avoid CORS issues with ES6 modules
###############################################################################

PORT="${1:-8000}"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║         AWS Policy Explorer - Starting Server           ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "🚀 Starting local web server on port $PORT..."
echo ""
echo "   📍 URL: http://localhost:$PORT"
echo ""
echo "   Press Ctrl+C to stop the server"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Try different server options in order of preference
if command -v python3 &> /dev/null; then
    echo "Using Python 3..."
    python3 -m http.server $PORT
elif command -v python &> /dev/null; then
    echo "Using Python 2..."
    python -m SimpleHTTPServer $PORT
elif command -v php &> /dev/null; then
    echo "Using PHP..."
    php -S localhost:$PORT
elif command -v node &> /dev/null; then
    echo "Using Node.js (npx http-server)..."
    npx -y http-server -p $PORT
else
    echo "❌ Error: No web server found!"
    echo ""
    echo "Please install one of the following:"
    echo "  • Python 3:  brew install python3"
    echo "  • PHP:       brew install php"
    echo "  • Node.js:   brew install node"
    echo ""
    exit 1
fi

