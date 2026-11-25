#!/bin/bash

# RDNSx Docker Build Script

set -e

echo "🐳 Building RDNSx Docker image..."

# Build the Docker image
docker build -t rdnsx:latest -t telcosec/rdnsx:latest .

echo "✅ Build complete!"
echo ""
echo "🚀 Run RDNSx:"
echo "   docker run --rm rdnsx:latest --help"
echo ""
echo "📝 Examples:"
echo "   # ✅ WORKING: Basic DNS query with host networking"
echo "   echo 'example.com' | docker run --rm --network host -i rdnsx:latest query --resolvers '8.8.8.8:53'"
echo ""
echo "   # Multiple domains with host networking"
echo "   echo -e 'google.com\\ncloudflare.com' | docker run --rm --network host -i rdnsx:latest query --resolvers '8.8.8.8,1.1.1.1'"
echo ""
echo "   # Subdomain enumeration (host networking + wordlist)"
echo "   docker run --rm --network host -v \$(pwd)/wordlists:/app/wordlists rdnsx:latest bruteforce --resolvers '8.8.8.8:53' -d example.com -w /app/wordlists/subdomains.txt"
echo ""
echo "   # With docker-compose (uses host networking for DNS)"
echo "   docker-compose up -d"
echo "   docker-compose exec rdnsx rdnsx query -d example.com"