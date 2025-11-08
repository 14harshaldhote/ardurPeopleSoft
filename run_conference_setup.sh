#!/bin/bash

# Conference Room Booking System - Setup Script
# Run this script to set up the conference room booking system

echo "🚀 Conference Room Booking System - Setup"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check if Python is available
if ! command -v python &> /dev/null; then
    print_error "Python is not installed or not in PATH"
    exit 1
fi

print_success "Python found"

# Step 1: Create migrations
echo ""
echo "📦 Step 1: Creating database migrations..."
python manage.py makemigrations
if [ $? -eq 0 ]; then
    print_success "Migrations created successfully"
else
    print_error "Failed to create migrations"
    exit 1
fi

# Step 2: Apply migrations
echo ""
echo "🗄️  Step 2: Applying migrations to database..."
python manage.py migrate
if [ $? -eq 0 ]; then
    print_success "Migrations applied successfully"
else
    print_error "Failed to apply migrations"
    exit 1
fi

# Step 3: Collect static files (optional, skip if it fails)
echo ""
echo "📁 Step 3: Collecting static files..."
python manage.py collectstatic --noinput
if [ $? -eq 0 ]; then
    print_success "Static files collected"
else
    print_warning "Static files collection skipped (not critical)"
fi

# Step 4: Ask if user wants to seed sample data
echo ""
read -p "Would you like to create sample data? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🌱 Step 4: Seeding sample data..."
    python manage.py seed_conference_data
    if [ $? -eq 0 ]; then
        print_success "Sample data created successfully"
    else
        print_warning "Sample data creation failed (you can do this manually later)"
    fi
else
    print_warning "Skipping sample data creation"
fi

# Summary
echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "📍 Next Steps:"
echo ""
echo "1. Configure email settings in .env file (see CONFERENCE_ROOM_QUICK_START.md)"
echo "2. Start the development server: python manage.py runserver"
echo "3. Access the system:"
echo "   • Browse Rooms: http://localhost:8000/conference/rooms/"
echo "   • Admin Panel: http://localhost:8000/conference/admin/rooms/"
echo "   • My Bookings: http://localhost:8000/conference/bookings/my/"
echo ""
echo "📚 Documentation:"
echo "   • Quick Start: CONFERENCE_ROOM_QUICK_START.md"
echo "   • Full Docs: CONFERENCE_ROOM_MODULE_DOCS.md"
echo "   • Checklist: INSTALLATION_CHECKLIST.md"
echo ""
echo "🎉 Happy Booking!"
echo ""
