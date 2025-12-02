#!/bin/bash

# ============================================
# Finance Module - Phase 1 Installation Script
# GoDaddy cPanel Compatible Version
# ============================================

set -e  # Exit on error

echo "====================================="
echo "Finance Module: Phase 1 Setup"
echo "cPanel-Compatible Production Libraries"
echo "====================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if we're in correct directory
if [ ! -f "manage.py" ]; then
    echo -e "${RED}Error: This script must be run from the Django project root directory${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Found Django project${NC}"
echo ""

# ============================================
# Step 1: Environment Detection
# ============================================

echo "Step 1: Detecting environment..."
echo "---------------------------------------"

# Check Python version
python_version=$(python --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"

# Check pip
if ! command -v pip &> /dev/null; then
    echo -e "${RED}Error: pip not found${NC}"
    exit 1
fi
echo -e "${GREEN}✓ pip is installed${NC}"

# Detect if on cPanel (check for common cPanel paths)
if [ -d "/home/$USER/public_html" ] || [ -d "/usr/local/cpanel" ]; then
    echo -e "${BLUE}ℹ Detected cPanel environment${NC}"
    IS_CPANEL=true
else
    echo -e "${BLUE}ℹ Local/VPS environment detected${NC}"
    IS_CPANEL=false
fi

echo ""

# ============================================
# Step 2: Choose Installation Type
# ============================================

echo "Step 2: Select installation type..."
echo "---------------------------------------"

if [ "$IS_CPANEL" = true ]; then
    echo -e "${YELLOW}cPanel detected - installing production-safe libraries only${NC}"
    REQUIREMENTS_FILE="requirements/finance-production.txt"
else
    echo "Choose installation type:"
    echo "1) Production (cPanel-safe, 25 libraries)"
    echo "2) Development (All libraries + dev tools)"
    read -p "Enter choice [1-2]: " choice
    
    case $choice in
        1)
            REQUIREMENTS_FILE="requirements/finance-production.txt"
            echo -e "${GREEN}Selected: Production (cPanel-safe)${NC}"
            ;;
        2)
            REQUIREMENTS_FILE="requirements/finance-dev.txt"
            echo -e "${GREEN}Selected: Development (Full suite)${NC}"
            ;;
        *)
            echo -e "${RED}Invalid choice. Using production.${NC}"
            REQUIREMENTS_FILE="requirements/finance-production.txt"
            ;;
    esac
fi

echo ""

# ============================================
# Step 3: Install Libraries
# ============================================

echo "Step 3: Installing Python libraries..."
echo "---------------------------------------"
echo -e "${BLUE}Installing from: $REQUIREMENTS_FILE${NC}"

pip install -r "$REQUIREMENTS_FILE"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ All libraries installed successfully${NC}"
else
    echo -e "${RED}Error: Installation failed${NC}"
    exit 1
fi

echo ""

# ============================================
# Step 4: Verify Installation
# ============================================

echo "Step 4: Verifying installation..."
echo "---------------------------------------"

python -c "
import sys
success = True

# Core libraries (always installed)
try:
    import djmoney
    import moneyed
    import forex_python
    import babel
    import arrow
    import stdnum
    import pdfplumber
    import pandas
    print('✓ Core libraries imported successfully')
except ImportError as e:
    print(f'✗ Core library import failed: {e}')
    success = False
    sys.exit(1)

# Optional libraries (dev only)
if '$REQUIREMENTS_FILE' == 'requirements/finance-dev.txt':
    try:
        import spacy
        import statsmodels
        print('✓ Development libraries imported successfully')
    except ImportError as e:
        print(f'⚠ Some dev libraries not available: {e}')

sys.exit(0 if success else 1)
"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Installation verified${NC}"
else
    echo -e "${RED}Error: Verification failed${NC}"
    exit 1
fi

echo ""

# ============================================
# Step 5: Generate Configuration
# ============================================

echo "Step 5: Generating configuration..."
echo "---------------------------------------"

# Generate encryption key
encryption_key=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Create .env.finance
cat > .env.finance << EOF
# Finance Module Configuration
# Generated on $(date)
# Environment: $(if [ "$IS_CPANEL" = true ]; then echo "cPanel"; else echo "Local/VPS"; fi)

# Django-Money Settings
DEFAULT_CURRENCY=INR
CURRENCIES=('INR', 'USD', 'EUR', 'GBP', 'AED')

# Encryption (for PII Protection)
FIELD_ENCRYPTION_KEY=$encryption_key

# Forex Settings
FOREX_CACHE_TTL=3600  # 1 hour

# Logging
FINANCE_LOG_LEVEL=INFO
FINANCE_LOG_FILE=logs/finance.json

# Cache Backend (for cPanel, use database or file cache)
# CACHE_BACKEND=database  # or 'file' or 'dummy'
# For VPS with Redis:
# REDIS_HOST=localhost
# REDIS_PORT=6379
# REDIS_DB=0
EOF

echo -e "${GREEN}✓ Created .env.finance${NC}"
echo -e "${YELLOW}⚠ Add .env.finance to .gitignore${NC}"

echo ""

# ============================================
# Step 6: Create Directories
# ============================================

echo "Step 6: Creating directory structure..."
echo "---------------------------------------"

mkdir -p logs
mkdir -p trueAlign/finance/analytics
mkdir -p trueAlign/finance/rules

echo -e "${GREEN}✓ Created directories${NC}"

echo ""

# ============================================
# Step 7: cPanel-Specific Instructions
# ============================================

if [ "$IS_CPANEL" = true ]; then
    echo "====================================="
    echo "cPanel-Specific Setup"
    echo "====================================="
    echo ""
    echo "1. Cache Configuration:"
    echo "   Use Django's database cache (no Redis needed):"
    echo "   python manage.py createcachetable finance_cache"
    echo ""
    echo "2. For background tasks (instead of Celery):"
    echo "   Use cron jobs + management commands"
    echo "   Example: */15 * * * * cd ~/yourapp && python manage.py process_pending_tasks"
    echo ""
    echo "3. Excluded libraries (need system packages):"
    echo "   ⛔ tabula-py (Java)"
    echo "   ⛔ camelot-py (Ghostscript)"
    echo "   ⛔ pytesseract (Tesseract binary)"
    echo "   ⛔ celery/redis (background workers)"
    echo ""
    echo "   Use pdfplumber instead for PDF parsing ✓"
    echo ""
fi

# ============================================
# Success Summary
# ============================================

echo "====================================="
echo "Installation Complete! ✓"
echo "====================================="
echo ""
echo "Installed libraries from: $REQUIREMENTS_FILE"
echo ""
echo "Next steps:"
echo "1. Configure settings.py:"
echo "   - Add 'djmoney', 'django_iban' to INSTALLED_APPS"
echo "   - Configure JSON logging"
echo "   - Set up Django cache (database/file for cPanel)"
echo ""
echo "2. Test installation:"
echo "   python manage.py shell"
echo "   >>> from djmoney.money import Money"
echo "   >>> from trueAlign.finance.validators import validate_pan"
echo "   >>> from trueAlign.finance.currency_converter import FXConverter"
echo ""
echo "3. Run migrations (after model updates):"
echo "   python manage.py makemigrations"
echo "   python manage.py migrate"
echo ""
if [ "$IS_CPANEL" = true ]; then
    echo "4. Create cache table for cPanel:"
    echo "   python manage.py createcachetable finance_cache"
    echo ""
fi
echo -e "${GREEN}Ready for django-money model migration!${NC}"
