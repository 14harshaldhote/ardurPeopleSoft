"""
Constants for the profile application.
Centralizes magic strings, configuration values, and patterns.
"""

# Password and security
DEFAULT_PASSWORD_LENGTH = 12
DEFAULT_PASSWORD_PREFIX = "Welcome@"

# Pagination
DEFAULT_PAGINATION_SIZE = 10
MAX_PAGINATION_SIZE = 100

# File upload
MAX_CSV_FILE_SIZE_MB = 10
MAX_CSV_FILE_SIZE_BYTES = MAX_CSV_FILE_SIZE_MB * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = ['.csv', '.xlsx', '.xls']
ALLOWED_UPLOAD_MIME_TYPES = [
    'text/csv',
    'text/plain',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
]

# Employee ID
EMPLOYEE_ID_PREFIXES = {
    'betul': 'ATS',
    'pune': 'AT',
    'default': 'EMP'
}

# Reserved ID ranges for Management and Finance roles
RESERVED_ID_RANGES = {
    'priority_start': 1,
    'priority_end': 15,
    'reserved_start': 301,
    'reserved_end': 400,
    'regular_start': 101,
    'regular_end': 300
}

# Finance and Management group IDs (update based on your Group IDs)
RESERVED_GROUPS = ['7', '8']  # Finance and Management

# Cache timeouts (seconds)
CACHE_TIMEOUT_ANALYTICS = 300  # 5 minutes
CACHE_TIMEOUT_DASHBOARD = 60   # 1 minute
CACHE_TIMEOUT_USER_LIST = 120  # 2 minutes

# Validation patterns
PAN_PATTERN = r'^[A-Z]{5}[0-9]{4}[A-Z]$'
AADHAR_PATTERN = r'^\d{12}$'
IFSC_PATTERN = r'^[A-Z]{4}0[A-Z0-9]{6}$'
INDIAN_PHONE_PATTERN = r'^[6-9]\d{9}$'

# Error messages
ERROR_MESSAGES = {
    'pan_invalid': 'PAN must be in format: ABCDE1234F (5 letters, 4 digits, 1 letter)',
    'aadhar_invalid': 'Aadhar must be exactly 12 digits',
    'ifsc_invalid': 'Invalid IFSC code format (e.g., SBIN0001234)',
    'phone_invalid': 'Enter a valid 10-digit Indian mobile number starting with 6-9',
    'email_duplicate': 'A user with this email already exists',
    'permission_denied': 'You do not have permission to perform this action'
}

# Bulk upload
BULK_UPLOAD_REQUIRED_COLUMNS = ['first_name', 'last_name', 'email']
BULK_UPLOAD_OPTIONAL_COLUMNS = ['employee_type', 'phone', 'department']
MAX_BULK_UPLOAD_ROWS = 1000

# Action log types
ACTION_TYPES = {
    'create': 'User Created',
    'update': 'User Updated',
    'delete': 'User Deleted',
    'status_change': 'Status Changed',
    'password_reset': 'Password Reset',
    'bulk_upload': 'Bulk Upload',
    'export': 'Data Exported'
}
