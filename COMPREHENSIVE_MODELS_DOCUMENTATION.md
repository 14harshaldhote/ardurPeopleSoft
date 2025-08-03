# ArdurTrueAlign People Management System - Comprehensive Models Documentation

## Overview

The ArdurTrueAlign People Management System is a sophisticated Django-based enterprise resource planning (ERP) application specifically designed for comprehensive people and organizational management. The system integrates multiple business domains into a unified platform for managing employee lifecycle, productivity tracking, financial operations, and operational efficiency.

## System Architecture & Core Functionality

### Primary Business Domains
1. **User Session Analytics & Productivity Tracking**
2. **Leave Management System**
3. **Attendance & Shift Management**
4. **Support Ticketing System**
5. **Employee Profile & HR Management**
6. **Project Management & Client Relations**
7. **Financial Management & Payroll**
8. **Communication & Chat System**
9. **Entertainment & Engagement Features**
10. **Conference Room Booking System**

---

## 1. Core Infrastructure Models

### OfficeLocation
**Purpose**: Manages organizational office locations and infrastructure
```python
# Key Fields:
- name, code, address, contact info
- timezone, working_hours, is_active
- Properties: full_address, working_hours_display
```

### ClientProfile
**Purpose**: Extends Django User model for client-specific business data
```python
# Key Features:
- One-to-one relationship with User
- Company information, industry, revenue data
- Contact and registration details
```

---

## 2. Session Management & Analytics System

### UserSession
**Purpose**: Comprehensive session tracking for productivity and security monitoring

**Key Capabilities:**
- **Session Tracking**: Parent-child tab relationships, session fingerprinting
- **Real-time Activity**: Page views, clicks, scrolls, keyboard events, mouse movements
- **Location Intelligence**: GeoIP integration, GPS tracking, device fingerprinting
- **Productivity Metrics**: Work time calculation, focus time, engagement scoring
- **Security Features**: Anomaly detection, fingerprint mismatch detection
- **Progressive Management**: Auto-logout, idle detection, session warnings

**Critical Fields:**
```python
# Session Identity
session_id, parent_session_id, tab_id, device_fingerprint

# Time Tracking
login_time, logout_time, last_activity, idle_start_time
total_time, work_time, focus_time, idle_time

# Location & Device
ip_address, user_agent, device_info, geolocation
country, city, region, timezone_detected

# Activity Analytics
page_views, clicks, scrolls, keyboard_events
mouse_movements, tab_switches, window_focus_events

# Security & Performance
security_score, productivity_score, engagement_score
anomaly_flags, performance_metrics
```

**Methods:**
- `update_activity()`: Real-time activity tracking
- `calculate_metrics()`: Performance and engagement calculations
- `detect_anomalies()`: Security anomaly detection
- `end_session()`: Session cleanup and metrics finalization

### SessionActivity
**Purpose**: Individual activity event tracking linked to sessions
```python
# Decouples granular events from UserSession for performance
# Activity types: click, scroll, keyboard, mouse, page_view, idle, heartbeat
```

---

## 3. Leave Management System

### LeavePolicy
**Purpose**: Dynamic leave policy definitions for different user groups
```python
# Configurable policies per group/department
# Supports multiple leave types with different rules
```

### LeaveType
**Purpose**: Customizable leave categories with business rules
```python
# Key Features:
- paid/unpaid classification
- approval requirements
- documentation needs
- half-day support
- carry-forward rules
```

### LeaveAllocation
**Purpose**: Per-policy leave quotas and constraints
```python
# Features:
- Annual quotas per leave type
- Carry-forward limits
- Maximum consecutive days
- Advance notice requirements
```

### UserLeaveBalance
**Purpose**: Real-time leave balance tracking
```python
# Tracks:
- Current balance per user/type/year
- Used leave, carried forward amounts
- Automatic balance updates on approvals
```

### LeaveRequest
**Purpose**: Enhanced leave request management with business validation
```python
# Key Features:
- Multi-stage approval workflow
- Overlap detection and prevention
- Balance validation
- Auto-conversion to Loss of Pay
- Documentation attachment support
- Retroactive leave handling

# Business Logic:
def clean(self):
    # Validates overlapping requests
    # Checks sufficient balance
    # Enforces policy compliance
    
def save(self):
    # Updates leave balances
    # Handles auto-conversions
    # Triggers notifications
```

### CompOffRequest
**Purpose**: Compensatory leave management
```python
# Links to leave system for automatic balance credits
# Tracks overtime work and approvals
```

---

## 4. Attendance & Shift Management

### ShiftMaster
**Purpose**: Flexible shift definitions with business logic
```python
# Features:
- Day/Night shift support
- Midnight crossing handling
- Working days configuration
- Grace period management
- Break duration calculation

# Key Methods:
def crosses_midnight(self): # Detects night shifts
def is_working_day(self, date): # Checks working day
def expected_hours(self): # Calculates net working hours
```

### Holiday
**Purpose**: Holiday calendar management
```python
# Features:
- Recurring annual holidays
- Date-based holiday detection
- Integration with attendance system
```

### ShiftAssignment
**Purpose**: Dynamic shift assignment management
```python
# Features:
- Date-range based assignments
- Automatic assignment management
- Historical tracking
- Default shift handling

# Key Methods:
@classmethod
def get_user_current_shift(cls, user, date=None):
    # Intelligent shift detection
    # Fallback to default shifts
    
def is_active_on(self, date): # Validates assignment dates
```

### Attendance
**Purpose**: Comprehensive attendance tracking with advanced features

**Core Capabilities:**
- **Automated Status Logic**: Present, Late, Absent, On Leave, WFH, Holiday detection
- **Time Calculations**: Total hours, overtime, late minutes, early departure
- **Multi-location Support**: Office, Home, Remote, Client Site tracking
- **Session Integration**: Links with UserSession for accurate time tracking
- **Regularization Workflow**: Employee requests, manager approvals
- **Break Management**: JSON-based break tracking
- **Audit Trail**: Original values preservation, modification tracking

**Key Fields:**
```python
# Time Tracking
clock_in_time, clock_out_time, total_hours, expected_hours
overtime_hours, late_minutes, early_departure_minutes

# Status Management
status (Present, Late, Absent, On Leave, etc.)
leave_type, location, is_weekend, is_holiday

# Session Integration
first_session, last_session, total_sessions, idle_time

# Regularization
regularization_reason, regularization_status
requested_status, regularization_attempts
original_clock_in_time, original_clock_out_time

# Device & Location Tracking
ip_address, device_info, breaks (JSON)
```

**Advanced Methods:**
```python
@classmethod
def create_attendance_record(cls, user, clock_in_time=None, **kwargs):
    # Intelligent attendance creation with defaults
    
def _update_status_logic(self):
    # Complex business rules for status determination
    
def request_regularization(self, requested_status, reason):
    # Employee regularization workflow
    
def approve_regularization(self, approved_by, comments=None):
    # Manager approval process
```

---

## 5. Support Ticketing System

### Support
**Purpose**: Comprehensive IT/HR support ticket management

**Features:**
- **Multi-category Support**: Hardware, Software, Network, HR, Security, Access Management
- **SLA Management**: Automatic SLA calculation, breach detection
- **Assignment Logic**: Auto-assignment to HR/Admin based on issue type
- **Escalation Tracking**: Multi-level escalation with time tracking
- **User Satisfaction**: Rating and feedback collection
- **Analytics**: Response time, resolution time, reopen tracking

**Key Fields:**
```python
# Core Ticket Data
ticket_id (auto-generated), user, issue_type, subject, description
status (New, Open, In Progress, Resolved, Closed)
priority (Low, Medium, High, Critical)

# Assignment & Routing
assigned_group (HR/Admin), assigned_to_user, cc_users

# SLA & Time Tracking
created_at, due_date, resolved_at, sla_target_date
response_time, time_to_close, resolution_time
sla_breach, sla_status

# User Experience
satisfaction_rating, feedback, reopen_count
```

**Related Models:**
- **StatusLog**: Tracks all status changes with timestamps
- **TicketComment**: User and internal comments with attachment support
- **TicketActivity**: Comprehensive activity logging
- **TicketAttachment**: File attachment management with organized storage
- **CommentAttachment**: Comment-specific attachments

---

## 6. Employee Profile & HR Management

### UserDetails
**Purpose**: Comprehensive employee information management

**Data Categories:**
1. **Personal Information**: DOB, gender, marital status, blood group
2. **Contact Information**: Primary/personal/company emails, addresses
3. **Employment Information**: Type, role, manager, dates, status
4. **Compensation**: Salary, currency, frequency
5. **Government IDs**: PAN, Aadhar, Passport with validation
6. **Banking Details**: Account information for payroll
7. **Previous Employment**: Work history tracking
8. **Skills & Competencies**: Skill matrix management

**Advanced Features:**
```python
# Employment Status Tracking
EMPLOYMENT_STATUS_CHOICES = [
    'active', 'inactive', 'terminated', 'resigned',
    'suspended', 'absconding', 'probation', 'notice_period'
]

# Reporting Chain Management
@property
def get_reporting_chain(self):
    # Builds hierarchical reporting structure

# Duration Calculations
@property
def employment_duration(self):
    # Calculates years and months of service

# Status Management
def save(self): # Handles status change tracking
```

### UserActionLog
**Purpose**: Audit trail for important HR actions
```python
# Tracks: User creation, updates, status changes, role changes
# Provides complete audit history for compliance
```

---

## 7. Project Management & Client Relations

### Project
**Purpose**: Project lifecycle management with client integration
```python
# Features:
- Multi-client project support
- Status tracking (Completed, In Progress, Pending, On Hold)
- Value tracking, delivery format specification
- Deadline management with overdue detection
```

### ProjectAssignment
**Purpose**: Team member assignment to projects
```python
# Features:
- Role-based assignments (Manager, Employee, Support, QC)
- Hours tracking, soft delete support
- Performance monitoring
```

### ClientParticipation
**Purpose**: Client engagement and feedback management
```python
# Tracks client feedback, approval status
# Supports client project collaboration
```

---

## 8. Financial Management System

### FinancialParameter
**Purpose**: Dynamic financial parameter management
```python
# Features:
- Multi-type values (decimal, percentage, integer, text, JSON, boolean, date)
- Time-validity with fiscal year support
- Entity-specific and global parameters
- Approval workflow for financial governance
- Category-based organization (tax, fee, rate, threshold, limit, rule)

# Usage Examples:
FinancialParameter.get_param('income_tax_rate', entity=employee, date=today)
FinancialParameter.get_all_params(category='tax', fiscal_year='2023-2024')
```

### Financial Transaction Models:
- **DailyExpense**: Daily expense tracking with approval workflow
- **Voucher**: Payment/Receipt/Journal vouchers with multi-level approval
- **BankAccount**: Bank account management with balance tracking
- **BankPayment**: Payment processing with verification workflow
- **Subscription**: Recurring subscription management
- **ClientInvoice**: Client billing with multiple models (Per Order, Per FTE, Hybrid)
- **ChartOfAccount**: Hierarchical account structure

---

## 9. Communication & Chat System

### ChatGroup
**Purpose**: Department/team group communication
```python
# Features:
- Manager/Admin only creation
- Member role management (admin, member)
- Unread message tracking
- Activity status monitoring
```

### DirectMessage
**Purpose**: One-to-one private messaging
```python
# Features:
- Two-participant validation
- Message history management
- Unread count tracking
```

### Message
**Purpose**: Universal message handling for groups and DMs
```python
# Features:
- Multi-type messages (text, file, system)
- File attachment support
- Edit/delete functionality
- Read receipt tracking via MessageRead model
```

---

## 10. Entertainment & Engagement

### TicTacToeGame System
**Purpose**: Employee engagement through gaming

**Models:**
- **GameIcon**: Customizable game symbols
- **TicTacToeGame**: Complete game state management with real-time play
- **GameSpectator**: Spectator mode support
- **PlayerStats**: Leaderboard and statistics tracking
- **Notification**: Game-related notifications

**Features:**
- Real-time multiplayer gameplay
- Spectator support
- Comprehensive statistics
- Tournament potential
- Notification system integration

---

## 11. Conference Room Booking System

### Room
**Purpose**: Conference room resource management

**Features:**
- **Multi-location Support**: Integrated with OfficeLocation
- **Room Types**: Conference, Huddle, Meeting, Board rooms
- **Status Management**: Active, Maintenance, Inactive
- **Analytics Integration**: Booking statistics, utilization tracking
- **Capacity Management**: Seating and facility specifications

### ConferenceBooking
**Purpose**: Comprehensive booking management system

**Advanced Features:**
- **24/7 Booking Support**: No time restrictions (configurable)
- **Conflict Prevention**: Automatic overlap detection
- **Recurring Bookings**: Daily, Weekly, Monthly patterns
- **Check-in System**: Meeting attendance tracking
- **No-show Detection**: Automatic identification and marking
- **Cost Tracking**: Hourly rates and total cost calculation
- **Approval Workflow**: Multi-stage approval if required
- **Cancellation Management**: Reason tracking and analytics

**Analytics & Utilities:**
- **BookingAnalytics**: Comprehensive reporting and dashboard data
- **RoomManager**: Availability detection and alternative suggestions
- **BookingValidator**: Business rule validation
- **BookingNotification**: Reminder and notification management

---

## 12. Additional Specialized Models

### Break Management
```python
class Break:
    # Manages employee break tracking
    # Features: Daily limits, duration tracking, extension reasons
    # Types: Tea Break 1, Lunch/Dinner, Tea Break 2
```

### Timesheet Management
```python
class Timesheet:
    # Project time tracking with approval workflow
    # Features: Version control, validation, manager review
    # Prevents: Backdated entries, excessive hours
```

### Presence Management
```python
class Presence:
    # Manual attendance marking by managers
    # Supports: Present, Absent, Late, Leave, WFH, Business Trip
```

### Appraisal System
```python
class Appraisal:
    # Employee performance review workflow
    # Features: Multi-stage approval, item tracking, attachment support
```

### Global Updates
```python
class GlobalUpdate:
    # HR announcements and company updates
    # Status: Upcoming, Released, Scheduled
```

---

## Key Technical Strengths

### 1. **Comprehensive Business Logic**
- Advanced validation and business rule enforcement
- Automatic calculations and status updates
- Cross-model data consistency

### 2. **Audit & Compliance**
- Complete audit trails for all critical operations
- Historical data preservation
- User action logging

### 3. **Performance Optimization**
- Strategic database indexing
- Efficient query patterns
- JSON field usage for flexible data storage

### 4. **Security Features**
- Session fingerprinting and anomaly detection
- Location-based access tracking
- Device information logging

### 5. **User Experience**
- Regularization workflows for error correction
- Notification systems for real-time updates
- Comprehensive dashboard data provision

### 6. **Scalability Design**
- Soft delete patterns
- Flexible parameter systems
- Modular architecture

---

## Integration Points

### Session ↔ Attendance Integration
```python
# UserSession automatically updates Attendance records
# Provides accurate time tracking across systems
Attendance.update_session_data(user, session, date)
```

### Leave ↔ Attendance Integration
```python
# Leave approvals automatically set attendance status
# Prevents conflicts between leave and attendance marking
```

### Project ↔ Timesheet Integration
```python
# Project assignments link to timesheet entries
# Provides comprehensive project time tracking
```

### Financial Parameter Integration
```python
# Dynamic financial calculations across all modules
# Centralized parameter management for consistency
```

---

## Recommendations for Enhancement

### 1. **Performance Optimizations**
- Implement session event archiving for large JSON fields
- Add database partitioning for high-volume tables
- Optimize complex query patterns

### 2. **Security Hardening**
- Implement JSON field sanitization
- Add rate limiting for session updates
- Enhance anomaly detection algorithms

### 3. **Code Quality Improvements**
- Replace print() statements with proper logging
- Extract complex business logic into service classes
- Add comprehensive unit test coverage

### 4. **Feature Enhancements**
- Add mobile API support
- Implement real-time notifications
- Create advanced analytics dashboards

### 5. **Configuration Management**
- Make hardcoded values configurable
- Add feature flags for optional modules
- Implement environment-specific settings

---

## Conclusion

The ArdurTrueAlign People Management System represents a sophisticated, feature-rich enterprise application that comprehensively addresses modern organizational needs. The system demonstrates advanced Django development practices, complex business logic implementation, and thoughtful integration between multiple business domains.

The extensive model structure provides a solid foundation for enterprise people management, with particular strengths in session analytics, attendance management, and operational efficiency tracking. With focused improvements on performance optimization and code maintainability, this system can serve as a powerful platform for organizational excellence.

**Total Models: 70+**  
**Lines of Code: ~7,200**  
**Business Domains: 11**  
**Key Features: 100+**

---

*This documentation represents the comprehensive analysis of the models.py file as of the current version. For implementation details and API documentation, refer to the views, serializers, and URL configuration files.*
