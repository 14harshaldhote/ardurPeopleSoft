# Leave Management Templates - Complete Set

## Summary

I've created **15 comprehensive Jinja2/HTML templates** for your leave management system using Tailwind CSS with a beautiful glassmorphism design inspired by your support templates. All templates are production-ready and fully responsive.

## Templates Created

### Employee Templates

#### 1. **employee_dashboard.html**
**Location:** `/trueAlign/templates/leave_management/employee_dashboard.html`

**Features:**
- Displays leave balances for all leave types with gradient color coding
- Shows color-coded cards for Casual Leave (blue), Sick Leave (red), Comp-Off (purple)
- Recent leave history (last 10 requests)
- Quick action buttons for applying leave and comp-off
- Status badges for Pending/Approved/Rejected/Cancelled
- Empty state handling when no leave history exists

#### 2. **apply_leave.html**  
**Location:** `/trueAlign/templates/leave_management/apply_leave.html`

**Features:**
- Complete leave application form with all required fields:
  - Leave type selection
  - Start and end date pickers
  - Half-day checkbox option
  - Reason text area
  - Approver dropdown  
  - Optional documentation upload
- Form validation error display
- Cancel and submit actions
- Responsive design for all screen sizes

#### 3. **leave_detail.html**
**Location:** `/trueAlign/templates/leave_management/leave_detail.html`

**Features:**
- Comprehensive leave request details display
- Status badges with animated pulse for pending states
- Leave information sidebar (employee, approver, dates)
- Edit button for pending requests (own leaves only)
- Rejection reason display if rejected
- Supporting documentation view/download
- Action buttons for cancel (employees), approve/reject (managers/HR)
- Modal for rejection with reason input
- Half-day and retroactive leave indicators

#### 4. **apply_comp_off.html**
**Location:** `/trueAlign/templates/leave_management/apply_comp_off.html`

**Features:**
- Informational banner explaining comp-off concept
- Form fields for overtime work details
- Conversion rate information box (8hrs = 1 day, 4hrs = 0.5 day)
- Form validation and error display

#### 5. **my_leaves.html**
**Location:** `/trueAlign/templates/leave_management/my_leaves.html`

**Features:**
- Complete leave history with advanced filtering
- Filter by status, leave type, and date range
- Clear filters option
- Count of total requests displayed
- Empty state with context-aware messages

### Manager Templates

#### 6. **manager_dashboard.html**
**Location:** `/trueAlign/templates/leave_management/manager_dashboard.html`

**Features:**
- Statistics cards (pending approvals, team size, on leave today, present)
- Pending approvals list with quick access
- Team leave calendar showing upcoming leaves
- Employee avatars with initials
- Empty states when no pending approvals

#### 7. **team_leaves.html**
**Location:** `/trueAlign/templates/leave_management/team_leaves.html`

**Features:**
- Comprehensive team leave view with filters
- Filter by team member, status, leave type, and dates
- Team statistics dashboard (team size, on leave, present, upcoming)
- Quick approve button for pending requests
- Team member selection dropdown

### HR Templates

#### 8. **hr_dashboard.html**
**Location:** `/trueAlign/templates/leave_management/hr_dashboard.html`

**Features:**
- Organization-wide statistics
- All pending requests across the organization
- Retroactive leave tracking
- Leave type distribution analytics
- Monthly leave counts

#### 9. **balance_adjustment.html**
**Location:** `/trueAlign/templates/leave_management/balance_adjustment.html`

**Features:**
- Manual leave balance adjustment form
- Warning banner about manual adjustments
- Employee and leave type selection
- Adjustment type (credit/debit) selector
- Reason field with audit logging
- Current balance display
- Confirmation dialog before submission

### Admin Templates

#### 10. **admin_dashboard.html**
**Location:** `/trueAlign/templates/leave_management/admin_dashboard.html`

**Features:**
- System-wide statistics (users, policies, leave types, pending requests)
- Quick action cards for common tasks
- Links to leave type and policy management
- Leave distribution analytics
- Visual circular charts for leave types

#### 11. **admin/leavetype_list.html**
**Location:** `/trueAlign/templates/leave_management/admin/leavetype_list.html`

**Features:**
- List of all configured leave types
- Visual indicators for:
  - Active/Inactive status
  - Paid/Unpaid types
  - Requires approval
  - Requires documentation  
  - Half-day allowed
  - Maximum days per year
- Color-coded icons for different leave types
- Edit action buttons
- Empty state with call-to-action

#### 12. **admin/leavetype_form.html**
**Location:** `/trueAlign/templates/leave_management/admin/leavetype_form.html`

**Features:**
- Create/Edit leave type form
- Sections: Basic Information, Configuration, Options
- Fields for all leave type properties
- Checkbox options for various settings
- Form validation display
- Works for both create and update operations

#### 13. **admin/policy_list.html**
**Location:** `/trueAlign/templates/leave_management/admin/policy_list.html`

**Features:**
- List all leave policies
- Shows policy allocations inline
- Active/Inactive and Default badges
- Effective date ranges
- Edit actions for each policy
- Empty state with create option

#### 14. **admin/policy_form.html**
**Location:** `/trueAlign/templates/leave_management/admin/policy_form.html`

**Features:**
- Create/Edit leave policy form
- Basic information section
- Effective period configuration
- Active and default policy toggles
- Info box about next steps (allocations)
- Works for both create and update

#### 15. **admin/allocation_form.html**
**Location:** `/trueAlign/templates/leave_management/admin/allocation_form.html`

**Features:**
- Configure leave type allocations for policies
- Policy and leave type selection
- Allocated days configuration
- Carry forward limit settings
- Proration method dropdown
- Accrual frequency settings
- Encashment allowed option

## Design Features

### Consistent UI/UX Elements
- **Glassmorphism Design:** Backdrop blur effects with semi-transparent white backgrounds
- **Gradient Orbs:** Animated soft gradient spheres in the background
- **Color Coding:** 
  - Emerald/Teal/Green for leave-related actions
  - Purple/Indigo for comp-off and manager features
  - Red/Orange for admin features
  - Cyan/Blue for HR features
- **Status Badges:** Color-coded with animated pulse for pending states
- **Responsive Design:** Works on mobile (320px+), tablet (768px+), and desktop (1024px+)
- **Hover Effects:** Scale and background color transitions
- **Smooth Animations:** Transition effects on all interactive elements

### Typography & Spacing
- Consistent font sizes: xs (10-11px), sm (12-14px), base (14-16px), lg-3xl for headers
- Proper spacing using Tailwind's spacing scale (2, 3, 4, 6, 8, 12)
- Line clamping for long text to prevent overflow

### Navigation Patterns  
- Consistent "Back to Dashboard" buttons
- Breadcrumb-style navigation bars
- Quick action primary buttons in header sections

## Integration Notes

### URL Pattern Updates
Ensure your `urls.py` includes these URL patterns:
- `leave_management:employee_dashboard`
- `leave_management:apply_leave`
- `leave_management:leave_detail`
- `leave_management:leave_update`
- `leave_management:leave_action`
- `leave_management:apply_comp_off`
- `leave_management:manager_dashboard`
- `leave_management:leavetype_list`
- `leave_management:leavetype_create`
- `leave_management:leavetype_update`

### Form Widget Styling
The templates expect Django forms to use Tailwind CSS classes. You may need to configure your forms to output the correct HTML or use a form library like `django-widget-tweaks` or `crispy-tailwind`.

### Base Template Requirements
These templates extend `base.html` and expect:
- Tailwind CSS to be properly configured
- Alpine.js (optional, for interactive features)
- Proper block definitions: `{% block title %}` and `{% block content %}`

## Browser Compatibility
- Modern browsers (Chrome, Firefox, Safari, Edge)
- Responsive design tested for mobile (320px+), tablet (768px+), and desktop (1024px+)
- Backdrop filter support required for glassmorphism effects

---

All templates follow best practices for:
- Accessibility (semantic HTML, ARIA labels where needed)
- SEO (proper heading hierarchy)
- Performance (optimized CSS, minimal JavaScript)
- Maintainability (consistent patterns, well-organized code)
