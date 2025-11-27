-- =============================================
-- TrueAlign Database Migration Script
-- Generated from production database schema
-- Database: ardurtechnology
-- Tables: 39 trueAlign_ tables
-- =============================================

SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- =============================================
-- INDEPENDENT TABLES (No Foreign Keys)
-- =============================================

-- Table: trueAlign_holiday
CREATE TABLE `trueAlign_holiday` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `date` date NOT NULL,
  `recurring_yearly` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_layoutpreference
CREATE TABLE `trueAlign_layoutpreference` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `layout` longtext NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_leavetype
CREATE TABLE `trueAlign_leavetype` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` longtext,
  `is_paid` tinyint(1) NOT NULL,
  `requires_approval` tinyint(1) NOT NULL,
  `requires_documentation` tinyint(1) NOT NULL,
  `count_weekends` tinyint(1) NOT NULL,
  `can_be_half_day` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `max_days_allowed` int(10) unsigned NOT NULL DEFAULT 30,
  `carry_forward_allowed` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_officelocation
CREATE TABLE `trueAlign_officelocation` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `code` varchar(10) NOT NULL,
  `address_line1` varchar(255) NOT NULL,
  `address_line2` varchar(255) NOT NULL,
  `city` varchar(100) NOT NULL,
  `state` varchar(100) NOT NULL,
  `postal_code` varchar(20) NOT NULL,
  `country` varchar(100) NOT NULL,
  `phone` varchar(20) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `timezone` varchar(50) NOT NULL,
  `working_hours_start` time(6) NOT NULL,
  `working_hours_end` time(6) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  UNIQUE KEY `code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_systemerror
CREATE TABLE `trueAlign_systemerror` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `error_message` longtext NOT NULL,
  `error_time` datetime(6) NOT NULL,
  `resolved` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_systemusage
CREATE TABLE `trueAlign_systemusage` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `peak_time_start` datetime(6) NOT NULL,
  `peak_time_end` datetime(6) NOT NULL,
  `active_users_count` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_subscription
CREATE TABLE `trueAlign_subscription` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `vendor` varchar(255) NOT NULL,
  `subscription_type` varchar(100) NOT NULL,
  `amount` decimal(15,2) NOT NULL,
  `frequency` varchar(20) NOT NULL,
  `start_date` date NOT NULL,
  `next_payment_date` date NOT NULL,
  `auto_renew` tinyint(1) NOT NULL,
  `status` varchar(20) NOT NULL,
  `alert_days` int(11) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- TABLES WITH FOREIGN KEYS TO auth_user/auth_group
-- =============================================

-- Table: trueAlign_shiftmaster
CREATE TABLE `trueAlign_shiftmaster` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `shift_type` varchar(20) NOT NULL DEFAULT 'Day Shift',
  `start_time` time(6) NOT NULL,
  `end_time` time(6) NOT NULL,
  `shift_duration` decimal(5,2) NOT NULL DEFAULT 8.00,
  `break_duration` bigint(20) NOT NULL DEFAULT 1800000000,
  `grace_period` bigint(20) NOT NULL DEFAULT 900000000,
  `work_days` varchar(20) NOT NULL DEFAULT 'Weekdays',
  `custom_work_days` varchar(255),
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `created_by_id` int(11),
  `color_code` char(7) NOT NULL DEFAULT '#3B82F6',
  `description` text,
  `requires_approval` tinyint(1) NOT NULL DEFAULT 0,
  `min_rest_hours` decimal(4,2) NOT NULL DEFAULT 8.00,
  `max_consecutive_days` int(11) NOT NULL DEFAULT 6,
  `overtime_threshold` decimal(4,2) NOT NULL DEFAULT 8.00,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  KEY `fk_shiftmaster_created_by` (`created_by_id`),
  CONSTRAINT `fk_shiftmaster_created_by` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_usersession
CREATE TABLE `trueAlign_usersession` (
  `id` char(36) NOT NULL,
  `user_id` int(11) NOT NULL,
  `parent_session_id` varchar(100),
  `tab_id` varchar(100),
  `is_primary_tab` tinyint(1) NOT NULL DEFAULT 0,
  `session_fingerprint` varchar(255),
  `session_key` varchar(40) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `login_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `logout_time` datetime,
  `last_activity` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ended_at` datetime,
  `session_end_time` datetime,
  `start_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tab_opened_time` datetime,
  `tab_last_focus` datetime,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `is_idle` tinyint(1) NOT NULL DEFAULT 0,
  `idle_start_time` datetime,
  `total_idle_time` bigint(20) NOT NULL DEFAULT 0,
  `working_time` bigint(20) NOT NULL DEFAULT 0,
  `focus_time` bigint(20) NOT NULL DEFAULT 0,
  `session_duration` float,
  `idle_time` time,
  `ip_address` varchar(45),
  `user_agent` text,
  `browser_fingerprint` text,
  `browser` varchar(100),
  `os` varchar(100),
  `csrf_token` char(64),
  `csrf_token_created` datetime,
  `device_type` varchar(20),
  `screen_resolution` varchar(20),
  `timezone_offset` int(11),
  `language` varchar(10),
  `battery_level` float,
  `connection_type` varchar(20),
  `location_history` longtext,
  `location_country` varchar(100),
  `location_region` varchar(100),
  `location_city` varchar(100),
  `location_latitude` float,
  `location_longitude` float,
  `location_accuracy` float,
  `location_type` varchar(20),
  `tab_title` longtext NOT NULL DEFAULT ('[]'),
  `tab_url` longtext NOT NULL DEFAULT ('[]'),
  `url` longtext NOT NULL DEFAULT ('[]'),
  `title` longtext NOT NULL DEFAULT ('[]'),
  `referrer` longtext NOT NULL DEFAULT ('[]'),
  `page_views` longtext NOT NULL DEFAULT ('[]'),
  `clicks` longtext NOT NULL DEFAULT ('[]'),
  `scrolls` longtext NOT NULL DEFAULT ('[]'),
  `keyboard_events` longtext NOT NULL DEFAULT ('[]'),
  `mouse_movements` int(11) NOT NULL DEFAULT 0,
  `tab_visibility_log` longtext NOT NULL DEFAULT ('[]'),
  `tab_switches` int(11) NOT NULL DEFAULT 0,
  `background_time` bigint(20) NOT NULL DEFAULT 0,
  `idle_state_changes` longtext NOT NULL DEFAULT ('[]'),
  `performance_metrics` longtext NOT NULL DEFAULT ('{}'),
  `network_events` longtext NOT NULL DEFAULT ('[]'),
  `error_events` longtext NOT NULL DEFAULT ('[]'),
  `custom_timeout` int(10) unsigned,
  `inactivity_warnings_sent` int(11) NOT NULL DEFAULT 0,
  `last_warning_time` datetime,
  `auto_logout_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `offline_data` longtext NOT NULL DEFAULT ('{}'),
  `last_sync_time` datetime,
  `pending_sync_count` int(11) NOT NULL DEFAULT 0,
  `related_tabs` longtext NOT NULL DEFAULT ('[]'),
  `broadcast_messages_sent` int(11) NOT NULL DEFAULT 0,
  `broadcast_messages_received` int(11) NOT NULL DEFAULT 0,
  `cross_tab_activity_syncs` int(11) NOT NULL DEFAULT 0,
  `visited_urls` longtext NOT NULL DEFAULT ('{}'),
  `most_visited_url` varchar(2000),
  `most_visited_count` int(11) NOT NULL DEFAULT 0,
  `productivity_score` float,
  `engagement_score` float,
  `session_quality` varchar(20),
  `security_score` float,
  `security_anomalies` longtext NOT NULL DEFAULT ('[]'),
  `end_reason` varchar(50),
  PRIMARY KEY (`id`),
  KEY `fk_user` (`user_id`),
  KEY `trueAlign_usersession_parent_session_id` (`parent_session_id`),
  KEY `trueAlign_usersession_tab_id` (`tab_id`),
  KEY `trueAlign_usersession_created_at` (`created_at`),
  KEY `trueAlign_usersession_last_activity` (`last_activity`),
  CONSTRAINT `fk_user` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_clientprofile
CREATE TABLE `trueAlign_clientprofile` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `company_name` varchar(100) NOT NULL,
  `contact_info` longtext NOT NULL,
  `industry_type` varchar(100) NOT NULL,
  `company_size` varchar(50) NOT NULL,
  `registration_number` varchar(50),
  `business_location` varchar(255),
  `website_url` varchar(200),
  `year_established` int(11),
  `annual_revenue` decimal(15,2),
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`),
  CONSTRAINT `fk_clientprofile_user` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_conferenceroom
CREATE TABLE `trueAlign_conferenceroom` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `floor` varchar(20) NOT NULL,
  `capacity` int(10) unsigned NOT NULL,
  `amenities` longtext NOT NULL,
  `buffer_time_minutes` int(10) unsigned NOT NULL,
  `min_lead_time_minutes` int(10) unsigned NOT NULL,
  `max_booking_duration_hours` int(10) unsigned NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `description` text,
  `image` varchar(255),
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `office_location_id` bigint(20) NOT NULL,
  `created_by_id` int(11),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_globalupdate
CREATE TABLE `trueAlign_globalupdate` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `description` longtext NOT NULL,
  `title_hi` varchar(255),
  `description_hi` text,
  `title_mr` varchar(255),
  `description_mr` text,
  `primary_language` varchar(2) NOT NULL DEFAULT 'en',
  `status` varchar(20) NOT NULL,
  `scheduled_date` datetime(6),
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `managed_by_id` int(11),
  PRIMARY KEY (`id`),
  KEY `trueAlign_globalupdate_managed_by_id` (`managed_by_id`),
  CONSTRAINT `trueAlign_globalupdate_managed_by_id_4a1205f1_fk_auth_user_id` FOREIGN KEY (`managed_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_globalupdate_managed_by` FOREIGN KEY (`managed_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_leavepolicy
CREATE TABLE `trueAlign_leavepolicy` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `group_id` int(11) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `effective_from` date NOT NULL DEFAULT (curdate()),
  `effective_to` date,
  `created_by` int(11),
  PRIMARY KEY (`id`),
  KEY `trueAlign_leavepolicy_group_id` (`group_id`),
  KEY `fk_leavepolicy_created_by` (`created_by`),
  CONSTRAINT `trueAlign_leavepolicy_group_id_09217772_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_leavepolicy_created_by` FOREIGN KEY (`created_by`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_notification
CREATE TABLE `trueAlign_notification` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `message` text NOT NULL,
  `module` varchar(50) NOT NULL,
  `read` tinyint(1) NOT NULL DEFAULT 0,
  `timestamp` datetime(6) NOT NULL,
  `reference_id` varchar(50),
  `url` varchar(255),
  `recipient_id` int(11) NOT NULL,
  `title` varchar(200) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_notification_timestamp` (`timestamp`),
  KEY `trueAlign_notification_recipient_id` (`recipient_id`),
  CONSTRAINT `trueAlign_notification_recipient_id_58ebd476_fk_auth_user_id` FOREIGN KEY (`recipient_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_sessionactivity
CREATE TABLE `trueAlign_sessionactivity` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `session_id` bigint(20),
  `user_id` int(11),
  `created_at` datetime(6) NOT NULL,
  `activity_time` datetime(6) NOT NULL,
  `activity_type` varchar(20) NOT NULL,
  `activity_data` longtext NOT NULL DEFAULT ('{}'),
  `url` varchar(2000),
  `title` varchar(500),
  `location_latitude` double,
  `location_longitude` double,
  `location_accuracy` double,
  `productivity_score` double,
  `engagement_score` double,
  PRIMARY KEY (`id`),
  KEY `fk_sessionactivity_session` (`session_id`),
  KEY `fk_sessionactivity_user` (`user_id`),
  CONSTRAINT `fk_sessionactivity_session` FOREIGN KEY (`session_id`) REFERENCES `trueAlign_usersession` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_sessionactivity_user` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_shiftvalidationrule
CREATE TABLE `trueAlign_shiftvalidationrule` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `rule_type` varchar(30) NOT NULL,
  `value` decimal(10,2) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `group_id` int(11),
  PRIMARY KEY (`id`),
  KEY `fk_shiftvalidationrule_group` (`group_id`),
  CONSTRAINT `fk_shiftvalidationrule_group` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_userdetails
CREATE TABLE `trueAlign_userdetails` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `dob` date,
  `blood_group` varchar(10),
  `gender` varchar(20),
  `marital_status` varchar(20),
  `contact_number_primary` varchar(15),
  `personal_email` varchar(254),
  `company_email` varchar(254),
  `current_address_line1` varchar(255),
  `current_address_line2` varchar(255),
  `current_city` varchar(100),
  `current_state` varchar(100),
  `current_postal_code` varchar(10),
  `current_country` varchar(100),
  `permanent_address_line1` varchar(255),
  `permanent_address_line2` varchar(255),
  `permanent_city` varchar(100),
  `permanent_state` varchar(100),
  `permanent_postal_code` varchar(10),
  `permanent_country` varchar(100),
  `is_current_same_as_permanent` tinyint(1) NOT NULL,
  `emergency_contact_name` varchar(255),
  `emergency_contact_number` varchar(15),
  `emergency_contact_relationship` varchar(50),
  `secondary_emergency_contact_name` varchar(255),
  `secondary_emergency_contact_number` varchar(15),
  `secondary_emergency_contact_relationship` varchar(50),
  `employee_type` varchar(20),
  `role` varchar(50) NOT NULL DEFAULT 'employee',
  `hire_date` date,
  `start_date` date,
  `probation_end_date` date,
  `notice_period_days` int(10) unsigned NOT NULL,
  `job_description` longtext,
  `office_location_id` bigint(20),
  `work_location` varchar(100),
  `employment_status` varchar(50) NOT NULL DEFAULT 'probation',
  `exit_date` date,
  `exit_reason` longtext,
  `rehire_eligibility` tinyint(1),
  `salary_currency` varchar(3) NOT NULL DEFAULT 'INR',
  `base_salary` decimal(12,2),
  `salary_frequency` varchar(20) NOT NULL,
  `pan_number` varchar(10),
  `aadhar_number` varchar(12),
  `passport_number` varchar(20),
  `passport_expiry` date,
  `bank_name` varchar(100),
  `bank_account_number` varchar(30),
  `bank_ifsc` varchar(11),
  `previous_company` varchar(255),
  `previous_position` varchar(100),
  `previous_experience_years` int(10) unsigned,
  `onboarding_date` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `last_updated` datetime(6) NOT NULL,
  `last_status_change` datetime(6),
  `skills` longtext,
  `confidential_notes` longtext,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  `onboarded_by_id` int(11),
  `reporting_manager_id` int(11),
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `personal_email` (`personal_email`),
  UNIQUE KEY `company_email` (`company_email`),
  UNIQUE KEY `user_id` (`user_id`),
  KEY `trueAlign_userdetails_employee_type` (`employee_type`),
  KEY `trueAlign_userdetails_hire_date` (`hire_date`),
  KEY `trueAlign_userdetails_start_date` (`start_date`),
  KEY `trueAlign_userdetails_office_location_id` (`office_location_id`),
  KEY `trueAlign_userdetails_work_location` (`work_location`),
  KEY `trueAlign_userdetails_employment_status` (`employment_status`),
  KEY `fk_onboarded_by` (`onboarded_by_id`),
  KEY `fk_reporting_manager` (`reporting_manager_id`),
  CONSTRAINT `trueAlign_userdetails_user_id_c5e60317_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_office_location` FOREIGN KEY (`office_location_id`) REFERENCES `trueAlign_officelocation` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_onboarded_by` FOREIGN KEY (`onboarded_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_userdetails_onboarded_by_id_48fcb744_fk_auth_user_id` FOREIGN KEY (`onboarded_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_reporting_manager` FOREIGN KEY (`reporting_manager_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_userdetail_reporting_manager_id_6b80f879_fk_auth_user` FOREIGN KEY (`reporting_manager_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_attendance
CREATE TABLE `trueAlign_attendance` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `date` date NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'Not Marked',
  `version` int(11) NOT NULL DEFAULT 0,
  `is_being_processed` tinyint(1) NOT NULL DEFAULT 0,
  `last_processed_at` datetime(6),
  `processing_lock_expires` datetime(6),
  `leave_type` varchar(50),
  `clock_in_time` datetime(6),
  `clock_out_time` datetime(6),
  `total_hours` decimal(5,2),
  `expected_hours` decimal(5,2),
  `is_weekend` tinyint(1) NOT NULL DEFAULT 0,
  `is_holiday` tinyint(1) NOT NULL DEFAULT 0,
  `holiday_name` varchar(100),
  `location` varchar(50) NOT NULL,
  `ip_address` char(39),
  `late_minutes` int(11) NOT NULL,
  `early_departure_minutes` int(11) NOT NULL,
  `left_early` tinyint(1) NOT NULL DEFAULT 0,
  `last_modified` datetime(6) NOT NULL,
  `regularization_reason` longtext,
  `regularization_status` varchar(20),
  `total_sessions` int(11) NOT NULL DEFAULT 0,
  `idle_time` bigint(20) NOT NULL DEFAULT 0,
  `overtime_hours` decimal(5,2) NOT NULL DEFAULT 0.00,
  `is_overtime_approved` tinyint(1) NOT NULL DEFAULT 0,
  `modified_by_id` int(11),
  `user_id` int(11) NOT NULL,
  `shift_id` bigint(20),
  `is_employee_notified` tinyint(1) NOT NULL DEFAULT 0,
  `is_hr_notified` tinyint(1) NOT NULL DEFAULT 0,
  `is_manually_approved` tinyint(1) NOT NULL DEFAULT 0,
  `last_regularization_date` datetime(6),
  `original_clock_in_time` datetime(6),
  `original_clock_out_time` datetime(6),
  `original_status` varchar(20),
  `regularization_attempts` int(11) NOT NULL DEFAULT 0,
  `remarks` longtext,
  `requested_status` varchar(20),
  `is_half_day` tinyint(1) NOT NULL DEFAULT 0,
  `device_info` longtext,
  `breaks` longtext NOT NULL DEFAULT (json_array()),
  `first_session_id` char(36),
  `last_session_id` char(36),
  PRIMARY KEY (`id`),
  KEY `trueAlign_attendance_date` (`date`),
  KEY `trueAlign_attendance_version` (`version`),
  KEY `trueAlign_attendance_is_being_processed` (`is_being_processed`),
  KEY `trueAlign_attendance_clock_in_time` (`clock_in_time`),
  KEY `trueAlign_attendance_clock_out_time` (`clock_out_time`),
  KEY `trueAlign_attendance_is_weekend` (`is_weekend`),
  KEY `trueAlign_attendance_last_modified` (`last_modified`),
  KEY `trueAlign_attendance_regularization_status` (`regularization_status`),
  KEY `trueAlign_attendance_modified_by_id` (`modified_by_id`),
  KEY `trueAlign_attendance_user_id` (`user_id`),
  KEY `trueAlign_attendance_shift_id` (`shift_id`),
  KEY `trueAlign_attendance_first_session_id` (`first_session_id`),
  KEY `trueAlign_attendance_last_session_id` (`last_session_id`),
  CONSTRAINT `fk_first_session` FOREIGN KEY (`first_session_id`) REFERENCES `trueAlign_usersession` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_last_session` FOREIGN KEY (`last_session_id`) REFERENCES `trueAlign_usersession` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_attendance_modified_by_id_153336d2_fk_auth_user_id` FOREIGN KEY (`modified_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_attendance_shift_id_72809dfc_fk_trueAlign` FOREIGN KEY (`shift_id`) REFERENCES `trueAlign_shiftmaster` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_attendance_user_id_d8115814_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_shiftassignment
CREATE TABLE `trueAlign_shiftassignment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `effective_from` date NOT NULL,
  `effective_to` date,
  `is_current` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `user_id` int(11) NOT NULL,
  `shift_id` bigint(20) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'ACTIVE',
  `requires_approval` tinyint(1) NOT NULL DEFAULT 0,
  `approved_by` int(11),
  `approved_at` datetime,
  `assignment_hash` varchar(64),
  `notes` text,
  PRIMARY KEY (`id`),
  KEY `trueAlign_shiftassignment_is_current` (`is_current`),
  KEY `trueAlign_shiftassignment_user_id` (`user_id`),
  KEY `trueAlign_shiftassignment_shift_id` (`shift_id`),
  KEY `fk_shiftassignment_approved_by` (`approved_by`),
  CONSTRAINT `trueAlign_shiftassignment_user_id_24ba47d7_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_shiftassig_shift_id_97eae7b7_fk_trueAlign` FOREIGN KEY (`shift_id`) REFERENCES `trueAlign_shiftmaster` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_shiftassignment_approved_by` FOREIGN KEY (`approved_by`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_shiftconflict
CREATE TABLE `trueAlign_shiftconflict` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `conflict_type` varchar(20) NOT NULL,
  `severity` varchar(10) NOT NULL,
  `description` longtext NOT NULL,
  `is_resolved` tinyint(1) NOT NULL,
  `resolved_at` datetime(6),
  `resolution_notes` longtext NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `resolved_by` int(11),
  `assignment_id` bigint(20) NOT NULL,
  `conflicting_assignment_id` bigint(20),
  PRIMARY KEY (`id`),
  KEY `fk_shiftconflict_resolved_by` (`resolved_by`),
  KEY `fk_shiftconflict_assignment` (`assignment_id`),
  KEY `fk_shiftconflict_conflicting_assignment` (`conflicting_assignment_id`),
  CONSTRAINT `fk_shiftconflict_resolved_by` FOREIGN KEY (`resolved_by`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_shiftconflict_assignment` FOREIGN KEY (`assignment_id`) REFERENCES `trueAlign_shiftassignment` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_shiftconflict_conflicting_assignment` FOREIGN KEY (`conflicting_assignment_id`) REFERENCES `trueAlign_shiftassignment` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_appraisal
CREATE TABLE `trueAlign_appraisal` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `title` varchar(200) NOT NULL,
  `overview` longtext NOT NULL,
  `period_start` date NOT NULL,
  `period_end` date NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `submitted_at` datetime(6),
  `approved_at` datetime(6),
  `manager_id` int(11),
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisal_status` (`status`),
  KEY `trueAlign_appraisal_manager_id` (`manager_id`),
  KEY `trueAlign_appraisal_user_id` (`user_id`),
  CONSTRAINT `trueAlign_appraisal_manager_id_3ea4d24d_fk_auth_user_id` FOREIGN KEY (`manager_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_appraisal_user_id_1e4892d0_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_appraisalattachment
CREATE TABLE `trueAlign_appraisalattachment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `title` varchar(200) NOT NULL,
  `uploaded_at` datetime(6) NOT NULL,
  `appraisal_id` bigint(20) NOT NULL,
  `uploaded_by_id` int(11),
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisalattachment_appraisal_id` (`appraisal_id`),
  KEY `trueAlign_appraisalattachment_uploaded_by_id` (`uploaded_by_id`),
  CONSTRAINT `trueAlign_appraisala_appraisal_id_94991c7b_fk_trueAlign` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_appraisala_uploaded_by_id_d8366266_fk_auth_user` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_appraisalitem
CREATE TABLE `trueAlign_appraisalitem` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `category` varchar(20) NOT NULL,
  `title` varchar(200) NOT NULL,
  `description` longtext NOT NULL,
  `date` date,
  `employee_rating` smallint(5) unsigned,
  `manager_rating` smallint(5) unsigned,
  `manager_comments` longtext NOT NULL,
  `hr_rating` smallint(5) unsigned,
  `hr_comments` longtext NOT NULL,
  `appraisal_id` bigint(20) NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisalitem_appraisal_id` (`appraisal_id`),
  CONSTRAINT `trueAlign_appraisali_appraisal_id_bece5be9_fk_trueAlign` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_appraisalworkflow
CREATE TABLE `trueAlign_appraisalworkflow` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `from_status` varchar(20),
  `to_status` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `comments` longtext NOT NULL,
  `action_by_id` int(11),
  `appraisal_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisalworkflow_action_by_id` (`action_by_id`),
  KEY `trueAlign_appraisalworkflow_appraisal_id` (`appraisal_id`),
  CONSTRAINT `trueAlign_appraisalw_action_by_id_1c58029c_fk_auth_user` FOREIGN KEY (`action_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_appraisalw_appraisal_id_1184f4fa_fk_trueAlign` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_compoffrequest
CREATE TABLE `trueAlign_compoffrequest` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `worked_date` date NOT NULL,
  `reason` longtext NOT NULL,
  `hours_worked` decimal(4,1) NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approver_id` int(11),
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_compoffrequest_approver_id` (`approver_id`),
  KEY `trueAlign_compoffrequest_user_id` (`user_id`),
  CONSTRAINT `trueAlign_compoffrequest_approver_id_3638a657_fk_auth_user_id` FOREIGN KEY (`approver_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_compoffrequest_user_id_285921bf_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_leaveallocation
CREATE TABLE `trueAlign_leaveallocation` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `annual_days` decimal(5,1) NOT NULL,
  `carry_forward_limit` decimal(5,1) NOT NULL,
  `max_consecutive_days` int(11) NOT NULL,
  `advance_notice_days` int(11) NOT NULL,
  `policy_id` bigint(20) NOT NULL,
  `leave_type_id` bigint(20) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `trueAlign_leaveallocation_policy_id` (`policy_id`),
  KEY `trueAlign_leaveallocation_leave_type_id` (`leave_type_id`),
  CONSTRAINT `trueAlign_leavealloc_policy_id_9dbff9f8_fk_trueAlign` FOREIGN KEY (`policy_id`) REFERENCES `trueAlign_leavepolicy` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_leavealloc_leave_type_id_a50a7eb3_fk_trueAlign` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_leaverequest
CREATE TABLE `trueAlign_leaverequest` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `start_date` date NOT NULL,
  `end_date` date NOT NULL,
  `half_day` tinyint(1) NOT NULL,
  `leave_days` decimal(5,1) NOT NULL,
  `reason` longtext NOT NULL,
  `status` varchar(20) NOT NULL,
  `rejection_reason` longtext,
  `suggested_dates` longtext,
  `documentation` varchar(100),
  `is_retroactive` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approver_id` int(11),
  `user_id` int(11) NOT NULL,
  `leave_type_id` bigint(20) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `trueAlign_leaverequest_approver_id` (`approver_id`),
  KEY `trueAlign_leaverequest_user_id` (`user_id`),
  KEY `trueAlign_leaverequest_leave_type_id` (`leave_type_id`),
  CONSTRAINT `trueAlign_leaverequest_approver_id_0a10ae72_fk_auth_user_id` FOREIGN KEY (`approver_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_leaverequest_user_id_e0803633_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_leavereque_leave_type_id_71691a23_fk_trueAlign` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_leaverequesthistory
CREATE TABLE `trueAlign_leaverequesthistory` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `action` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `old_values` longtext,
  `new_values` longtext,
  `reason` longtext,
  `ip_address` char(39),
  `user_agent` longtext,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_roombooking
CREATE TABLE `trueAlign_roombooking` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `title` varchar(200) NOT NULL,
  `purpose` longtext NOT NULL,
  `attendees` longtext NOT NULL,
  `attendee_count` int(10) unsigned NOT NULL,
  `start_time` datetime(6) NOT NULL,
  `end_time` datetime(6) NOT NULL,
  `status` varchar(20) NOT NULL,
  `special_requirements` longtext NOT NULL,
  `cancelled_at` datetime(6),
  `cancellation_reason` text,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `room_id` bigint(20) unsigned NOT NULL,
  `booked_by_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_roombooking_status` (`status`),
  KEY `trueAlign_roombooking_room_id` (`room_id`),
  KEY `trueAlign_roombooking_booked_by_id` (`booked_by_id`),
  CONSTRAINT `trueAlign_roombooking_booked_by_id_fk_auth_user_id` FOREIGN KEY (`booked_by_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_support
CREATE TABLE `trueAlign_support` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ticket_id` varchar(100) NOT NULL,
  `issue_type` varchar(50) NOT NULL,
  `subject` varchar(200) NOT NULL,
  `description` longtext NOT NULL,
  `status` varchar(30) NOT NULL,
  `priority` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `resolved_at` datetime(6),
  `due_date` datetime(6),
  `location` varchar(100),
  `asset_id` varchar(50),
  `sla_breach` tinyint(1) NOT NULL,
  `resolution_summary` longtext NOT NULL,
  `resolution_time` bigint(20),
  `satisfaction_rating` int(11),
  `feedback` longtext NOT NULL,
  `assigned_to_user_id` int(11),
  `parent_ticket_id` bigint(20),
  `user_id` int(11) NOT NULL,
  `assigned_group` varchar(50),
  `escalation_level` smallint(5) unsigned NOT NULL,
  `response_time` bigint(20),
  `sla_status` varchar(20),
  `sla_target_date` datetime,
  `time_to_close` bigint(20),
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `reopen_count` smallint(5) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ticket_id` (`ticket_id`),
  KEY `trueAlign_support_status` (`status`),
  KEY `trueAlign_support_priority` (`priority`),
  KEY `trueAlign_support_created_at` (`created_at`),
  KEY `trueAlign_support_resolved_at` (`resolved_at`),
  KEY `trueAlign_support_due_date` (`due_date`),
  KEY `trueAlign_support_assigned_to_user_id` (`assigned_to_user_id`),
  KEY `trueAlign_support_parent_ticket_id` (`parent_ticket_id`),
  KEY `trueAlign_support_user_id` (`user_id`),
  CONSTRAINT `trueAlign_support_assigned_to_user_id_5c14c839_fk_auth_user_id` FOREIGN KEY (`assigned_to_user_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_support_assigned_user` FOREIGN KEY (`assigned_to_user_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_support_parent_ticket_id_81413f37_fk_trueAlign` FOREIGN KEY (`parent_ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_support_parent_ticket` FOREIGN KEY (`parent_ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_support_user_id_be914a5a_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_support_cc_users
CREATE TABLE `trueAlign_support_cc_users` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `support_id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_support_cc_users_support` (`support_id`),
  KEY `fk_support_cc_users_user` (`user_id`),
  CONSTRAINT `fk_support_cc_users_support` FOREIGN KEY (`support_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_support_cc_users_user` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_statuslog
CREATE TABLE `trueAlign_statuslog` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `old_status` varchar(30) NOT NULL,
  `new_status` varchar(30) NOT NULL,
  `changed_at` datetime(6) NOT NULL,
  `changed_by_id` int(11),
  `ticket_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_statuslog_changed_by_id` (`changed_by_id`),
  KEY `trueAlign_statuslog_ticket_id` (`ticket_id`),
  CONSTRAINT `trueAlign_statuslog_changed_by_id_5eec04f0_fk_auth_user_id` FOREIGN KEY (`changed_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `fk_statuslog_user` FOREIGN KEY (`changed_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_statuslog_ticket_id_1f656ca2_fk_trueAlign_support_id` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_statuslog_ticket` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_ticketactivity
CREATE TABLE `trueAlign_ticketactivity` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `action` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `details` longtext NOT NULL,
  `ticket_id` bigint(20) NOT NULL,
  `user_id` int(11),
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketactivity_ticket_id` (`ticket_id`),
  KEY `trueAlign_ticketactivity_user_id` (`user_id`),
  CONSTRAINT `trueAlign_ticketacti_ticket_id_812010d6_fk_trueAlign` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ticketactivity_ticket` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_ticketactivity_user_id_39616151_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_ticketattachment
CREATE TABLE `trueAlign_ticketattachment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `uploaded_at` datetime(6) NOT NULL,
  `description` varchar(255) NOT NULL,
  `ticket_id` bigint(20) NOT NULL,
  `uploaded_by_id` int(11) NOT NULL,
  `file_size` int(10) unsigned NOT NULL,
  `file_type` varchar(100),
  `formatted_filename` varchar(255) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `original_filename` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketattachment_ticket_id` (`ticket_id`),
  KEY `trueAlign_ticketattachment_uploaded_by_id` (`uploaded_by_id`),
  CONSTRAINT `trueAlign_ticketatta_ticket_id_84e3681b_fk_trueAlign` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ticketattachment_ticket` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_ticketatta_uploaded_by_id_8bca47bb_fk_auth_user` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ticketattachment_user` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_ticketcomment
CREATE TABLE `trueAlign_ticketcomment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `content` longtext NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `is_internal` tinyint(1) NOT NULL DEFAULT 0,
  `ticket_id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketcomment_ticket_id` (`ticket_id`),
  KEY `trueAlign_ticketcomment_user_id` (`user_id`),
  CONSTRAINT `fk_ticketcomment_ticket` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_ticketcomm_ticket_id_dc0044c9_fk_trueAlign` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ticketcomment_user` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_ticketcomment_user_id_6c79e01c_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: truealign_comment_attachment
CREATE TABLE `truealign_comment_attachment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `file` varchar(255) NOT NULL,
  `original_filename` varchar(255) NOT NULL,
  `formatted_filename` varchar(255) NOT NULL,
  `file_size` int(10) unsigned NOT NULL,
  `content_type` varchar(100),
  `uploaded_at` datetime(6) NOT NULL,
  `description` text,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `comment_id` bigint(20) NOT NULL,
  `ticket_activity_id` bigint(20) NOT NULL,
  `uploaded_by_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `truealign_comment_attachment_comment_id` (`comment_id`),
  KEY `truealign_comment_attachment_ticket_activity_id` (`ticket_activity_id`),
  KEY `truealign_comment_attachment_uploaded_by_id` (`uploaded_by_id`),
  CONSTRAINT `fk_comment_attachment_comment` FOREIGN KEY (`comment_id`) REFERENCES `trueAlign_ticketcomment` (`id`) ON DELETE CASCADE,
  CONSTRAINT `truealign_comment_at_comment_id_ea271478_fk_trueAlign` FOREIGN KEY (`comment_id`) REFERENCES `trueAlign_ticketcomment` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_comment_attachment_activity` FOREIGN KEY (`ticket_activity_id`) REFERENCES `trueAlign_ticketactivity` (`id`) ON DELETE CASCADE,
  CONSTRAINT `truealign_comment_at_ticket_activity_id_3c828dc4_fk_trueAlign` FOREIGN KEY (`ticket_activity_id`) REFERENCES `trueAlign_ticketactivity` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_comment_attachment_user` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE,
  CONSTRAINT `truealign_comment_at_uploaded_by_id_5f77739f_fk_auth_user` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_useractionlog
CREATE TABLE `trueAlign_useractionlog` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `action_type` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `details` longtext,
  `action_by_id` int(11),
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_useractionlog_action_by_id` (`action_by_id`),
  KEY `trueAlign_useractionlog_user_id` (`user_id`),
  CONSTRAINT `trueAlign_useractionlog_action_by_id_9d5bb9bc_fk_auth_user_id` FOREIGN KEY (`action_by_id`) REFERENCES `auth_user` (`id`) ON DELETE SET NULL,
  CONSTRAINT `trueAlign_useractionlog_user_id_2e26b9dd_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: trueAlign_userleavebalance
CREATE TABLE `trueAlign_userleavebalance` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `year` int(11) NOT NULL,
  `allocated` decimal(5,1) NOT NULL,
  `used` decimal(5,1) NOT NULL,
  `carried_forward` decimal(5,1) NOT NULL,
  `additional` decimal(5,1) NOT NULL,
  `leave_type_id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `trueAlign_userleavebalance_leave_type_id` (`leave_type_id`),
  KEY `trueAlign_userleavebalance_user_id` (`user_id`),
  CONSTRAINT `trueAlign_userleaveb_leave_type_id_72addf12_fk_trueAlign` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`) ON DELETE CASCADE,
  CONSTRAINT `trueAlign_userleavebalance_user_id_c558436a_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- END OF MIGRATION SCRIPT
-- =============================================
