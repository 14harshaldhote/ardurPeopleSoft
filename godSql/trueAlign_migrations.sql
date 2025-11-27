-- TrueAlign Migration Script
-- Generated from godSql schema data
-- Date: 2025-11-27

SET FOREIGN_KEY_CHECKS = 0;

-- =============================================
-- 1. trueAlign_leavetype
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_leavetype` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` longtext DEFAULT NULL,
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

-- =============================================
-- 2. trueAlign_officelocation
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_officelocation` (
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

-- =============================================
-- 3. trueAlign_subscription
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_subscription` (
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
-- 4. trueAlign_systemerror
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_systemerror` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `error_message` longtext NOT NULL,
  `error_time` datetime(6) NOT NULL,
  `resolved` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 5. trueAlign_systemusage
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_systemusage` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `peak_time_start` datetime(6) NOT NULL,
  `peak_time_end` datetime(6) NOT NULL,
  `active_users_count` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 6. trueAlign_holiday
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_holiday` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `date` date NOT NULL,
  `recurring_yearly` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 7. trueAlign_layoutpreference
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_layoutpreference` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `layout` longtext NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 8. trueAlign_leaverequesthistory
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_leaverequesthistory` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `action` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `old_values` longtext DEFAULT NULL,
  `new_values` longtext DEFAULT NULL,
  `reason` longtext DEFAULT NULL,
  `ip_address` char(39) DEFAULT NULL,
  `user_agent` longtext DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 9. trueAlign_shiftmaster
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_shiftmaster` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `shift_type` varchar(20) NOT NULL DEFAULT 'Day Shift',
  `start_time` time(6) NOT NULL,
  `end_time` time(6) NOT NULL,
  `shift_duration` decimal(5,2) NOT NULL DEFAULT 8.00,
  `break_duration` bigint(20) NOT NULL DEFAULT 1800000000,
  `grace_period` bigint(20) NOT NULL DEFAULT 900000000,
  `work_days` varchar(20) NOT NULL DEFAULT 'Weekdays',
  `custom_work_days` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `created_by_id` int(11) DEFAULT NULL,
  `color_code` char(7) NOT NULL DEFAULT '#3B82F6',
  `description` text DEFAULT NULL,
  `requires_approval` tinyint(1) NOT NULL DEFAULT 0,
  `min_rest_hours` decimal(4,2) NOT NULL DEFAULT 8.00,
  `max_consecutive_days` int(11) NOT NULL DEFAULT 6,
  `overtime_threshold` decimal(4,2) NOT NULL DEFAULT 8.00,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  KEY `trueAlign_shiftmaster_created_by_id_fk` (`created_by_id`),
  CONSTRAINT `trueAlign_shiftmaster_created_by_id_fk` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 10. trueAlign_leavepolicy
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_leavepolicy` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `group_id` int(11) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `effective_from` date NOT NULL DEFAULT (curdate()),
  `effective_to` date DEFAULT NULL,
  `created_by` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_leavepolicy_group_id_fk` (`group_id`),
  KEY `trueAlign_leavepolicy_created_by_fk` (`created_by`),
  CONSTRAINT `trueAlign_leavepolicy_group_id_fk` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `trueAlign_leavepolicy_created_by_fk` FOREIGN KEY (`created_by`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 11. trueAlign_clientprofile
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_clientprofile` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `company_name` varchar(100) NOT NULL,
  `contact_info` longtext NOT NULL,
  `industry_type` varchar(100) NOT NULL,
  `company_size` varchar(50) NOT NULL,
  `registration_number` varchar(50) DEFAULT NULL,
  `business_location` varchar(255) DEFAULT NULL,
  `website_url` varchar(200) DEFAULT NULL,
  `year_established` int(11) DEFAULT NULL,
  `annual_revenue` decimal(15,2) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`),
  CONSTRAINT `trueAlign_clientprofile_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 12. trueAlign_usersession
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_usersession` (
  `id` char(36) NOT NULL,
  `user_id` int(11) NOT NULL,
  `parent_session_id` varchar(100) DEFAULT NULL,
  `tab_id` varchar(100) DEFAULT NULL,
  `is_primary_tab` tinyint(1) NOT NULL DEFAULT 0,
  `session_fingerprint` varchar(255) DEFAULT NULL,
  `session_key` varchar(40) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `login_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `logout_time` datetime DEFAULT NULL,
  `last_activity` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ended_at` datetime DEFAULT NULL,
  `session_end_time` datetime DEFAULT NULL,
  `start_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tab_opened_time` datetime DEFAULT NULL,
  `tab_last_focus` datetime DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `is_idle` tinyint(1) NOT NULL DEFAULT 0,
  `idle_start_time` datetime DEFAULT NULL,
  `total_idle_time` bigint(20) NOT NULL DEFAULT 0,
  `working_time` bigint(20) NOT NULL DEFAULT 0,
  `focus_time` bigint(20) NOT NULL DEFAULT 0,
  `session_duration` float DEFAULT NULL,
  `idle_time` time DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `browser_fingerprint` text DEFAULT NULL,
  `browser` varchar(100) DEFAULT NULL,
  `os` varchar(100) DEFAULT NULL,
  `csrf_token` char(64) DEFAULT NULL,
  `csrf_token_created` datetime DEFAULT NULL,
  `device_type` varchar(20) DEFAULT NULL,
  `screen_resolution` varchar(20) DEFAULT NULL,
  `timezone_offset` int(11) DEFAULT NULL,
  `language` varchar(10) DEFAULT NULL,
  `battery_level` float DEFAULT NULL,
  `connection_type` varchar(20) DEFAULT NULL,
  `location_history` longtext DEFAULT NULL,
  `location_country` varchar(100) DEFAULT NULL,
  `location_region` varchar(100) DEFAULT NULL,
  `location_city` varchar(100) DEFAULT NULL,
  `location_latitude` float DEFAULT NULL,
  `location_longitude` float DEFAULT NULL,
  `location_accuracy` float DEFAULT NULL,
  `location_type` varchar(20) DEFAULT NULL,
  `tab_title` longtext NOT NULL DEFAULT '[]',
  `tab_url` longtext NOT NULL DEFAULT '[]',
  `url` longtext NOT NULL DEFAULT '[]',
  `title` longtext NOT NULL DEFAULT '[]',
  `referrer` longtext NOT NULL DEFAULT '[]',
  `page_views` longtext NOT NULL DEFAULT '[]',
  `clicks` longtext NOT NULL DEFAULT '[]',
  `scrolls` longtext NOT NULL DEFAULT '[]',
  `keyboard_events` longtext NOT NULL DEFAULT '[]',
  `mouse_movements` int(11) NOT NULL DEFAULT 0,
  `tab_visibility_log` longtext NOT NULL DEFAULT '[]',
  `tab_switches` int(11) NOT NULL DEFAULT 0,
  `background_time` bigint(20) NOT NULL DEFAULT 0,
  `idle_state_changes` longtext NOT NULL DEFAULT '[]',
  `performance_metrics` longtext NOT NULL DEFAULT '{}',
  `network_events` longtext NOT NULL DEFAULT '[]',
  `error_events` longtext NOT NULL DEFAULT '[]',
  `custom_timeout` int(10) unsigned DEFAULT NULL,
  `inactivity_warnings_sent` int(11) NOT NULL DEFAULT 0,
  `last_warning_time` datetime DEFAULT NULL,
  `auto_logout_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `offline_data` longtext NOT NULL DEFAULT '{}',
  `last_sync_time` datetime DEFAULT NULL,
  `pending_sync_count` int(11) NOT NULL DEFAULT 0,
  `related_tabs` longtext NOT NULL DEFAULT '[]',
  `broadcast_messages_sent` int(11) NOT NULL DEFAULT 0,
  `broadcast_messages_received` int(11) NOT NULL DEFAULT 0,
  `cross_tab_activity_syncs` int(11) NOT NULL DEFAULT 0,
  `visited_urls` longtext NOT NULL DEFAULT '{}',
  `most_visited_url` varchar(2000) DEFAULT NULL,
  `most_visited_count` int(11) NOT NULL DEFAULT 0,
  `productivity_score` float DEFAULT NULL,
  `engagement_score` float DEFAULT NULL,
  `session_quality` varchar(20) DEFAULT NULL,
  `security_score` float DEFAULT NULL,
  `security_anomalies` longtext NOT NULL DEFAULT '[]',
  `end_reason` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_usersession_user_id_fk` (`user_id`),
  KEY `trueAlign_usersession_parent_session_id_fk` (`parent_session_id`),
  KEY `trueAlign_usersession_tab_id_index` (`tab_id`),
  KEY `trueAlign_usersession_created_at_index` (`created_at`),
  KEY `trueAlign_usersession_last_activity_index` (`last_activity`),
  CONSTRAINT `trueAlign_usersession_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 13. trueAlign_conferenceroom
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_conferenceroom` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `floor` varchar(20) NOT NULL,
  `capacity` int(10) unsigned NOT NULL,
  `amenities` longtext NOT NULL,
  `buffer_time_minutes` int(10) unsigned NOT NULL,
  `min_lead_time_minutes` int(10) unsigned NOT NULL,
  `max_booking_duration_hours` int(10) unsigned NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `description` text DEFAULT NULL,
  `image` varchar(255) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `office_location_id` bigint(20) NOT NULL,
  `created_by_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_conferenceroom_office_location_id_fk` (`office_location_id`),
  KEY `trueAlign_conferenceroom_created_by_id_fk` (`created_by_id`),
  CONSTRAINT `trueAlign_conferenceroom_office_location_id_fk` FOREIGN KEY (`office_location_id`) REFERENCES `trueAlign_officelocation` (`id`),
  CONSTRAINT `trueAlign_conferenceroom_created_by_id_fk` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 14. trueAlign_userdetails
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_userdetails` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `dob` date DEFAULT NULL,
  `blood_group` varchar(10) DEFAULT NULL,
  `gender` varchar(20) DEFAULT NULL,
  `marital_status` varchar(20) DEFAULT NULL,
  `contact_number_primary` varchar(15) DEFAULT NULL,
  `personal_email` varchar(254) DEFAULT NULL,
  `company_email` varchar(254) DEFAULT NULL,
  `current_address_line1` varchar(255) DEFAULT NULL,
  `current_address_line2` varchar(255) DEFAULT NULL,
  `current_city` varchar(100) DEFAULT NULL,
  `current_state` varchar(100) DEFAULT NULL,
  `current_postal_code` varchar(10) DEFAULT NULL,
  `current_country` varchar(100) DEFAULT NULL,
  `permanent_address_line1` varchar(255) DEFAULT NULL,
  `permanent_address_line2` varchar(255) DEFAULT NULL,
  `permanent_city` varchar(100) DEFAULT NULL,
  `permanent_state` varchar(100) DEFAULT NULL,
  `permanent_postal_code` varchar(10) DEFAULT NULL,
  `permanent_country` varchar(100) DEFAULT NULL,
  `is_current_same_as_permanent` tinyint(1) NOT NULL,
  `emergency_contact_name` varchar(255) DEFAULT NULL,
  `emergency_contact_number` varchar(15) DEFAULT NULL,
  `emergency_contact_relationship` varchar(50) DEFAULT NULL,
  `secondary_emergency_contact_name` varchar(255) DEFAULT NULL,
  `secondary_emergency_contact_number` varchar(15) DEFAULT NULL,
  `secondary_emergency_contact_relationship` varchar(50) DEFAULT NULL,
  `employee_type` varchar(20) DEFAULT NULL,
  `role` varchar(50) NOT NULL DEFAULT 'employee',
  `hire_date` date DEFAULT NULL,
  `start_date` date DEFAULT NULL,
  `probation_end_date` date DEFAULT NULL,
  `notice_period_days` int(10) unsigned NOT NULL,
  `job_description` longtext DEFAULT NULL,
  `office_location_id` bigint(20) DEFAULT NULL,
  `work_location` varchar(100) DEFAULT NULL,
  `employment_status` varchar(50) NOT NULL DEFAULT 'probation',
  `exit_date` date DEFAULT NULL,
  `exit_reason` longtext DEFAULT NULL,
  `rehire_eligibility` tinyint(1) DEFAULT NULL,
  `salary_currency` varchar(3) NOT NULL DEFAULT 'INR',
  `base_salary` decimal(12,2) DEFAULT NULL,
  `salary_frequency` varchar(20) NOT NULL,
  `pan_number` varchar(10) DEFAULT NULL,
  `aadhar_number` varchar(12) DEFAULT NULL,
  `passport_number` varchar(20) DEFAULT NULL,
  `passport_expiry` date DEFAULT NULL,
  `bank_name` varchar(100) DEFAULT NULL,
  `bank_account_number` varchar(30) DEFAULT NULL,
  `bank_ifsc` varchar(11) DEFAULT NULL,
  `previous_company` varchar(255) DEFAULT NULL,
  `previous_position` varchar(100) DEFAULT NULL,
  `previous_experience_years` int(10) unsigned DEFAULT NULL,
  `onboarding_date` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `last_updated` datetime(6) NOT NULL,
  `last_status_change` datetime(6) DEFAULT NULL,
  `skills` longtext DEFAULT NULL,
  `confidential_notes` longtext DEFAULT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  `onboarded_by_id` int(11) DEFAULT NULL,
  `reporting_manager_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`),
  UNIQUE KEY `personal_email` (`personal_email`),
  UNIQUE KEY `company_email` (`company_email`),
  KEY `trueAlign_userdetails_office_location_id_fk` (`office_location_id`),
  KEY `trueAlign_userdetails_onboarded_by_id_fk` (`onboarded_by_id`),
  KEY `trueAlign_userdetails_reporting_manager_id_fk` (`reporting_manager_id`),
  KEY `trueAlign_userdetails_employee_type_index` (`employee_type`),
  KEY `trueAlign_userdetails_hire_date_index` (`hire_date`),
  KEY `trueAlign_userdetails_start_date_index` (`start_date`),
  KEY `trueAlign_userdetails_work_location_index` (`work_location`),
  KEY `trueAlign_userdetails_employment_status_index` (`employment_status`),
  CONSTRAINT `trueAlign_userdetails_office_location_id_fk` FOREIGN KEY (`office_location_id`) REFERENCES `trueAlign_officelocation` (`id`),
  CONSTRAINT `trueAlign_userdetails_onboarded_by_id_fk` FOREIGN KEY (`onboarded_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_userdetails_reporting_manager_id_fk` FOREIGN KEY (`reporting_manager_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_userdetails_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 15. trueAlign_leaveallocation
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_leaveallocation` (
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
  KEY `trueAlign_leaveallocation_policy_id_fk` (`policy_id`),
  KEY `trueAlign_leaveallocation_leave_type_id_fk` (`leave_type_id`),
  CONSTRAINT `trueAlign_leaveallocation_policy_id_fk` FOREIGN KEY (`policy_id`) REFERENCES `trueAlign_leavepolicy` (`id`),
  CONSTRAINT `trueAlign_leaveallocation_leave_type_id_fk` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 16. trueAlign_leaverequest
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_leaverequest` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `start_date` date NOT NULL,
  `end_date` date NOT NULL,
  `half_day` tinyint(1) NOT NULL,
  `leave_days` decimal(5,1) NOT NULL,
  `reason` longtext NOT NULL,
  `status` varchar(20) NOT NULL,
  `rejection_reason` longtext DEFAULT NULL,
  `suggested_dates` longtext DEFAULT NULL,
  `documentation` varchar(100) DEFAULT NULL,
  `is_retroactive` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approver_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `leave_type_id` bigint(20) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `trueAlign_leaverequest_approver_id_fk` (`approver_id`),
  KEY `trueAlign_leaverequest_user_id_fk` (`user_id`),
  KEY `trueAlign_leaverequest_leave_type_id_fk` (`leave_type_id`),
  CONSTRAINT `trueAlign_leaverequest_approver_id_fk` FOREIGN KEY (`approver_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_leaverequest_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_leaverequest_leave_type_id_fk` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 17. trueAlign_userleavebalance
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_userleavebalance` (
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
  KEY `trueAlign_userleavebalance_leave_type_id_fk` (`leave_type_id`),
  KEY `trueAlign_userleavebalance_user_id_fk` (`user_id`),
  CONSTRAINT `trueAlign_userleavebalance_leave_type_id_fk` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`),
  CONSTRAINT `trueAlign_userleavebalance_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 18. trueAlign_shiftassignment
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_shiftassignment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `effective_from` date NOT NULL,
  `effective_to` date DEFAULT NULL,
  `is_current` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `user_id` int(11) NOT NULL,
  `shift_id` bigint(20) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'ACTIVE',
  `requires_approval` tinyint(1) NOT NULL DEFAULT 0,
  `approved_by` int(11) DEFAULT NULL,
  `approved_at` datetime DEFAULT NULL,
  `assignment_hash` varchar(64) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_shiftassignment_user_id_fk` (`user_id`),
  KEY `trueAlign_shiftassignment_shift_id_fk` (`shift_id`),
  KEY `trueAlign_shiftassignment_approved_by_fk` (`approved_by`),
  KEY `trueAlign_shiftassignment_is_current_index` (`is_current`),
  CONSTRAINT `trueAlign_shiftassignment_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_shiftassignment_shift_id_fk` FOREIGN KEY (`shift_id`) REFERENCES `trueAlign_shiftmaster` (`id`),
  CONSTRAINT `trueAlign_shiftassignment_approved_by_fk` FOREIGN KEY (`approved_by`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 19. trueAlign_shiftvalidationrule
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_shiftvalidationrule` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `rule_type` varchar(30) NOT NULL,
  `value` decimal(10,2) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `group_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_shiftvalidationrule_group_id_fk` (`group_id`),
  CONSTRAINT `trueAlign_shiftvalidationrule_group_id_fk` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 20. trueAlign_shiftconflict
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_shiftconflict` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `conflict_type` varchar(20) NOT NULL,
  `severity` varchar(10) NOT NULL,
  `description` longtext NOT NULL,
  `is_resolved` tinyint(1) NOT NULL,
  `resolved_at` datetime(6) DEFAULT NULL,
  `resolution_notes` longtext NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `resolved_by` int(11) DEFAULT NULL,
  `assignment_id` bigint(20) NOT NULL,
  `conflicting_assignment_id` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_shiftconflict_resolved_by_fk` (`resolved_by`),
  KEY `trueAlign_shiftconflict_assignment_id_fk` (`assignment_id`),
  KEY `trueAlign_shiftconflict_conflicting_assignment_id_fk` (`conflicting_assignment_id`),
  CONSTRAINT `trueAlign_shiftconflict_resolved_by_fk` FOREIGN KEY (`resolved_by`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_shiftconflict_assignment_id_fk` FOREIGN KEY (`assignment_id`) REFERENCES `trueAlign_shiftassignment` (`id`),
  CONSTRAINT `trueAlign_shiftconflict_conflicting_assignment_id_fk` FOREIGN KEY (`conflicting_assignment_id`) REFERENCES `trueAlign_shiftassignment` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 21. trueAlign_attendance
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_attendance` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) NOT NULL,
  `date` date NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'Not Marked',
  `version` int(11) NOT NULL DEFAULT 0,
  `is_being_processed` tinyint(1) NOT NULL DEFAULT 0,
  `last_processed_at` datetime(6) DEFAULT NULL,
  `processing_lock_expires` datetime(6) DEFAULT NULL,
  `leave_type` varchar(50) DEFAULT NULL,
  `clock_in_time` datetime(6) DEFAULT NULL,
  `clock_out_time` datetime(6) DEFAULT NULL,
  `total_hours` decimal(5,2) DEFAULT NULL,
  `expected_hours` decimal(5,2) DEFAULT NULL,
  `is_weekend` tinyint(1) NOT NULL DEFAULT 0,
  `is_holiday` tinyint(1) NOT NULL DEFAULT 0,
  `holiday_name` varchar(100) DEFAULT NULL,
  `location` varchar(50) NOT NULL,
  `ip_address` char(39) DEFAULT NULL,
  `late_minutes` int(11) NOT NULL,
  `early_departure_minutes` int(11) NOT NULL,
  `left_early` tinyint(1) NOT NULL DEFAULT 0,
  `last_modified` datetime(6) NOT NULL,
  `regularization_reason` longtext DEFAULT NULL,
  `regularization_status` varchar(20) DEFAULT NULL,
  `total_sessions` int(11) NOT NULL DEFAULT 0,
  `idle_time` bigint(20) NOT NULL DEFAULT 0,
  `overtime_hours` decimal(5,2) NOT NULL DEFAULT 0.00,
  `is_overtime_approved` tinyint(1) NOT NULL DEFAULT 0,
  `modified_by_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `shift_id` bigint(20) DEFAULT NULL,
  `is_employee_notified` tinyint(1) NOT NULL DEFAULT 0,
  `is_hr_notified` tinyint(1) NOT NULL DEFAULT 0,
  `is_manually_approved` tinyint(1) NOT NULL DEFAULT 0,
  `last_regularization_date` datetime(6) DEFAULT NULL,
  `original_clock_in_time` datetime(6) DEFAULT NULL,
  `original_clock_out_time` datetime(6) DEFAULT NULL,
  `original_status` varchar(20) DEFAULT NULL,
  `regularization_attempts` int(11) NOT NULL DEFAULT 0,
  `remarks` longtext DEFAULT NULL,
  `requested_status` varchar(20) DEFAULT NULL,
  `is_half_day` tinyint(1) NOT NULL DEFAULT 0,
  `device_info` longtext DEFAULT NULL,
  `breaks` longtext NOT NULL,
  `first_session_id` char(36) DEFAULT NULL,
  `last_session_id` char(36) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_attendance_user_id_fk` (`user_id`),
  KEY `trueAlign_attendance_modified_by_id_fk` (`modified_by_id`),
  KEY `trueAlign_attendance_shift_id_fk` (`shift_id`),
  KEY `trueAlign_attendance_first_session_id_fk` (`first_session_id`),
  KEY `trueAlign_attendance_last_session_id_fk` (`last_session_id`),
  KEY `trueAlign_attendance_date_index` (`date`),
  KEY `trueAlign_attendance_clock_in_time_index` (`clock_in_time`),
  KEY `trueAlign_attendance_clock_out_time_index` (`clock_out_time`),
  CONSTRAINT `trueAlign_attendance_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_attendance_modified_by_id_fk` FOREIGN KEY (`modified_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_attendance_shift_id_fk` FOREIGN KEY (`shift_id`) REFERENCES `trueAlign_shiftmaster` (`id`),
  CONSTRAINT `trueAlign_attendance_first_session_id_fk` FOREIGN KEY (`first_session_id`) REFERENCES `trueAlign_usersession` (`id`),
  CONSTRAINT `trueAlign_attendance_last_session_id_fk` FOREIGN KEY (`last_session_id`) REFERENCES `trueAlign_usersession` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 22. trueAlign_sessionactivity
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_sessionactivity` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `session_id` bigint(20) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `activity_time` datetime(6) NOT NULL,
  `activity_type` varchar(20) NOT NULL,
  `activity_data` longtext NOT NULL DEFAULT '{}',
  `url` varchar(2000) DEFAULT NULL,
  `title` varchar(500) DEFAULT NULL,
  `location_latitude` double DEFAULT NULL,
  `location_longitude` double DEFAULT NULL,
  `location_accuracy` double DEFAULT NULL,
  `productivity_score` double DEFAULT NULL,
  `engagement_score` double DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_sessionactivity_session_id_fk` (`session_id`),
  KEY `trueAlign_sessionactivity_user_id_fk` (`user_id`),
  CONSTRAINT `trueAlign_sessionactivity_session_id_fk` FOREIGN KEY (`session_id`) REFERENCES `trueAlign_usersession` (`id`),
  CONSTRAINT `trueAlign_sessionactivity_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 23. trueAlign_support
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_support` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ticket_id` varchar(100) NOT NULL,
  `issue_type` varchar(50) NOT NULL,
  `subject` varchar(200) NOT NULL,
  `description` longtext NOT NULL,
  `status` varchar(30) NOT NULL,
  `priority` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `resolved_at` datetime(6) DEFAULT NULL,
  `due_date` datetime(6) DEFAULT NULL,
  `location` varchar(100) DEFAULT NULL,
  `asset_id` varchar(50) DEFAULT NULL,
  `sla_breach` tinyint(1) NOT NULL,
  `resolution_summary` longtext NOT NULL,
  `resolution_time` bigint(20) DEFAULT NULL,
  `satisfaction_rating` int(11) DEFAULT NULL,
  `feedback` longtext NOT NULL,
  `assigned_to_user_id` int(11) DEFAULT NULL,
  `parent_ticket_id` bigint(20) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `assigned_group` varchar(50) DEFAULT NULL,
  `escalation_level` smallint(5) unsigned NOT NULL,
  `response_time` bigint(20) DEFAULT NULL,
  `sla_status` varchar(20) DEFAULT NULL,
  `sla_target_date` datetime DEFAULT NULL,
  `time_to_close` bigint(20) DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `reopen_count` smallint(5) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ticket_id` (`ticket_id`),
  KEY `trueAlign_support_assigned_to_user_id_fk` (`assigned_to_user_id`),
  KEY `trueAlign_support_parent_ticket_id_fk` (`parent_ticket_id`),
  KEY `trueAlign_support_user_id_fk` (`user_id`),
  KEY `trueAlign_support_status_index` (`status`),
  KEY `trueAlign_support_priority_index` (`priority`),
  KEY `trueAlign_support_created_at_index` (`created_at`),
  KEY `trueAlign_support_resolved_at_index` (`resolved_at`),
  KEY `trueAlign_support_due_date_index` (`due_date`),
  CONSTRAINT `trueAlign_support_assigned_to_user_id_fk` FOREIGN KEY (`assigned_to_user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_support_parent_ticket_id_fk` FOREIGN KEY (`parent_ticket_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_support_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 24. trueAlign_support_cc_users
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_support_cc_users` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `support_id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_support_cc_users_support_id_fk` (`support_id`),
  KEY `trueAlign_support_cc_users_user_id_fk` (`user_id`),
  CONSTRAINT `trueAlign_support_cc_users_support_id_fk` FOREIGN KEY (`support_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_support_cc_users_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 25. trueAlign_ticketactivity
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_ticketactivity` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `action` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `details` longtext NOT NULL,
  `ticket_id` bigint(20) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketactivity_ticket_id_fk` (`ticket_id`),
  KEY `trueAlign_ticketactivity_user_id_fk` (`user_id`),
  CONSTRAINT `trueAlign_ticketactivity_ticket_id_fk` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_ticketactivity_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 26. trueAlign_ticketattachment
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_ticketattachment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `uploaded_at` datetime(6) NOT NULL,
  `description` varchar(255) NOT NULL,
  `ticket_id` bigint(20) NOT NULL,
  `uploaded_by_id` int(11) NOT NULL,
  `file_size` int(10) unsigned NOT NULL,
  `file_type` varchar(100) DEFAULT NULL,
  `formatted_filename` varchar(255) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
  `original_filename` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketattachment_ticket_id_fk` (`ticket_id`),
  KEY `trueAlign_ticketattachment_uploaded_by_id_fk` (`uploaded_by_id`),
  CONSTRAINT `trueAlign_ticketattachment_ticket_id_fk` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_ticketattachment_uploaded_by_id_fk` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 27. trueAlign_ticketcomment
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_ticketcomment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `content` longtext NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `is_internal` tinyint(1) NOT NULL DEFAULT 0,
  `ticket_id` bigint(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketcomment_ticket_id_fk` (`ticket_id`),
  KEY `trueAlign_ticketcomment_user_id_fk` (`user_id`),
  CONSTRAINT `trueAlign_ticketcomment_ticket_id_fk` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_ticketcomment_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 28. truealign_comment_attachment
-- =============================================
CREATE TABLE IF NOT EXISTS `truealign_comment_attachment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `file` varchar(255) NOT NULL,
  `original_filename` varchar(255) NOT NULL,
  `formatted_filename` varchar(255) NOT NULL,
  `file_size` int(10) unsigned NOT NULL,
  `content_type` varchar(100) DEFAULT NULL,
  `uploaded_at` datetime(6) NOT NULL,
  `description` text DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `comment_id` bigint(20) NOT NULL,
  `ticket_activity_id` bigint(20) NOT NULL,
  `uploaded_by_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `truealign_comment_attachment_comment_id_fk` (`comment_id`),
  KEY `truealign_comment_attachment_ticket_activity_id_fk` (`ticket_activity_id`),
  KEY `truealign_comment_attachment_uploaded_by_id_fk` (`uploaded_by_id`),
  CONSTRAINT `truealign_comment_attachment_comment_id_fk` FOREIGN KEY (`comment_id`) REFERENCES `trueAlign_ticketcomment` (`id`),
  CONSTRAINT `truealign_comment_attachment_ticket_activity_id_fk` FOREIGN KEY (`ticket_activity_id`) REFERENCES `trueAlign_ticketactivity` (`id`),
  CONSTRAINT `truealign_comment_attachment_uploaded_by_id_fk` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 29. trueAlign_statuslog
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_statuslog` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `old_status` varchar(30) NOT NULL,
  `new_status` varchar(30) NOT NULL,
  `changed_at` datetime(6) NOT NULL,
  `changed_by_id` int(11) DEFAULT NULL,
  `ticket_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_statuslog_changed_by_id_fk` (`changed_by_id`),
  KEY `trueAlign_statuslog_ticket_id_fk` (`ticket_id`),
  CONSTRAINT `trueAlign_statuslog_changed_by_id_fk` FOREIGN KEY (`changed_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_statuslog_ticket_id_fk` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 30. trueAlign_appraisal
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_appraisal` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `title` varchar(200) NOT NULL,
  `overview` longtext NOT NULL,
  `period_start` date NOT NULL,
  `period_end` date NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `submitted_at` datetime(6) DEFAULT NULL,
  `approved_at` datetime(6) DEFAULT NULL,
  `manager_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisal_manager_id_fk` (`manager_id`),
  KEY `trueAlign_appraisal_user_id_fk` (`user_id`),
  KEY `trueAlign_appraisal_status_index` (`status`),
  CONSTRAINT `trueAlign_appraisal_manager_id_fk` FOREIGN KEY (`manager_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_appraisal_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 31. trueAlign_appraisalattachment
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_appraisalattachment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `title` varchar(200) NOT NULL,
  `uploaded_at` datetime(6) NOT NULL,
  `appraisal_id` bigint(20) NOT NULL,
  `uploaded_by_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisalattachment_appraisal_id_fk` (`appraisal_id`),
  KEY `trueAlign_appraisalattachment_uploaded_by_id_fk` (`uploaded_by_id`),
  CONSTRAINT `trueAlign_appraisalattachment_appraisal_id_fk` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`),
  CONSTRAINT `trueAlign_appraisalattachment_uploaded_by_id_fk` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 32. trueAlign_appraisalitem
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_appraisalitem` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `category` varchar(20) NOT NULL,
  `title` varchar(200) NOT NULL,
  `description` longtext NOT NULL,
  `date` date DEFAULT NULL,
  `employee_rating` smallint(5) unsigned DEFAULT NULL,
  `manager_rating` smallint(5) unsigned DEFAULT NULL,
  `manager_comments` longtext NOT NULL,
  `hr_rating` smallint(5) unsigned DEFAULT NULL,
  `hr_comments` longtext NOT NULL,
  `appraisal_id` bigint(20) NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisalitem_appraisal_id_fk` (`appraisal_id`),
  CONSTRAINT `trueAlign_appraisalitem_appraisal_id_fk` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 33. trueAlign_appraisalworkflow
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_appraisalworkflow` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `from_status` varchar(20) DEFAULT NULL,
  `to_status` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `comments` longtext NOT NULL,
  `action_by_id` int(11) DEFAULT NULL,
  `appraisal_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisalworkflow_action_by_id_fk` (`action_by_id`),
  KEY `trueAlign_appraisalworkflow_appraisal_id_fk` (`appraisal_id`),
  CONSTRAINT `trueAlign_appraisalworkflow_action_by_id_fk` FOREIGN KEY (`action_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_appraisalworkflow_appraisal_id_fk` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 34. trueAlign_globalupdate
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_globalupdate` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `description` longtext NOT NULL,
  `title_hi` varchar(255) DEFAULT NULL,
  `description_hi` text DEFAULT NULL,
  `title_mr` varchar(255) DEFAULT NULL,
  `description_mr` text DEFAULT NULL,
  `primary_language` varchar(2) NOT NULL DEFAULT 'en',
  `status` varchar(20) NOT NULL,
  `scheduled_date` datetime(6) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `managed_by_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_globalupdate_managed_by_id_fk` (`managed_by_id`),
  CONSTRAINT `trueAlign_globalupdate_managed_by_id_fk` FOREIGN KEY (`managed_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 35. trueAlign_notification
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_notification` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `message` text NOT NULL,
  `module` varchar(50) NOT NULL,
  `read` tinyint(1) NOT NULL DEFAULT 0,
  `timestamp` datetime(6) NOT NULL,
  `reference_id` varchar(50) DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  `recipient_id` int(11) NOT NULL,
  `title` varchar(200) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_notification_recipient_id_fk` (`recipient_id`),
  KEY `trueAlign_notification_timestamp_index` (`timestamp`),
  CONSTRAINT `trueAlign_notification_recipient_id_fk` FOREIGN KEY (`recipient_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 36. trueAlign_useractionlog
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_useractionlog` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `action_type` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `details` longtext DEFAULT NULL,
  `action_by_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_useractionlog_action_by_id_fk` (`action_by_id`),
  KEY `trueAlign_useractionlog_user_id_fk` (`user_id`),
  CONSTRAINT `trueAlign_useractionlog_action_by_id_fk` FOREIGN KEY (`action_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_useractionlog_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 37. trueAlign_compoffrequest
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_compoffrequest` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `worked_date` date NOT NULL,
  `reason` longtext NOT NULL,
  `hours_worked` decimal(4,1) NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approver_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_compoffrequest_approver_id_fk` (`approver_id`),
  KEY `trueAlign_compoffrequest_user_id_fk` (`user_id`),
  CONSTRAINT `trueAlign_compoffrequest_approver_id_fk` FOREIGN KEY (`approver_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_compoffrequest_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =============================================
-- 38. trueAlign_roombooking
-- =============================================
CREATE TABLE IF NOT EXISTS `trueAlign_roombooking` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `title` varchar(200) NOT NULL,
  `purpose` longtext NOT NULL,
  `attendees` longtext NOT NULL,
  `attendee_count` int(10) unsigned NOT NULL,
  `start_time` datetime(6) NOT NULL,
  `end_time` datetime(6) NOT NULL,
  `status` varchar(20) NOT NULL,
  `special_requirements` longtext NOT NULL,
  `cancelled_at` datetime(6) DEFAULT NULL,
  `cancellation_reason` text DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `room_id` bigint(20) NOT NULL,
  `booked_by_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_roombooking_room_id_fk` (`room_id`),
  KEY `trueAlign_roombooking_booked_by_id_fk` (`booked_by_id`),
  KEY `trueAlign_roombooking_status_index` (`status`),
  CONSTRAINT `trueAlign_roombooking_room_id_fk` FOREIGN KEY (`room_id`) REFERENCES `trueAlign_conferenceroom` (`id`),
  CONSTRAINT `trueAlign_roombooking_booked_by_id_fk` FOREIGN KEY (`booked_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
