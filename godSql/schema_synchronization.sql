-- Change trueAlign_officelocation.email: Type varchar(254)->varchar(255), Null NO->NOT NULL

ALTER TABLE `trueAlign_officelocation` MODIFY COLUMN `email` varchar(255) NOT NULL;

-- Change trueAlign_conferenceroom.office_location_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_conferenceroom` MODIFY COLUMN `office_location_id` int NOT NULL;

-- Change trueAlign_conferenceroom.description: Type text->longtext, Null YES->NULL

ALTER TABLE `trueAlign_conferenceroom` MODIFY COLUMN `description` longtext NULL;

-- Change trueAlign_roombooking.room_id: Type bigint(20) unsigned->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_roombooking` MODIFY COLUMN `room_id` int NOT NULL;

-- Change trueAlign_roombooking.cancellation_reason: Type text->longtext, Null YES->NULL

ALTER TABLE `trueAlign_roombooking` MODIFY COLUMN `cancellation_reason` longtext NULL;

-- Change trueAlign_clientprofile.website_url: Type varchar(200)->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_clientprofile` MODIFY COLUMN `website_url` varchar(255) NULL;

-- Change trueAlign_usersession.id: Type char(36)->char(32), Null NO->NOT NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `id` char(32) NOT NULL;

-- Change trueAlign_usersession.created_at: Type datetime->datetime(6), Null NO->NOT NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `created_at` datetime(6) NOT NULL;

-- Change trueAlign_usersession.login_time: Type datetime->datetime(6), Null NO->NOT NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `login_time` datetime(6) NOT NULL;

-- Change trueAlign_usersession.logout_time: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `logout_time` datetime(6) NULL;

-- Change trueAlign_usersession.last_activity: Type datetime->datetime(6), Null NO->NOT NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `last_activity` datetime(6) NOT NULL;

-- Change trueAlign_usersession.ended_at: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `ended_at` datetime(6) NULL;

-- Change trueAlign_usersession.session_end_time: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `session_end_time` datetime(6) NULL;

-- Change trueAlign_usersession.start_time: Type datetime->datetime(6), Null NO->NOT NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `start_time` datetime(6) NOT NULL;

-- Change trueAlign_usersession.tab_opened_time: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `tab_opened_time` datetime(6) NULL;

-- Change trueAlign_usersession.tab_last_focus: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `tab_last_focus` datetime(6) NULL;

-- Change trueAlign_usersession.idle_start_time: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `idle_start_time` datetime(6) NULL;

-- Change trueAlign_usersession.session_duration: Type float->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `session_duration` varchar(255) NULL;

-- Change trueAlign_usersession.idle_time: Type time->bigint, Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `idle_time` bigint NULL;

-- Change trueAlign_usersession.ip_address: Type varchar(45)->char(39), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `ip_address` char(39) NULL;

-- Change trueAlign_usersession.user_agent: Type text->longtext, Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `user_agent` longtext NULL;

-- Change trueAlign_usersession.browser_fingerprint: Type text->longtext, Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `browser_fingerprint` longtext NULL;

-- Change trueAlign_usersession.csrf_token: Type char(64)->varchar(64), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `csrf_token` varchar(64) NULL;

-- Change trueAlign_usersession.csrf_token_created: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `csrf_token_created` datetime(6) NULL;

-- Change trueAlign_usersession.battery_level: Type float->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `battery_level` varchar(255) NULL;

-- Change trueAlign_usersession.location_latitude: Type float->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `location_latitude` varchar(255) NULL;

-- Change trueAlign_usersession.location_longitude: Type float->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `location_longitude` varchar(255) NULL;

-- Change trueAlign_usersession.location_accuracy: Type float->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `location_accuracy` varchar(255) NULL;

ALTER TABLE `trueAlign_usersession` ADD COLUMN `current_office_location_id` int NULL;

ALTER TABLE `trueAlign_usersession` ADD COLUMN `last_location_latitude` varchar(255) NULL;

ALTER TABLE `trueAlign_usersession` ADD COLUMN `last_location_longitude` varchar(255) NULL;

ALTER TABLE `trueAlign_usersession` ADD COLUMN `last_location_time` datetime(6) NULL;

ALTER TABLE `trueAlign_usersession` ADD COLUMN `impossible_travel_detected` tinyint(1) NOT NULL;

ALTER TABLE `trueAlign_usersession` ADD COLUMN `travel_velocity_kmh` varchar(255) NULL;

-- Change trueAlign_usersession.last_warning_time: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `last_warning_time` datetime(6) NULL;

-- Change trueAlign_usersession.last_sync_time: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `last_sync_time` datetime(6) NULL;

-- Change trueAlign_usersession.most_visited_url: Type varchar(2000)->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `most_visited_url` varchar(255) NULL;

-- Change trueAlign_usersession.productivity_score: Type float->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `productivity_score` varchar(255) NULL;

-- Change trueAlign_usersession.engagement_score: Type float->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `engagement_score` varchar(255) NULL;

-- Change trueAlign_usersession.security_score: Type float->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_usersession` MODIFY COLUMN `security_score` varchar(255) NULL;

CREATE TABLE `trueAlign_userdevice` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `user_id` int NOT NULL,
    `device_fingerprint` varchar(255) NOT NULL,
    `device_name` varchar(200) NOT NULL,
    `browser` varchar(100) NULL,
    `os` varchar(100) NULL,
    `device_type` varchar(20) NULL,
    `is_trusted` tinyint(1) NOT NULL,
    `trust_level` int NOT NULL,
    `first_seen` datetime(6) NOT NULL,
    `last_seen` datetime(6) NOT NULL,
    `last_ip` char(39) NULL,
    `ip_addresses` longtext NOT NULL,
    `locations_used` longtext NOT NULL,
    `session_count` int NOT NULL,
    `last_session_id` char(32) NULL,
    `suspicious_activity_count` int NOT NULL,
    `is_blocked` tinyint(1) NOT NULL,
    `blocked_reason` longtext NULL
);

-- Change trueAlign_sessionactivity.session_id: Type bigint(20)->int, Null YES->NOT NULL

ALTER TABLE `trueAlign_sessionactivity` MODIFY COLUMN `session_id` int NOT NULL;

-- Change trueAlign_sessionactivity.user_id: Type int(11)->int, Null YES->NOT NULL

ALTER TABLE `trueAlign_sessionactivity` MODIFY COLUMN `user_id` int NOT NULL;

-- Change trueAlign_sessionactivity.url: Type varchar(2000)->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_sessionactivity` MODIFY COLUMN `url` varchar(255) NULL;

-- Change trueAlign_sessionactivity.location_latitude: Type double->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_sessionactivity` MODIFY COLUMN `location_latitude` varchar(255) NULL;

-- Change trueAlign_sessionactivity.location_longitude: Type double->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_sessionactivity` MODIFY COLUMN `location_longitude` varchar(255) NULL;

-- Change trueAlign_sessionactivity.location_accuracy: Type double->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_sessionactivity` MODIFY COLUMN `location_accuracy` varchar(255) NULL;

-- Change trueAlign_sessionactivity.productivity_score: Type double->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_sessionactivity` MODIFY COLUMN `productivity_score` varchar(255) NULL;

-- Change trueAlign_sessionactivity.engagement_score: Type double->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_sessionactivity` MODIFY COLUMN `engagement_score` varchar(255) NULL;

-- Change trueAlign_userdetails.personal_email: Type varchar(254)->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_userdetails` MODIFY COLUMN `personal_email` varchar(255) NULL;

-- Change trueAlign_userdetails.company_email: Type varchar(254)->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_userdetails` MODIFY COLUMN `company_email` varchar(255) NULL;

-- Change trueAlign_userdetails.office_location_id: Type bigint(20)->int, Null YES->NULL

ALTER TABLE `trueAlign_userdetails` MODIFY COLUMN `office_location_id` int NULL;

-- Change trueAlign_useractionlog.action_by_id: Type int(11)->int, Null YES->NOT NULL

ALTER TABLE `trueAlign_useractionlog` MODIFY COLUMN `action_by_id` int NOT NULL;

ALTER TABLE `trueAlign_layoutpreference` ADD COLUMN `user_id` int NULL;

ALTER TABLE `trueAlign_shiftmaster` ADD COLUMN `MIN_SHIFT_DURATION` varchar(255) NOT NULL;

ALTER TABLE `trueAlign_shiftmaster` ADD COLUMN `MAX_SHIFT_DURATION` varchar(255) NOT NULL;

ALTER TABLE `trueAlign_shiftmaster` ADD COLUMN `MAX_BREAK_HOURS` varchar(255) NOT NULL;

-- Change trueAlign_shiftmaster.color_code: Type char(7)->varchar(7), Null NO->NOT NULL

ALTER TABLE `trueAlign_shiftmaster` MODIFY COLUMN `color_code` varchar(7) NOT NULL;

-- Change trueAlign_shiftmaster.description: Type text->longtext, Null YES->NULL

ALTER TABLE `trueAlign_shiftmaster` MODIFY COLUMN `description` longtext NULL;

-- Change trueAlign_shiftassignment.shift_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_shiftassignment` MODIFY COLUMN `shift_id` int NOT NULL;

ALTER TABLE `trueAlign_shiftassignment` ADD COLUMN `created_by_id` int NULL;

-- Change trueAlign_shiftassignment.notes: Type text->longtext, Null YES->NULL

ALTER TABLE `trueAlign_shiftassignment` MODIFY COLUMN `notes` longtext NULL;

ALTER TABLE `trueAlign_shiftassignment` ADD COLUMN `approved_by_id` int NULL;

-- Change trueAlign_shiftassignment.approved_at: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_shiftassignment` MODIFY COLUMN `approved_at` datetime(6) NULL;

ALTER TABLE `trueAlign_leavepolicy` ADD COLUMN `created_by_id` int NULL;

-- Change trueAlign_leaveallocation.policy_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_leaveallocation` MODIFY COLUMN `policy_id` int NOT NULL;

-- Change trueAlign_leaveallocation.leave_type_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_leaveallocation` MODIFY COLUMN `leave_type_id` int NOT NULL;

ALTER TABLE `trueAlign_leaveallocation` ADD COLUMN `carryforward_limit` decimal(5,1) NOT NULL;

-- Change trueAlign_userleavebalance.leave_type_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_userleavebalance` MODIFY COLUMN `leave_type_id` int NOT NULL;

-- Change trueAlign_userleavebalance.allocated: Type decimal(5,1)->decimal(5,2), Null NO->NOT NULL

ALTER TABLE `trueAlign_userleavebalance` MODIFY COLUMN `allocated` decimal(5,2) NOT NULL;

-- Change trueAlign_userleavebalance.used: Type decimal(5,1)->decimal(5,2), Null NO->NOT NULL

ALTER TABLE `trueAlign_userleavebalance` MODIFY COLUMN `used` decimal(5,2) NOT NULL;

-- Change trueAlign_userleavebalance.additional: Type decimal(5,1)->decimal(5,2), Null NO->NOT NULL

ALTER TABLE `trueAlign_userleavebalance` MODIFY COLUMN `additional` decimal(5,2) NOT NULL;

-- Change trueAlign_userleavebalance.carried_forward: Type decimal(5,1)->decimal(5,2), Null NO->NOT NULL

ALTER TABLE `trueAlign_userleavebalance` MODIFY COLUMN `carried_forward` decimal(5,2) NOT NULL;

-- Change trueAlign_leaverequest.leave_type_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_leaverequest` MODIFY COLUMN `leave_type_id` int NOT NULL;

-- Change trueAlign_leaverequest.leave_days: Type decimal(5,1)->decimal(5,2), Null NO->NOT NULL

ALTER TABLE `trueAlign_leaverequest` MODIFY COLUMN `leave_days` decimal(5,2) NOT NULL;

-- Change trueAlign_leaverequest.documentation: Type varchar(100)->varchar(255), Null YES->NULL

ALTER TABLE `trueAlign_leaverequest` MODIFY COLUMN `documentation` varchar(255) NULL;

ALTER TABLE `trueAlign_compoffrequest` ADD COLUMN `rejection_reason` longtext NULL;

ALTER TABLE `trueAlign_compoffrequest` ADD COLUMN `is_deleted` tinyint(1) NOT NULL;

ALTER TABLE `trueAlign_leaverequesthistory` ADD COLUMN `leave_request_id` int NOT NULL;

ALTER TABLE `trueAlign_leaverequesthistory` ADD COLUMN `performed_by_id` int NOT NULL;

-- Change trueAlign_attendance.shift_id: Type bigint(20)->int, Null YES->NULL

ALTER TABLE `trueAlign_attendance` MODIFY COLUMN `shift_id` int NULL;

-- Change trueAlign_attendance.first_session_id: Type char(36)->int, Null YES->NULL

ALTER TABLE `trueAlign_attendance` MODIFY COLUMN `first_session_id` int NULL;

-- Change trueAlign_attendance.last_session_id: Type char(36)->int, Null YES->NULL

ALTER TABLE `trueAlign_attendance` MODIFY COLUMN `last_session_id` int NULL;

-- Change trueAlign_globalupdate.description_hi: Type text->longtext, Null YES->NULL

ALTER TABLE `trueAlign_globalupdate` MODIFY COLUMN `description_hi` longtext NULL;

-- Change trueAlign_globalupdate.description_mr: Type text->longtext, Null YES->NULL

ALTER TABLE `trueAlign_globalupdate` MODIFY COLUMN `description_mr` longtext NULL;

-- Change trueAlign_support.id: Type bigint(20)->int AUTO_INCREMENT, Null NO->NOT NULL

ALTER TABLE `trueAlign_support` MODIFY COLUMN `id` int AUTO_INCREMENT NOT NULL;

ALTER TABLE `trueAlign_support` ADD COLUMN `cc_users` varchar(255) NOT NULL;

-- Change trueAlign_support.parent_ticket_id: Type bigint(20)->int, Null YES->NULL

ALTER TABLE `trueAlign_support` MODIFY COLUMN `parent_ticket_id` int NULL;

-- Change trueAlign_support.sla_target_date: Type datetime->datetime(6), Null YES->NULL

ALTER TABLE `trueAlign_support` MODIFY COLUMN `sla_target_date` datetime(6) NULL;

-- Change trueAlign_statuslog.ticket_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_statuslog` MODIFY COLUMN `ticket_id` int NOT NULL;

-- Change trueAlign_statuslog.changed_by_id: Type int(11)->int, Null YES->NOT NULL

ALTER TABLE `trueAlign_statuslog` MODIFY COLUMN `changed_by_id` int NOT NULL;

-- Change trueAlign_ticketcomment.ticket_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_ticketcomment` MODIFY COLUMN `ticket_id` int NOT NULL;

-- Change trueAlign_ticketactivity.ticket_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_ticketactivity` MODIFY COLUMN `ticket_id` int NOT NULL;

-- Change trueAlign_ticketactivity.user_id: Type int(11)->int, Null YES->NOT NULL

ALTER TABLE `trueAlign_ticketactivity` MODIFY COLUMN `user_id` int NOT NULL;

-- Change truealign_comment_attachment.comment_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `truealign_comment_attachment` MODIFY COLUMN `comment_id` int NOT NULL;

-- Change truealign_comment_attachment.ticket_activity_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `truealign_comment_attachment` MODIFY COLUMN `ticket_activity_id` int NOT NULL;

-- Change truealign_comment_attachment.description: Type text->longtext, Null YES->NULL

ALTER TABLE `truealign_comment_attachment` MODIFY COLUMN `description` longtext NULL;

-- Change trueAlign_ticketattachment.ticket_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_ticketattachment` MODIFY COLUMN `ticket_id` int NOT NULL;

-- Change trueAlign_ticketattachment.file: Type varchar(100)->varchar(255), Null NO->NOT NULL

ALTER TABLE `trueAlign_ticketattachment` MODIFY COLUMN `file` varchar(255) NOT NULL;

-- Change trueAlign_notification.message: Type text->longtext, Null NO->NOT NULL

ALTER TABLE `trueAlign_notification` MODIFY COLUMN `message` longtext NOT NULL;

-- Change trueAlign_appraisalitem.appraisal_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_appraisalitem` MODIFY COLUMN `appraisal_id` int NOT NULL;

-- Change trueAlign_appraisalitem.employee_rating: Type smallint(5) unsigned->int, Null YES->NULL

ALTER TABLE `trueAlign_appraisalitem` MODIFY COLUMN `employee_rating` int NULL;

-- Change trueAlign_appraisalitem.manager_rating: Type smallint(5) unsigned->int, Null YES->NULL

ALTER TABLE `trueAlign_appraisalitem` MODIFY COLUMN `manager_rating` int NULL;

-- Change trueAlign_appraisalitem.hr_rating: Type smallint(5) unsigned->int, Null YES->NULL

ALTER TABLE `trueAlign_appraisalitem` MODIFY COLUMN `hr_rating` int NULL;

-- Change trueAlign_appraisalattachment.appraisal_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_appraisalattachment` MODIFY COLUMN `appraisal_id` int NOT NULL;

-- Change trueAlign_appraisalattachment.file: Type varchar(100)->varchar(255), Null NO->NOT NULL

ALTER TABLE `trueAlign_appraisalattachment` MODIFY COLUMN `file` varchar(255) NOT NULL;

-- Change trueAlign_appraisalworkflow.appraisal_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_appraisalworkflow` MODIFY COLUMN `appraisal_id` int NOT NULL;

-- Change trueAlign_shiftvalidationrule.group_id: Type int(11)->int, Null YES->NOT NULL

ALTER TABLE `trueAlign_shiftvalidationrule` MODIFY COLUMN `group_id` int NOT NULL;

-- Change trueAlign_shiftconflict.assignment_id: Type bigint(20)->int, Null NO->NOT NULL

ALTER TABLE `trueAlign_shiftconflict` MODIFY COLUMN `assignment_id` int NOT NULL;

-- Change trueAlign_shiftconflict.conflicting_assignment_id: Type bigint(20)->int, Null YES->NULL

ALTER TABLE `trueAlign_shiftconflict` MODIFY COLUMN `conflicting_assignment_id` int NULL;

ALTER TABLE `trueAlign_shiftconflict` ADD COLUMN `resolved_by_id` int NULL;

CREATE TABLE `trueAlign_bankaccount` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `name` varchar(255) NOT NULL,
    `account_number` varchar(50) NOT NULL,
    `bank_name` varchar(255) NOT NULL,
    `branch` varchar(255) NOT NULL,
    `ifsc_code` varchar(20) NOT NULL,
    `current_balance` decimal(15,2) NOT NULL,
    `is_active` tinyint(1) NOT NULL,
    `created_at` datetime(6) NOT NULL,
    `updated_at` datetime(6) NOT NULL
);

CREATE TABLE `trueAlign_bankpayment` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `payment_id` varchar(50) NOT NULL,
    `bank_account_id` int NOT NULL,
    `party_name` varchar(255) NOT NULL,
    `payment_reason` longtext NOT NULL,
    `amount` decimal(15,2) NOT NULL,
    `payment_date` date NOT NULL,
    `reference_number` varchar(100) NULL,
    `status` varchar(20) NOT NULL,
    `created_by_id` int NOT NULL,
    `verified_by_id` int NULL,
    `approved_by_id` int NULL,
    `attachments` varchar(255) NULL,
    `created_at` datetime(6) NOT NULL,
    `updated_at` datetime(6) NOT NULL
);

CREATE TABLE `trueAlign_chartofaccount` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `name` varchar(255) NOT NULL,
    `code` varchar(20) NOT NULL,
    `account_type` varchar(20) NOT NULL,
    `parent_id` int NULL,
    `description` longtext NULL,
    `is_active` tinyint(1) NOT NULL,
    `created_at` datetime(6) NOT NULL,
    `updated_at` datetime(6) NOT NULL
);

CREATE TABLE `trueAlign_clientinvoice` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `invoice_number` varchar(50) NOT NULL,
    `client_id` int NOT NULL,
    `billing_model` varchar(20) NOT NULL,
    `billing_cycle_start` date NOT NULL,
    `billing_cycle_end` date NOT NULL,
    `order_count` int NULL,
    `fte_count` decimal(5,2) NULL,
    `rate` decimal(10,2) NOT NULL,
    `subtotal` decimal(15,2) NOT NULL,
    `tax_amount` decimal(15,2) NOT NULL,
    `discount` decimal(15,2) NOT NULL,
    `total_amount` decimal(15,2) NOT NULL,
    `status` varchar(20) NOT NULL,
    `due_date` date NOT NULL,
    `approved_by_id` int NULL,
    `created_at` datetime(6) NOT NULL,
    `updated_at` datetime(6) NOT NULL
);

CREATE TABLE `trueAlign_dailyexpense` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `expense_id` varchar(50) NOT NULL,
    `paid_by_id` int NOT NULL,
    `department` varchar(100) NOT NULL,
    `date` date NOT NULL,
    `category` varchar(20) NOT NULL,
    `description` longtext NOT NULL,
    `amount` decimal(15,2) NOT NULL,
    `status` varchar(20) NOT NULL,
    `approved_by_id` int NULL,
    `approved_at` datetime(6) NULL,
    `rejection_reason` longtext NULL,
    `attachments` varchar(255) NULL,
    `created_at` datetime(6) NOT NULL,
    `updated_at` datetime(6) NOT NULL
);

CREATE TABLE `trueAlign_financialparameter` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `key` varchar(100) NOT NULL,
    `name` varchar(255) NOT NULL,
    `category` varchar(20) NOT NULL,
    `description` longtext NULL,
    `value` longtext NOT NULL,
    `value_type` varchar(20) NOT NULL,
    `is_global` tinyint(1) NOT NULL,
    `content_type_id` int NULL,
    `object_id` int NULL,
    `valid_from` date NOT NULL,
    `valid_to` date NULL,
    `fiscal_year` varchar(9) NULL,
    `fiscal_quarter` varchar(6) NULL,
    `created_by_id` int NOT NULL,
    `updated_by_id` int NULL,
    `created_at` datetime(6) NOT NULL,
    `updated_at` datetime(6) NOT NULL,
    `is_approved` tinyint(1) NOT NULL,
    `approved_by_id` int NULL,
    `approved_at` datetime(6) NULL
);

CREATE TABLE `trueAlign_voucher` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `voucher_number` varchar(50) NOT NULL,
    `type` varchar(20) NOT NULL,
    `date` date NOT NULL,
    `reference_no` varchar(100) NULL,
    `party_name` varchar(255) NOT NULL,
    `purpose` longtext NOT NULL,
    `amount` decimal(15,2) NOT NULL,
    `status` varchar(25) NOT NULL,
    `created_by_id` int NOT NULL,
    `department_approved_by_id` int NULL,
    `finance_approved_by_id` int NULL,
    `attachments` varchar(255) NULL,
    `created_at` datetime(6) NOT NULL,
    `updated_at` datetime(6) NOT NULL
);

CREATE TABLE `trueAlign_voucherdetail` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `voucher_id` int NOT NULL,
    `account_id` int NOT NULL,
    `debit_amount` decimal(15,2) NOT NULL,
    `credit_amount` decimal(15,2) NOT NULL,
    `description` longtext NULL
);