-- Create Leave Management Tables Manually
-- This script creates the missing leave management tables for the trueAlign system

-- Drop tables if they exist (in reverse order due to foreign key constraints)
DROP TABLE IF EXISTS `truealign_leaverequesthistory`;
DROP TABLE IF EXISTS `truealign_compoffrequest`;
DROP TABLE IF EXISTS `truealign_leaverequest`;
DROP TABLE IF EXISTS `truealign_userleavebalance`;
DROP TABLE IF EXISTS `truealign_leaveallocation`;
DROP TABLE IF EXISTS `truealign_leavepolicy`;
DROP TABLE IF EXISTS `truealign_leavetype`;

-- Create LeaveType table
CREATE TABLE `truealign_leavetype` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `name` varchar(100) NOT NULL UNIQUE,
    `description` longtext NULL,
    `is_paid` tinyint(1) NOT NULL DEFAULT 1,
    `requires_approval` tinyint(1) NOT NULL DEFAULT 1,
    `requires_documentation` tinyint(1) NOT NULL DEFAULT 0,
    `count_weekends` tinyint(1) NOT NULL DEFAULT 0,
    `can_be_half_day` tinyint(1) NOT NULL DEFAULT 1,
    `is_active` tinyint(1) NOT NULL DEFAULT 1,
    `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);

-- Create LeavePolicy table
CREATE TABLE `truealign_leavepolicy` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `name` varchar(100) NOT NULL,
    `group_id` int NOT NULL,
    `is_active` tinyint(1) NOT NULL DEFAULT 1,
    `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
    `effective_from` date NOT NULL DEFAULT (CURDATE()),
    `effective_to` date NULL,
    `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
);

-- Create LeaveAllocation table
CREATE TABLE `truealign_leaveallocation` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `policy_id` bigint NOT NULL,
    `leave_type_id` bigint NOT NULL,
    `annual_days` decimal(5, 1) NOT NULL DEFAULT 0.0,
    `advance_notice_days` int NOT NULL DEFAULT 0,
    `max_consecutive_days` int NOT NULL DEFAULT 0,
    `carryforward_limit` decimal(5, 1) NOT NULL DEFAULT 0.0,
    `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
    `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    FOREIGN KEY (`policy_id`) REFERENCES `truealign_leavepolicy` (`id`),
    FOREIGN KEY (`leave_type_id`) REFERENCES `truealign_leavetype` (`id`)
);

-- Create UserLeaveBalance table
CREATE TABLE `truealign_userleavebalance` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `user_id` int NOT NULL,
    `leave_type_id` bigint NOT NULL,
    `year` int NOT NULL,
    `allocated` decimal(5, 1) NOT NULL DEFAULT 0.0,
    `used` decimal(5, 1) NOT NULL DEFAULT 0.0,
    `carried_forward` decimal(5, 1) NOT NULL DEFAULT 0.0,
    `additional` decimal(5, 1) NOT NULL DEFAULT 0.0,
    `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
    `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
    FOREIGN KEY (`leave_type_id`) REFERENCES `truealign_leavetype` (`id`)
);

-- Create LeaveRequest table
CREATE TABLE `truealign_leaverequest` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `user_id` int NOT NULL,
    `leave_type_id` bigint NOT NULL,
    `start_date` date NOT NULL,
    `end_date` date NOT NULL,
    `leave_days` decimal(5, 1) NOT NULL DEFAULT 0.0,
    `status` varchar(20) NOT NULL DEFAULT 'Pending',
    `approver_id` int NULL,
    `reason` longtext NOT NULL,
    `rejection_reason` longtext NULL,
    `documentation` varchar(255) NULL,
    `half_day` tinyint(1) NOT NULL DEFAULT 0,
    `suggested_dates` longtext NULL,
    `is_retroactive` tinyint(1) NOT NULL DEFAULT 0,
    `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
    FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
    FOREIGN KEY (`leave_type_id`) REFERENCES `truealign_leavetype` (`id`),
    FOREIGN KEY (`approver_id`) REFERENCES `auth_user` (`id`),
    CHECK (`end_date` >= `start_date`),
    CHECK (`leave_days` >= 0)
);

-- Create LeaveRequestHistory table
CREATE TABLE `truealign_leaverequesthistory` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `leave_request_id` bigint NOT NULL,
    `action` varchar(20) NOT NULL,
    `performed_by_id` int NOT NULL,
    `timestamp` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `old_values` json NULL,
    `new_values` json NULL,
    `comments` longtext NULL,
    FOREIGN KEY (`leave_request_id`) REFERENCES `truealign_leaverequest` (`id`),
    FOREIGN KEY (`performed_by_id`) REFERENCES `auth_user` (`id`)
);

-- Create CompOffRequest table
CREATE TABLE `truealign_compoffrequest` (
    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `user_id` int NOT NULL,
    `worked_date` date NOT NULL,
    `hours_worked` int NOT NULL,
    `status` varchar(20) NOT NULL DEFAULT 'Pending',
    `approver_id` int NULL,
    `reason` longtext NOT NULL,
    `comp_off_date_requested` date NULL,
    `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    `is_deleted` tinyint(1) NOT NULL DEFAULT 0,
    FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
    FOREIGN KEY (`approver_id`) REFERENCES `auth_user` (`id`)
);

-- Create indexes for better performance
CREATE INDEX `truealign_l_group_i_4b9a16_idx` ON `truealign_leavepolicy` (`group_id`, `is_active`, `is_deleted`);
CREATE INDEX `truealign_l_effecti_780dbb_idx` ON `truealign_leavepolicy` (`effective_from`, `effective_to`);

CREATE INDEX `truealign_l_leave_r_b90809_idx` ON `truealign_leaverequesthistory` (`leave_request_id`, `action`);
CREATE INDEX `truealign_l_perform_aa55a3_idx` ON `truealign_leaverequesthistory` (`performed_by_id`, `timestamp`);
CREATE INDEX `truealign_l_timesta_b66061_idx` ON `truealign_leaverequesthistory` (`timestamp`);

CREATE INDEX `truealign_l_user_id_e2aa7e_idx` ON `truealign_leaverequest` (`user_id`, `start_date`, `status`);
CREATE INDEX `truealign_l_status_33ebf9_idx` ON `truealign_leaverequest` (`status`, `created_at`);
CREATE INDEX `truealign_l_approve_986584_idx` ON `truealign_leaverequest` (`approver_id`, `status`);

CREATE INDEX `truealign_u_user_id_b8f539_idx` ON `truealign_userleavebalance` (`user_id`, `leave_type_id`, `year`);
CREATE INDEX `truealign_u_leave_t_7f4d31_idx` ON `truealign_userleavebalance` (`leave_type_id`, `year`);

-- Insert some default leave types
INSERT INTO `truealign_leavetype` (`name`, `description`, `is_paid`, `requires_approval`, `requires_documentation`, `count_weekends`, `can_be_half_day`, `is_active`) VALUES
('Annual Leave', 'Yearly vacation leave', 1, 1, 0, 0, 1, 1),
('Sick Leave', 'Medical leave', 1, 1, 1, 0, 1, 1),
('Casual Leave', 'Casual/personal leave', 1, 1, 0, 0, 1, 1),
('Maternity Leave', 'Maternity leave for mothers', 1, 1, 1, 1, 0, 1),
('Paternity Leave', 'Paternity leave for fathers', 1, 1, 1, 1, 0, 1),
('Emergency Leave', 'Emergency situations', 1, 1, 0, 0, 1, 1),
('Comp Off', 'Compensatory off for overtime work', 1, 1, 0, 0, 1, 1);

-- Update migration record to mark as applied
INSERT INTO `django_migrations` (`app`, `name`, `applied`) VALUES ('trueAlign', '0001_initial', NOW())
ON DUPLICATE KEY UPDATE `applied` = NOW();

COMMIT;
