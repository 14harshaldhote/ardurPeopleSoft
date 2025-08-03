-- MySQL dump 10.13  Distrib 8.0.42, for macos15.2 (arm64)
--
-- Host: localhost    Database: ardurTrueAlign
-- ------------------------------------------------------
-- Server version	8.0.42

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_group` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_group_permissions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `group_id` int NOT NULL,
  `permission_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_permission` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=316 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_user`
--

DROP TABLE IF EXISTS `auth_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_user_groups`
--

DROP TABLE IF EXISTS `auth_user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user_groups` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `group_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_groups_user_id_group_id_94350c0c_uniq` (`user_id`,`group_id`),
  KEY `auth_user_groups_group_id_97559544_fk_auth_group_id` (`group_id`),
  CONSTRAINT `auth_user_groups_group_id_97559544_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `auth_user_groups_user_id_6a12ed8b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_user_user_permissions`
--

DROP TABLE IF EXISTS `auth_user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user_user_permissions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `permission_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_user_permissions_user_id_permission_id_14a6b632_uniq` (`user_id`,`permission_id`),
  KEY `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_admin_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint unsigned NOT NULL,
  `change_message` longtext NOT NULL,
  `content_type_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  KEY `django_admin_log_user_id_c564eba6_fk_auth_user_id` (`user_id`),
  CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `django_admin_log_user_id_c564eba6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `django_admin_log_chk_1` CHECK ((`action_flag` >= 0))
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_celery_beat_clockedschedule`
--

DROP TABLE IF EXISTS `django_celery_beat_clockedschedule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_celery_beat_clockedschedule` (
  `id` int NOT NULL AUTO_INCREMENT,
  `clocked_time` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_celery_beat_crontabschedule`
--

DROP TABLE IF EXISTS `django_celery_beat_crontabschedule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_celery_beat_crontabschedule` (
  `id` int NOT NULL AUTO_INCREMENT,
  `minute` varchar(240) NOT NULL,
  `hour` varchar(96) NOT NULL,
  `day_of_week` varchar(64) NOT NULL,
  `day_of_month` varchar(124) NOT NULL,
  `month_of_year` varchar(64) NOT NULL,
  `timezone` varchar(63) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_celery_beat_intervalschedule`
--

DROP TABLE IF EXISTS `django_celery_beat_intervalschedule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_celery_beat_intervalschedule` (
  `id` int NOT NULL AUTO_INCREMENT,
  `every` int NOT NULL,
  `period` varchar(24) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_celery_beat_periodictask`
--

DROP TABLE IF EXISTS `django_celery_beat_periodictask`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_celery_beat_periodictask` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(200) NOT NULL,
  `task` varchar(200) NOT NULL,
  `args` longtext NOT NULL,
  `kwargs` longtext NOT NULL,
  `queue` varchar(200) DEFAULT NULL,
  `exchange` varchar(200) DEFAULT NULL,
  `routing_key` varchar(200) DEFAULT NULL,
  `expires` datetime(6) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL,
  `last_run_at` datetime(6) DEFAULT NULL,
  `total_run_count` int unsigned NOT NULL,
  `date_changed` datetime(6) NOT NULL,
  `description` longtext NOT NULL,
  `crontab_id` int DEFAULT NULL,
  `interval_id` int DEFAULT NULL,
  `solar_id` int DEFAULT NULL,
  `one_off` tinyint(1) NOT NULL,
  `start_time` datetime(6) DEFAULT NULL,
  `priority` int unsigned DEFAULT NULL,
  `headers` longtext NOT NULL DEFAULT (_utf8mb4'{}'),
  `clocked_id` int DEFAULT NULL,
  `expire_seconds` int unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  KEY `django_celery_beat_p_crontab_id_d3cba168_fk_django_ce` (`crontab_id`),
  KEY `django_celery_beat_p_interval_id_a8ca27da_fk_django_ce` (`interval_id`),
  KEY `django_celery_beat_p_solar_id_a87ce72c_fk_django_ce` (`solar_id`),
  KEY `django_celery_beat_p_clocked_id_47a69f82_fk_django_ce` (`clocked_id`),
  CONSTRAINT `django_celery_beat_p_clocked_id_47a69f82_fk_django_ce` FOREIGN KEY (`clocked_id`) REFERENCES `django_celery_beat_clockedschedule` (`id`),
  CONSTRAINT `django_celery_beat_p_crontab_id_d3cba168_fk_django_ce` FOREIGN KEY (`crontab_id`) REFERENCES `django_celery_beat_crontabschedule` (`id`),
  CONSTRAINT `django_celery_beat_p_interval_id_a8ca27da_fk_django_ce` FOREIGN KEY (`interval_id`) REFERENCES `django_celery_beat_intervalschedule` (`id`),
  CONSTRAINT `django_celery_beat_p_solar_id_a87ce72c_fk_django_ce` FOREIGN KEY (`solar_id`) REFERENCES `django_celery_beat_solarschedule` (`id`),
  CONSTRAINT `django_celery_beat_periodictask_chk_1` CHECK ((`total_run_count` >= 0)),
  CONSTRAINT `django_celery_beat_periodictask_chk_2` CHECK ((`priority` >= 0)),
  CONSTRAINT `django_celery_beat_periodictask_chk_3` CHECK ((`expire_seconds` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_celery_beat_periodictasks`
--

DROP TABLE IF EXISTS `django_celery_beat_periodictasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_celery_beat_periodictasks` (
  `ident` smallint NOT NULL,
  `last_update` datetime(6) NOT NULL,
  PRIMARY KEY (`ident`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_celery_beat_solarschedule`
--

DROP TABLE IF EXISTS `django_celery_beat_solarschedule`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_celery_beat_solarschedule` (
  `id` int NOT NULL AUTO_INCREMENT,
  `event` varchar(24) NOT NULL,
  `latitude` decimal(9,6) NOT NULL,
  `longitude` decimal(9,6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_celery_beat_solar_event_latitude_longitude_ba64999a_uniq` (`event`,`latitude`,`longitude`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_content_type` (
  `id` int NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=78 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_cron_cronjoblock`
--

DROP TABLE IF EXISTS `django_cron_cronjoblock`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_cron_cronjoblock` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `job_name` varchar(200) NOT NULL,
  `locked` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `job_name` (`job_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_cron_cronjoblog`
--

DROP TABLE IF EXISTS `django_cron_cronjoblog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_cron_cronjoblog` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `code` varchar(64) NOT NULL,
  `start_time` datetime(6) NOT NULL,
  `end_time` datetime(6) NOT NULL,
  `is_success` tinyint(1) NOT NULL,
  `message` longtext NOT NULL,
  `ran_at_time` time(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `django_cron_cronjoblog_code_start_time_ran_at_time_8b50b8fa_idx` (`code`,`start_time`,`ran_at_time`),
  KEY `django_cron_cronjoblog_code_start_time_4fc78f9d_idx` (`code`,`start_time`),
  KEY `django_cron_cronjoblog_code_is_success_ran_at_time_84da9606_idx` (`code`,`is_success`,`ran_at_time`),
  KEY `django_cron_cronjoblog_code_48865653` (`code`),
  KEY `django_cron_cronjoblog_start_time_d68c0dd9` (`start_time`),
  KEY `django_cron_cronjoblog_end_time_7918602a` (`end_time`),
  KEY `django_cron_cronjoblog_ran_at_time_7fed2751` (`ran_at_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_migrations` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=61 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_appraisal`
--

DROP TABLE IF EXISTS `trueAlign_appraisal`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_appraisal` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `overview` longtext NOT NULL,
  `period_start` date NOT NULL,
  `period_end` date NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `submitted_at` datetime(6) DEFAULT NULL,
  `approved_at` datetime(6) DEFAULT NULL,
  `manager_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisal_manager_id_3ea4d24d_fk_auth_user_id` (`manager_id`),
  KEY `trueAlign_appraisal_user_id_1e4892d0_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_appraisal_manager_id_3ea4d24d_fk_auth_user_id` FOREIGN KEY (`manager_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_appraisal_user_id_1e4892d0_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_appraisalattachment`
--

DROP TABLE IF EXISTS `trueAlign_appraisalattachment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_appraisalattachment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` longtext NOT NULL,
  `upload_date` datetime(6) NOT NULL,
  `appraisal_id` bigint NOT NULL,
  `uploaded_by_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisala_appraisal_id_94991c7b_fk_trueAlign` (`appraisal_id`),
  KEY `trueAlign_appraisala_uploaded_by_id_d8366266_fk_auth_user` (`uploaded_by_id`),
  CONSTRAINT `trueAlign_appraisala_appraisal_id_94991c7b_fk_trueAlign` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`),
  CONSTRAINT `trueAlign_appraisala_uploaded_by_id_d8366266_fk_auth_user` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_appraisalitem`
--

DROP TABLE IF EXISTS `trueAlign_appraisalitem`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_appraisalitem` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `category` varchar(20) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` longtext NOT NULL,
  `date` date DEFAULT NULL,
  `employee_rating` smallint unsigned DEFAULT NULL,
  `manager_rating` smallint unsigned DEFAULT NULL,
  `manager_comments` longtext NOT NULL,
  `appraisal_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisali_appraisal_id_bece5be9_fk_trueAlign` (`appraisal_id`),
  CONSTRAINT `trueAlign_appraisali_appraisal_id_bece5be9_fk_trueAlign` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`),
  CONSTRAINT `truealign_appraisalitem_chk_1` CHECK ((`employee_rating` >= 0)),
  CONSTRAINT `truealign_appraisalitem_chk_2` CHECK ((`manager_rating` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_appraisalworkflow`
--

DROP TABLE IF EXISTS `trueAlign_appraisalworkflow`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_appraisalworkflow` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `from_status` varchar(20) DEFAULT NULL,
  `to_status` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `comments` longtext NOT NULL,
  `action_by_id` int DEFAULT NULL,
  `appraisal_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_appraisalw_action_by_id_1c58029c_fk_auth_user` (`action_by_id`),
  KEY `trueAlign_appraisalw_appraisal_id_1184f4fa_fk_trueAlign` (`appraisal_id`),
  CONSTRAINT `trueAlign_appraisalw_action_by_id_1c58029c_fk_auth_user` FOREIGN KEY (`action_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_appraisalw_appraisal_id_1184f4fa_fk_trueAlign` FOREIGN KEY (`appraisal_id`) REFERENCES `trueAlign_appraisal` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_attendance`
--

DROP TABLE IF EXISTS `trueAlign_attendance`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_attendance` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `status` varchar(20) NOT NULL,
  `leave_type` varchar(50) DEFAULT NULL,
  `clock_in_time` datetime(6) DEFAULT NULL,
  `clock_out_time` datetime(6) DEFAULT NULL,
  `breaks` json NOT NULL,
  `total_hours` decimal(5,2) DEFAULT NULL,
  `expected_hours` decimal(5,2) DEFAULT NULL,
  `is_weekend` tinyint(1) NOT NULL,
  `is_holiday` tinyint(1) NOT NULL,
  `holiday_name` varchar(100) DEFAULT NULL,
  `location` varchar(50) NOT NULL,
  `ip_address` char(39) DEFAULT NULL,
  `device_info` json DEFAULT NULL,
  `late_minutes` int NOT NULL,
  `early_departure_minutes` int NOT NULL,
  `left_early` tinyint(1) NOT NULL,
  `last_modified` datetime(6) NOT NULL,
  `regularization_reason` longtext,
  `regularization_status` varchar(20) DEFAULT NULL,
  `requested_status` varchar(20) DEFAULT NULL,
  `total_sessions` int NOT NULL,
  `idle_time` bigint NOT NULL,
  `overtime_hours` decimal(5,2) NOT NULL,
  `is_overtime_approved` tinyint(1) NOT NULL,
  `original_clock_in_time` datetime(6) DEFAULT NULL,
  `original_clock_out_time` datetime(6) DEFAULT NULL,
  `original_status` varchar(20) DEFAULT NULL,
  `is_employee_notified` tinyint(1) NOT NULL,
  `is_hr_notified` tinyint(1) NOT NULL,
  `regularization_attempts` int NOT NULL,
  `last_regularization_date` datetime(6) DEFAULT NULL,
  `remarks` longtext,
  `is_half_day` tinyint(1) NOT NULL,
  `modified_by_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  `shift_id` bigint DEFAULT NULL,
  `first_session_id` char(32) DEFAULT NULL,
  `last_session_id` char(32) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_attendance_user_id_date_a85ef53e_uniq` (`user_id`,`date`),
  KEY `trueAlign_a_user_id_96129d_idx` (`user_id`,`date`),
  KEY `trueAlign_a_date_2bbee0_idx` (`date`,`status`),
  KEY `trueAlign_attendance_modified_by_id_153336d2_fk_auth_user_id` (`modified_by_id`),
  KEY `trueAlign_attendance_shift_id_72809dfc_fk_trueAlign` (`shift_id`),
  KEY `trueAlign_attendance_first_session_id_52623455_fk_trueAlign` (`first_session_id`),
  KEY `trueAlign_attendance_last_session_id_d6b14b24_fk_trueAlign` (`last_session_id`),
  KEY `trueAlign_a_regular_148211_idx` (`regularization_status`),
  KEY `trueAlign_a_clock_i_aa9175_idx` (`clock_in_time`),
  KEY `trueAlign_a_clock_o_88645b_idx` (`clock_out_time`),
  KEY `trueAlign_a_is_week_ebd761_idx` (`is_weekend`,`is_holiday`),
  CONSTRAINT `trueAlign_attendance_first_session_id_52623455_fk_trueAlign` FOREIGN KEY (`first_session_id`) REFERENCES `trueAlign_usersession` (`id`),
  CONSTRAINT `trueAlign_attendance_last_session_id_d6b14b24_fk_trueAlign` FOREIGN KEY (`last_session_id`) REFERENCES `trueAlign_usersession` (`id`),
  CONSTRAINT `trueAlign_attendance_modified_by_id_153336d2_fk_auth_user_id` FOREIGN KEY (`modified_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_attendance_shift_id_72809dfc_fk_trueAlign` FOREIGN KEY (`shift_id`) REFERENCES `trueAlign_shiftmaster` (`id`),
  CONSTRAINT `trueAlign_attendance_user_id_d8115814_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=47 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_bankaccount`
--

DROP TABLE IF EXISTS `trueAlign_bankaccount`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_bankaccount` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `account_number` varchar(50) NOT NULL,
  `bank_name` varchar(255) NOT NULL,
  `branch` varchar(255) NOT NULL,
  `ifsc_code` varchar(20) NOT NULL,
  `current_balance` decimal(15,2) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `account_number` (`account_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_bankpayment`
--

DROP TABLE IF EXISTS `trueAlign_bankpayment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_bankpayment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `payment_id` varchar(50) NOT NULL,
  `party_name` varchar(255) NOT NULL,
  `payment_reason` longtext NOT NULL,
  `amount` decimal(15,2) NOT NULL,
  `payment_date` date NOT NULL,
  `reference_number` varchar(100) DEFAULT NULL,
  `status` varchar(20) NOT NULL,
  `attachments` varchar(100) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approved_by_id` int DEFAULT NULL,
  `bank_account_id` bigint NOT NULL,
  `created_by_id` int NOT NULL,
  `verified_by_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `payment_id` (`payment_id`),
  KEY `trueAlign_bankpayment_approved_by_id_abc837c6_fk_auth_user_id` (`approved_by_id`),
  KEY `trueAlign_bankpaymen_bank_account_id_afe4c387_fk_trueAlign` (`bank_account_id`),
  KEY `trueAlign_bankpayment_created_by_id_45de88cd_fk_auth_user_id` (`created_by_id`),
  KEY `trueAlign_bankpayment_verified_by_id_00a8e697_fk_auth_user_id` (`verified_by_id`),
  CONSTRAINT `trueAlign_bankpaymen_bank_account_id_afe4c387_fk_trueAlign` FOREIGN KEY (`bank_account_id`) REFERENCES `trueAlign_bankaccount` (`id`),
  CONSTRAINT `trueAlign_bankpayment_approved_by_id_abc837c6_fk_auth_user_id` FOREIGN KEY (`approved_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_bankpayment_created_by_id_45de88cd_fk_auth_user_id` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_bankpayment_verified_by_id_00a8e697_fk_auth_user_id` FOREIGN KEY (`verified_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_break`
--

DROP TABLE IF EXISTS `trueAlign_break`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_break` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `break_type` varchar(50) NOT NULL,
  `start_time` datetime(6) NOT NULL,
  `end_time` datetime(6) DEFAULT NULL,
  `reason_for_extension` longtext,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_break_user_id_3fec0bd1_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_break_user_id_3fec0bd1_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_chartofaccount`
--

DROP TABLE IF EXISTS `trueAlign_chartofaccount`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_chartofaccount` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `code` varchar(20) NOT NULL,
  `account_type` varchar(20) NOT NULL,
  `description` longtext,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `parent_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `code` (`code`),
  KEY `trueAlign_chartofacc_parent_id_5142b86b_fk_trueAlign` (`parent_id`),
  CONSTRAINT `trueAlign_chartofacc_parent_id_5142b86b_fk_trueAlign` FOREIGN KEY (`parent_id`) REFERENCES `trueAlign_chartofaccount` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_chatgroup`
--

DROP TABLE IF EXISTS `trueAlign_chatgroup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_chatgroup` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` longtext NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `last_activity` datetime(6) NOT NULL,
  `created_by_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_chatgroup_created_by_id_cadff3d3_fk_auth_user_id` (`created_by_id`),
  CONSTRAINT `trueAlign_chatgroup_created_by_id_cadff3d3_fk_auth_user_id` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_clientinvoice`
--

DROP TABLE IF EXISTS `trueAlign_clientinvoice`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_clientinvoice` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `invoice_number` varchar(50) NOT NULL,
  `billing_model` varchar(20) NOT NULL,
  `billing_cycle_start` date NOT NULL,
  `billing_cycle_end` date NOT NULL,
  `order_count` int DEFAULT NULL,
  `fte_count` decimal(5,2) DEFAULT NULL,
  `rate` decimal(10,2) NOT NULL,
  `subtotal` decimal(15,2) NOT NULL,
  `tax_amount` decimal(15,2) NOT NULL,
  `discount` decimal(15,2) NOT NULL,
  `total_amount` decimal(15,2) NOT NULL,
  `status` varchar(20) NOT NULL,
  `due_date` date NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approved_by_id` int DEFAULT NULL,
  `client_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `invoice_number` (`invoice_number`),
  KEY `trueAlign_clientinvoice_approved_by_id_6b7a59f2_fk_auth_user_id` (`approved_by_id`),
  KEY `trueAlign_clientinvoice_client_id_5a3fd84f_fk_auth_user_id` (`client_id`),
  CONSTRAINT `trueAlign_clientinvoice_approved_by_id_6b7a59f2_fk_auth_user_id` FOREIGN KEY (`approved_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_clientinvoice_client_id_5a3fd84f_fk_auth_user_id` FOREIGN KEY (`client_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_clientparticipation`
--

DROP TABLE IF EXISTS `trueAlign_clientparticipation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_clientparticipation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `feedback` longtext,
  `approved` tinyint(1) NOT NULL,
  `date` datetime(6) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `client_id` int NOT NULL,
  `project_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_clientparticipation_client_id_1fd72bf4_fk_auth_user_id` (`client_id`),
  KEY `trueAlign_clientpart_project_id_df9bb4fe_fk_trueAlign` (`project_id`),
  CONSTRAINT `trueAlign_clientpart_project_id_df9bb4fe_fk_trueAlign` FOREIGN KEY (`project_id`) REFERENCES `trueAlign_project` (`id`),
  CONSTRAINT `trueAlign_clientparticipation_client_id_1fd72bf4_fk_auth_user_id` FOREIGN KEY (`client_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_clientprofile`
--

DROP TABLE IF EXISTS `trueAlign_clientprofile`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_clientprofile` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `company_name` varchar(100) NOT NULL,
  `contact_info` longtext NOT NULL,
  `industry_type` varchar(100) NOT NULL,
  `company_size` varchar(50) NOT NULL,
  `registration_number` varchar(50) DEFAULT NULL,
  `business_location` varchar(255) DEFAULT NULL,
  `website_url` varchar(200) DEFAULT NULL,
  `year_established` int DEFAULT NULL,
  `annual_revenue` decimal(15,2) DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`),
  CONSTRAINT `trueAlign_clientprofile_user_id_15496a93_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `truealign_comment_attachment`
--

DROP TABLE IF EXISTS `truealign_comment_attachment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `truealign_comment_attachment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `original_filename` varchar(255) NOT NULL,
  `formatted_filename` varchar(255) NOT NULL,
  `file_size` int unsigned NOT NULL,
  `content_type` varchar(100) DEFAULT NULL,
  `uploaded_at` datetime(6) NOT NULL,
  `description` longtext,
  `is_active` tinyint(1) NOT NULL,
  `uploaded_by_id` int NOT NULL,
  `ticket_activity_id` bigint NOT NULL,
  `comment_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `truealign_comment_at_uploaded_by_id_5f77739f_fk_auth_user` (`uploaded_by_id`),
  KEY `truealign_comment_at_ticket_activity_id_3c828dc4_fk_trueAlign` (`ticket_activity_id`),
  KEY `truealign_comment_at_comment_id_ea271478_fk_trueAlign` (`comment_id`),
  CONSTRAINT `truealign_comment_at_comment_id_ea271478_fk_trueAlign` FOREIGN KEY (`comment_id`) REFERENCES `trueAlign_ticketcomment` (`id`),
  CONSTRAINT `truealign_comment_at_ticket_activity_id_3c828dc4_fk_trueAlign` FOREIGN KEY (`ticket_activity_id`) REFERENCES `trueAlign_ticketactivity` (`id`),
  CONSTRAINT `truealign_comment_at_uploaded_by_id_5f77739f_fk_auth_user` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `truealign_comment_attachment_chk_1` CHECK ((`file_size` >= 0))
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_compoffrequest`
--

DROP TABLE IF EXISTS `trueAlign_compoffrequest`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_compoffrequest` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `worked_date` date NOT NULL,
  `reason` longtext NOT NULL,
  `hours_worked` decimal(4,1) NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approver_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_compoffrequest_approver_id_3638a657_fk_auth_user_id` (`approver_id`),
  KEY `trueAlign_compoffrequest_user_id_285921bf_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_compoffrequest_approver_id_3638a657_fk_auth_user_id` FOREIGN KEY (`approver_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_compoffrequest_user_id_285921bf_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_conferencebooking`
--

DROP TABLE IF EXISTS `trueAlign_conferencebooking`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_conferencebooking` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `purpose` varchar(255) NOT NULL,
  `description` longtext NOT NULL,
  `start_time` datetime(6) NOT NULL,
  `end_time` datetime(6) NOT NULL,
  `attendees_count` int unsigned NOT NULL,
  `external_attendees` int unsigned NOT NULL,
  `meeting_type` varchar(50) NOT NULL,
  `priority` varchar(10) NOT NULL,
  `status` varchar(10) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `cancelled_at` datetime(6) DEFAULT NULL,
  `cancellation_reason` longtext NOT NULL,
  `approved_at` datetime(6) DEFAULT NULL,
  `recurring_pattern` varchar(20) NOT NULL,
  `checked_in` tinyint(1) NOT NULL,
  `checked_in_at` datetime(6) DEFAULT NULL,
  `no_show` tinyint(1) NOT NULL,
  `hourly_rate` decimal(8,2) NOT NULL,
  `total_cost` decimal(10,2) NOT NULL,
  `approved_by_id` int DEFAULT NULL,
  `booked_by_id` int NOT NULL,
  `cancelled_by_id` int DEFAULT NULL,
  `parent_booking_id` bigint DEFAULT NULL,
  `room_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_conference_approved_by_id_bfa6742b_fk_auth_user` (`approved_by_id`),
  KEY `trueAlign_conference_cancelled_by_id_6ef82365_fk_auth_user` (`cancelled_by_id`),
  KEY `trueAlign_conference_parent_booking_id_aaa1ee2b_fk_trueAlign` (`parent_booking_id`),
  KEY `trueAlign_c_room_id_0ca4c5_idx` (`room_id`,`start_time`,`status`),
  KEY `trueAlign_c_booked__c5f6f2_idx` (`booked_by_id`,`status`),
  KEY `trueAlign_c_start_t_9c696e_idx` (`start_time`,`end_time`),
  KEY `trueAlign_c_status_1d7a30_idx` (`status`,`created_at`),
  CONSTRAINT `trueAlign_conference_approved_by_id_bfa6742b_fk_auth_user` FOREIGN KEY (`approved_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_conference_booked_by_id_203b2396_fk_auth_user` FOREIGN KEY (`booked_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_conference_cancelled_by_id_6ef82365_fk_auth_user` FOREIGN KEY (`cancelled_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_conference_parent_booking_id_aaa1ee2b_fk_trueAlign` FOREIGN KEY (`parent_booking_id`) REFERENCES `trueAlign_conferencebooking` (`id`),
  CONSTRAINT `trueAlign_conference_room_id_9384027c_fk_trueAlign` FOREIGN KEY (`room_id`) REFERENCES `trueAlign_room` (`id`),
  CONSTRAINT `end_time_after_start_time` CHECK ((`end_time` > `start_time`)),
  CONSTRAINT `minimum_one_attendee` CHECK ((`attendees_count` >= 1)),
  CONSTRAINT `truealign_conferencebooking_chk_1` CHECK ((`attendees_count` >= 0)),
  CONSTRAINT `truealign_conferencebooking_chk_2` CHECK ((`external_attendees` >= 0))
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_dailyexpense`
--

DROP TABLE IF EXISTS `trueAlign_dailyexpense`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_dailyexpense` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `expense_id` varchar(50) NOT NULL,
  `date` date NOT NULL,
  `category` varchar(20) NOT NULL,
  `description` longtext NOT NULL,
  `amount` decimal(15,2) NOT NULL,
  `status` varchar(20) NOT NULL,
  `attachments` varchar(100) DEFAULT NULL,
  `approved_at` datetime(6) DEFAULT NULL,
  `rejection_reason` longtext,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approved_by_id` int DEFAULT NULL,
  `paid_by_id` int NOT NULL,
  `department_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `expense_id` (`expense_id`),
  KEY `trueAlign_dailyexpense_approved_by_id_1b794b7a_fk_auth_user_id` (`approved_by_id`),
  KEY `trueAlign_dailyexpense_paid_by_id_d853c4c2_fk_auth_user_id` (`paid_by_id`),
  KEY `trueAlign_dailyexpen_department_id_813bf2e4_fk_trueAlign` (`department_id`),
  CONSTRAINT `trueAlign_dailyexpen_department_id_813bf2e4_fk_trueAlign` FOREIGN KEY (`department_id`) REFERENCES `trueAlign_department` (`id`),
  CONSTRAINT `trueAlign_dailyexpense_approved_by_id_1b794b7a_fk_auth_user_id` FOREIGN KEY (`approved_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_dailyexpense_paid_by_id_d853c4c2_fk_auth_user_id` FOREIGN KEY (`paid_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_department`
--

DROP TABLE IF EXISTS `trueAlign_department`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_department` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_directmessage`
--

DROP TABLE IF EXISTS `trueAlign_directmessage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_directmessage` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `last_activity` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_directmessage_participants`
--

DROP TABLE IF EXISTS `trueAlign_directmessage_participants`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_directmessage_participants` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `directmessage_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_directmessage__directmessage_id_user_id_afc6ce73_uniq` (`directmessage_id`,`user_id`),
  KEY `trueAlign_directmess_user_id_5ffe7606_fk_auth_user` (`user_id`),
  CONSTRAINT `trueAlign_directmess_directmessage_id_baf1e9df_fk_trueAlign` FOREIGN KEY (`directmessage_id`) REFERENCES `trueAlign_directmessage` (`id`),
  CONSTRAINT `trueAlign_directmess_user_id_5ffe7606_fk_auth_user` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_failedloginattempt`
--

DROP TABLE IF EXISTS `trueAlign_failedloginattempt`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_failedloginattempt` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `attempt_time` datetime(6) NOT NULL,
  `ip_address` char(39) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_failedloginattempt_user_id_73dde8ed_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_failedloginattempt_user_id_73dde8ed_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_featureusage`
--

DROP TABLE IF EXISTS `trueAlign_featureusage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_featureusage` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `feature_name` varchar(100) NOT NULL,
  `usage_count` int unsigned NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `truealign_featureusage_chk_1` CHECK ((`usage_count` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_financialparameter`
--

DROP TABLE IF EXISTS `trueAlign_financialparameter`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_financialparameter` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `key` varchar(100) NOT NULL,
  `name` varchar(255) NOT NULL,
  `category` varchar(20) NOT NULL,
  `description` longtext,
  `value` longtext NOT NULL,
  `value_type` varchar(20) NOT NULL,
  `is_global` tinyint(1) NOT NULL,
  `object_id` int unsigned DEFAULT NULL,
  `valid_from` date NOT NULL,
  `valid_to` date DEFAULT NULL,
  `fiscal_year` varchar(9) DEFAULT NULL,
  `fiscal_quarter` varchar(6) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `is_approved` tinyint(1) NOT NULL,
  `approved_at` datetime(6) DEFAULT NULL,
  `approved_by_id` int DEFAULT NULL,
  `content_type_id` int DEFAULT NULL,
  `created_by_id` int NOT NULL,
  `updated_by_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_financialparam_key_content_type_id_obje_15cd89d9_uniq` (`key`,`content_type_id`,`object_id`,`valid_from`),
  KEY `trueAlign_financialp_approved_by_id_4f695c5f_fk_auth_user` (`approved_by_id`),
  KEY `trueAlign_financialp_created_by_id_916fee41_fk_auth_user` (`created_by_id`),
  KEY `trueAlign_financialp_updated_by_id_aaed065a_fk_auth_user` (`updated_by_id`),
  KEY `trueAlign_financialparameter_key_87320449` (`key`),
  KEY `fin_param_key_idx` (`key`),
  KEY `fin_param_cat_idx` (`category`),
  KEY `fin_param_entity_idx` (`content_type_id`,`object_id`),
  KEY `fin_param_validity_idx` (`valid_from`,`valid_to`),
  KEY `fin_param_fiscal_yr_idx` (`fiscal_year`),
  CONSTRAINT `trueAlign_financialp_approved_by_id_4f695c5f_fk_auth_user` FOREIGN KEY (`approved_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_financialp_content_type_id_f67dba46_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `trueAlign_financialp_created_by_id_916fee41_fk_auth_user` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_financialp_updated_by_id_aaed065a_fk_auth_user` FOREIGN KEY (`updated_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `truealign_financialparameter_chk_1` CHECK ((`object_id` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_gameicon`
--

DROP TABLE IF EXISTS `trueAlign_gameicon`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_gameicon` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `symbol` varchar(10) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `created_by_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_gameicon_created_by_id_de607bf7_fk_auth_user_id` (`created_by_id`),
  CONSTRAINT `trueAlign_gameicon_created_by_id_de607bf7_fk_auth_user_id` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_gamespectator`
--

DROP TABLE IF EXISTS `trueAlign_gamespectator`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_gamespectator` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `joined_at` datetime(6) NOT NULL,
  `user_id` int NOT NULL,
  `game_id` char(32) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_gamespectator_game_id_user_id_6089d676_uniq` (`game_id`,`user_id`),
  KEY `trueAlign_gamespectator_user_id_04c403ff_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_gamespecta_game_id_1a93c211_fk_trueAlign` FOREIGN KEY (`game_id`) REFERENCES `trueAlign_tictactoegame` (`id`),
  CONSTRAINT `trueAlign_gamespectator_user_id_04c403ff_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_globalupdate`
--

DROP TABLE IF EXISTS `trueAlign_globalupdate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_globalupdate` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `description` longtext NOT NULL,
  `status` varchar(20) NOT NULL,
  `scheduled_date` datetime(6) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `managed_by_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_globalupdate_managed_by_id_4a1205f1_fk_auth_user_id` (`managed_by_id`),
  CONSTRAINT `trueAlign_globalupdate_managed_by_id_4a1205f1_fk_auth_user_id` FOREIGN KEY (`managed_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_groupmember`
--

DROP TABLE IF EXISTS `trueAlign_groupmember`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_groupmember` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `role` varchar(20) NOT NULL,
  `joined_at` datetime(6) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `last_seen` datetime(6) NOT NULL,
  `typing_status` datetime(6) DEFAULT NULL,
  `group_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_groupmember_group_id_user_id_6d0c5169_uniq` (`group_id`,`user_id`),
  KEY `trueAlign_groupmember_user_id_a5e7a384_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_groupmembe_group_id_5890f9dd_fk_trueAlign` FOREIGN KEY (`group_id`) REFERENCES `trueAlign_chatgroup` (`id`),
  CONSTRAINT `trueAlign_groupmember_user_id_a5e7a384_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_holiday`
--

DROP TABLE IF EXISTS `trueAlign_holiday`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_holiday` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `date` date NOT NULL,
  `recurring_yearly` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_leaveallocation`
--

DROP TABLE IF EXISTS `trueAlign_leaveallocation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_leaveallocation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `annual_days` decimal(5,1) NOT NULL,
  `carry_forward_limit` decimal(5,1) NOT NULL,
  `max_consecutive_days` int NOT NULL,
  `advance_notice_days` int NOT NULL,
  `policy_id` bigint NOT NULL,
  `leave_type_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_leaveallocation_policy_id_leave_type_id_566797b5_uniq` (`policy_id`,`leave_type_id`),
  KEY `trueAlign_leavealloc_leave_type_id_a50a7eb3_fk_trueAlign` (`leave_type_id`),
  CONSTRAINT `trueAlign_leavealloc_leave_type_id_a50a7eb3_fk_trueAlign` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`),
  CONSTRAINT `trueAlign_leavealloc_policy_id_9dbff9f8_fk_trueAlign` FOREIGN KEY (`policy_id`) REFERENCES `trueAlign_leavepolicy` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_leavepolicy`
--

DROP TABLE IF EXISTS `trueAlign_leavepolicy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_leavepolicy` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `group_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_leavepolicy_group_id_09217772_fk_auth_group_id` (`group_id`),
  CONSTRAINT `trueAlign_leavepolicy_group_id_09217772_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_leaverequest`
--

DROP TABLE IF EXISTS `trueAlign_leaverequest`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_leaverequest` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `start_date` date NOT NULL,
  `end_date` date NOT NULL,
  `half_day` tinyint(1) NOT NULL,
  `leave_days` decimal(5,1) NOT NULL,
  `reason` longtext NOT NULL,
  `status` varchar(20) NOT NULL,
  `rejection_reason` longtext,
  `suggested_dates` json DEFAULT NULL,
  `documentation` varchar(100) DEFAULT NULL,
  `is_retroactive` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `approver_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  `leave_type_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_leaverequest_approver_id_0a10ae72_fk_auth_user_id` (`approver_id`),
  KEY `trueAlign_leavereque_leave_type_id_71691a23_fk_trueAlign` (`leave_type_id`),
  KEY `trueAlign_l_user_id_e2aa7e_idx` (`user_id`,`start_date`,`status`),
  CONSTRAINT `trueAlign_leavereque_leave_type_id_71691a23_fk_trueAlign` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`),
  CONSTRAINT `trueAlign_leaverequest_approver_id_0a10ae72_fk_auth_user_id` FOREIGN KEY (`approver_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_leaverequest_user_id_e0803633_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_leavetype`
--

DROP TABLE IF EXISTS `trueAlign_leavetype`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_leavetype` (
  `id` bigint NOT NULL AUTO_INCREMENT,
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
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_message`
--

DROP TABLE IF EXISTS `trueAlign_message`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_message` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `content` longtext NOT NULL,
  `message_type` varchar(20) NOT NULL,
  `file_attachment` varchar(100) DEFAULT NULL,
  `sent_at` datetime(6) NOT NULL,
  `edited_at` datetime(6) DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `deleted_at` datetime(6) DEFAULT NULL,
  `direct_message_id` bigint DEFAULT NULL,
  `group_id` bigint DEFAULT NULL,
  `sender_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_m_group_i_fbe0af_idx` (`group_id`,`sent_at`),
  KEY `trueAlign_m_direct__968179_idx` (`direct_message_id`,`sent_at`),
  KEY `trueAlign_m_sender__4a2cd7_idx` (`sender_id`,`sent_at`),
  CONSTRAINT `trueAlign_message_direct_message_id_383412c9_fk_trueAlign` FOREIGN KEY (`direct_message_id`) REFERENCES `trueAlign_directmessage` (`id`),
  CONSTRAINT `trueAlign_message_group_id_67aabac1_fk_trueAlign_chatgroup_id` FOREIGN KEY (`group_id`) REFERENCES `trueAlign_chatgroup` (`id`),
  CONSTRAINT `trueAlign_message_sender_id_54de5606_fk_auth_user_id` FOREIGN KEY (`sender_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_messageread`
--

DROP TABLE IF EXISTS `trueAlign_messageread`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_messageread` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `read_at` datetime(6) DEFAULT NULL,
  `message_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_messageread_message_id_user_id_7a0fda8a_uniq` (`message_id`,`user_id`),
  KEY `trueAlign_m_user_id_339db3_idx` (`user_id`,`read_at`),
  KEY `trueAlign_m_message_bf6b93_idx` (`message_id`,`user_id`),
  CONSTRAINT `trueAlign_messagerea_message_id_fb7bec75_fk_trueAlign` FOREIGN KEY (`message_id`) REFERENCES `trueAlign_message` (`id`),
  CONSTRAINT `trueAlign_messageread_user_id_a4198e92_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_notification`
--

DROP TABLE IF EXISTS `trueAlign_notification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_notification` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `message` varchar(255) NOT NULL,
  `notification_type` varchar(20) NOT NULL,
  `is_read` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `recipient_id` int NOT NULL,
  `game_id` char(32) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_notification_recipient_id_58ebd476_fk_auth_user_id` (`recipient_id`),
  KEY `trueAlign_notificati_game_id_68cdfb3f_fk_trueAlign` (`game_id`),
  CONSTRAINT `trueAlign_notificati_game_id_68cdfb3f_fk_trueAlign` FOREIGN KEY (`game_id`) REFERENCES `trueAlign_tictactoegame` (`id`),
  CONSTRAINT `trueAlign_notification_recipient_id_58ebd476_fk_auth_user_id` FOREIGN KEY (`recipient_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_officelocation`
--

DROP TABLE IF EXISTS `trueAlign_officelocation`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_officelocation` (
  `id` bigint NOT NULL AUTO_INCREMENT,
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
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_passwordchange`
--

DROP TABLE IF EXISTS `trueAlign_passwordchange`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_passwordchange` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `old_password` varchar(255) NOT NULL,
  `new_password` varchar(255) NOT NULL,
  `change_time` datetime(6) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_passwordchange_user_id_6b19a58c_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_passwordchange_user_id_6b19a58c_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_playerstats`
--

DROP TABLE IF EXISTS `trueAlign_playerstats`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_playerstats` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `games_played` int NOT NULL,
  `games_won` int NOT NULL,
  `games_lost` int NOT NULL,
  `games_drawn` int NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`),
  CONSTRAINT `trueAlign_playerstats_user_id_c889f3e4_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_presence`
--

DROP TABLE IF EXISTS `trueAlign_presence`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_presence` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `status` varchar(20) NOT NULL,
  `marked_at` datetime(6) NOT NULL,
  `notes` longtext,
  `marked_by_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_presence_per_user_per_day` (`user_id`,`date`),
  KEY `trueAlign_presence_marked_by_id_8fe8584c_fk_auth_user_id` (`marked_by_id`),
  CONSTRAINT `trueAlign_presence_marked_by_id_8fe8584c_fk_auth_user_id` FOREIGN KEY (`marked_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_presence_user_id_0654f696_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_project`
--

DROP TABLE IF EXISTS `trueAlign_project`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_project` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` longtext NOT NULL,
  `start_date` date NOT NULL,
  `deadline` date NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `total_value` decimal(12,2) NOT NULL,
  `delivery_format` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_project_clients`
--

DROP TABLE IF EXISTS `trueAlign_project_clients`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_project_clients` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `project_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_project_clients_project_id_user_id_75efdce2_uniq` (`project_id`,`user_id`),
  KEY `trueAlign_project_clients_user_id_96832104_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_project_cl_project_id_769e0061_fk_trueAlign` FOREIGN KEY (`project_id`) REFERENCES `trueAlign_project` (`id`),
  CONSTRAINT `trueAlign_project_clients_user_id_96832104_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_projectassignment`
--

DROP TABLE IF EXISTS `trueAlign_projectassignment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_projectassignment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `assigned_date` date NOT NULL,
  `hours_worked` double NOT NULL,
  `role_in_project` varchar(50) NOT NULL,
  `end_date` date DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `project_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_projectass_project_id_9d5d9376_fk_trueAlign` (`project_id`),
  KEY `trueAlign_projectassignment_user_id_88d7b9a9_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_projectass_project_id_9d5d9376_fk_trueAlign` FOREIGN KEY (`project_id`) REFERENCES `trueAlign_project` (`id`),
  CONSTRAINT `trueAlign_projectassignment_user_id_88d7b9a9_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_projectupdate`
--

DROP TABLE IF EXISTS `trueAlign_projectupdate`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_projectupdate` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `title` varchar(200) NOT NULL,
  `description` longtext NOT NULL,
  `status` varchar(20) NOT NULL,
  `scheduled_date` datetime(6) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `created_by_id` int NOT NULL,
  `project_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_projectupdate_created_by_id_6dc25910_fk_auth_user_id` (`created_by_id`),
  KEY `trueAlign_projectupd_project_id_b2208943_fk_trueAlign` (`project_id`),
  CONSTRAINT `trueAlign_projectupd_project_id_b2208943_fk_trueAlign` FOREIGN KEY (`project_id`) REFERENCES `trueAlign_project` (`id`),
  CONSTRAINT `trueAlign_projectupdate_created_by_id_6dc25910_fk_auth_user_id` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_roleassignmentaudit`
--

DROP TABLE IF EXISTS `trueAlign_roleassignmentaudit`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_roleassignmentaudit` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `role_assigned` varchar(50) NOT NULL,
  `assigned_date` datetime(6) NOT NULL,
  `assigned_by_id` int NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_roleassign_assigned_by_id_03fdc5d2_fk_auth_user` (`assigned_by_id`),
  KEY `trueAlign_roleassignmentaudit_user_id_e8bbd4f3_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_roleassign_assigned_by_id_03fdc5d2_fk_auth_user` FOREIGN KEY (`assigned_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_roleassignmentaudit_user_id_e8bbd4f3_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_room`
--

DROP TABLE IF EXISTS `trueAlign_room`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_room` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `room_type` varchar(15) NOT NULL,
  `capacity` int unsigned NOT NULL,
  `location` varchar(100) NOT NULL,
  `facilities` longtext NOT NULL,
  `status` varchar(12) NOT NULL,
  `hourly_rate` decimal(8,2) NOT NULL,
  `description` longtext NOT NULL,
  `image` varchar(100) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `total_bookings` int unsigned NOT NULL,
  `total_hours_booked` decimal(10,2) NOT NULL,
  `office_location_id` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_room_name_per_location` (`name`,`office_location_id`),
  KEY `trueAlign_room_office_location_id_50bf192a_fk_trueAlign` (`office_location_id`),
  CONSTRAINT `trueAlign_room_office_location_id_50bf192a_fk_trueAlign` FOREIGN KEY (`office_location_id`) REFERENCES `trueAlign_officelocation` (`id`),
  CONSTRAINT `truealign_room_chk_1` CHECK ((`capacity` >= 0)),
  CONSTRAINT `truealign_room_chk_2` CHECK ((`total_bookings` >= 0))
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_sessionactivity`
--

DROP TABLE IF EXISTS `trueAlign_sessionactivity`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_sessionactivity` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) NOT NULL,
  `activity_time` datetime(6) NOT NULL,
  `activity_type` varchar(20) NOT NULL,
  `activity_data` json NOT NULL,
  `url` varchar(2000) DEFAULT NULL,
  `title` varchar(500) DEFAULT NULL,
  `location_latitude` double DEFAULT NULL,
  `location_longitude` double DEFAULT NULL,
  `location_accuracy` double DEFAULT NULL,
  `productivity_score` double DEFAULT NULL,
  `engagement_score` double DEFAULT NULL,
  `session_id` char(32) NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `session_activity_type_idx` (`session_id`,`activity_type`),
  KEY `user_activity_time_idx` (`user_id`,`activity_time`),
  KEY `activity_created_at_idx` (`created_at`),
  KEY `type_time_idx` (`activity_type`,`activity_time`),
  CONSTRAINT `trueAlign_sessionact_session_id_ba699e9e_fk_trueAlign` FOREIGN KEY (`session_id`) REFERENCES `trueAlign_usersession` (`id`),
  CONSTRAINT `trueAlign_sessionactivity_user_id_720b825d_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=648 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_shiftassignment`
--

DROP TABLE IF EXISTS `trueAlign_shiftassignment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_shiftassignment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `effective_from` date NOT NULL,
  `effective_to` date DEFAULT NULL,
  `is_current` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `user_id` int NOT NULL,
  `shift_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_s_user_id_f0dd6b_idx` (`user_id`,`effective_from`),
  KEY `trueAlign_s_is_curr_9ea5e0_idx` (`is_current`),
  KEY `trueAlign_shiftassig_shift_id_97eae7b7_fk_trueAlign` (`shift_id`),
  CONSTRAINT `trueAlign_shiftassig_shift_id_97eae7b7_fk_trueAlign` FOREIGN KEY (`shift_id`) REFERENCES `trueAlign_shiftmaster` (`id`),
  CONSTRAINT `trueAlign_shiftassignment_user_id_24ba47d7_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_shiftmaster`
--

DROP TABLE IF EXISTS `trueAlign_shiftmaster`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_shiftmaster` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `start_time` time(6) NOT NULL,
  `end_time` time(6) NOT NULL,
  `shift_duration` decimal(5,2) NOT NULL,
  `break_duration` bigint NOT NULL,
  `grace_period` bigint NOT NULL,
  `work_days` varchar(20) NOT NULL,
  `custom_work_days` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_statuslog`
--

DROP TABLE IF EXISTS `trueAlign_statuslog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_statuslog` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `old_status` varchar(30) NOT NULL,
  `new_status` varchar(30) NOT NULL,
  `changed_at` datetime(6) NOT NULL,
  `changed_by_id` int DEFAULT NULL,
  `ticket_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_statuslog_changed_by_id_5eec04f0_fk_auth_user_id` (`changed_by_id`),
  KEY `trueAlign_statuslog_ticket_id_1f656ca2_fk_trueAlign_support_id` (`ticket_id`),
  CONSTRAINT `trueAlign_statuslog_changed_by_id_5eec04f0_fk_auth_user_id` FOREIGN KEY (`changed_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_statuslog_ticket_id_1f656ca2_fk_trueAlign_support_id` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_subscription`
--

DROP TABLE IF EXISTS `trueAlign_subscription`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_subscription` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `vendor` varchar(255) NOT NULL,
  `subscription_type` varchar(100) NOT NULL,
  `amount` decimal(15,2) NOT NULL,
  `frequency` varchar(20) NOT NULL,
  `start_date` date NOT NULL,
  `next_payment_date` date NOT NULL,
  `auto_renew` tinyint(1) NOT NULL,
  `status` varchar(20) NOT NULL,
  `alert_days` int NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_support`
--

DROP TABLE IF EXISTS `trueAlign_support`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_support` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `ticket_id` varchar(100) NOT NULL,
  `issue_type` varchar(50) NOT NULL,
  `subject` varchar(200) NOT NULL,
  `description` longtext NOT NULL,
  `status` varchar(30) NOT NULL,
  `priority` varchar(20) NOT NULL,
  `assigned_group` varchar(50) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `resolved_at` datetime(6) DEFAULT NULL,
  `due_date` datetime(6) DEFAULT NULL,
  `department` varchar(100) NOT NULL,
  `location` varchar(100) NOT NULL,
  `asset_id` varchar(50) NOT NULL,
  `sla_breach` tinyint(1) NOT NULL,
  `sla_target_date` datetime(6) DEFAULT NULL,
  `sla_status` varchar(20) DEFAULT NULL,
  `resolution_summary` longtext NOT NULL,
  `resolution_time` bigint DEFAULT NULL,
  `response_time` bigint DEFAULT NULL,
  `time_to_close` bigint DEFAULT NULL,
  `escalation_level` smallint unsigned NOT NULL,
  `reopen_count` smallint unsigned NOT NULL,
  `satisfaction_rating` int DEFAULT NULL,
  `feedback` longtext NOT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `assigned_to_user_id` int DEFAULT NULL,
  `parent_ticket_id` bigint DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ticket_id` (`ticket_id`),
  KEY `trueAlign_s_ticket__676519_idx` (`ticket_id`),
  KEY `trueAlign_s_status_69e152_idx` (`status`),
  KEY `trueAlign_s_created_577e4c_idx` (`created_at`),
  KEY `trueAlign_s_user_id_6fec4b_idx` (`user_id`),
  KEY `trueAlign_s_due_dat_c6bcc3_idx` (`due_date`),
  KEY `trueAlign_s_resolve_70ea27_idx` (`resolved_at`),
  KEY `trueAlign_s_priorit_933347_idx` (`priority`),
  KEY `trueAlign_support_assigned_to_user_id_5c14c839_fk_auth_user_id` (`assigned_to_user_id`),
  KEY `trueAlign_support_parent_ticket_id_81413f37_fk_trueAlign` (`parent_ticket_id`),
  CONSTRAINT `trueAlign_support_assigned_to_user_id_5c14c839_fk_auth_user_id` FOREIGN KEY (`assigned_to_user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_support_parent_ticket_id_81413f37_fk_trueAlign` FOREIGN KEY (`parent_ticket_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_support_user_id_be914a5a_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `truealign_support_chk_1` CHECK ((`escalation_level` >= 0)),
  CONSTRAINT `truealign_support_chk_2` CHECK ((`reopen_count` >= 0))
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_support_cc_users`
--

DROP TABLE IF EXISTS `trueAlign_support_cc_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_support_cc_users` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `support_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_support_cc_users_support_id_user_id_db2daa68_uniq` (`support_id`,`user_id`),
  KEY `trueAlign_support_cc_users_user_id_b2fd7409_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_support_cc_support_id_4d82f852_fk_trueAlign` FOREIGN KEY (`support_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_support_cc_users_user_id_b2fd7409_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_systemerror`
--

DROP TABLE IF EXISTS `trueAlign_systemerror`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_systemerror` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `error_message` longtext NOT NULL,
  `error_time` datetime(6) NOT NULL,
  `resolved` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_systemusage`
--

DROP TABLE IF EXISTS `trueAlign_systemusage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_systemusage` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `peak_time_start` datetime(6) NOT NULL,
  `peak_time_end` datetime(6) NOT NULL,
  `active_users_count` int unsigned NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `truealign_systemusage_chk_1` CHECK ((`active_users_count` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_ticketactivity`
--

DROP TABLE IF EXISTS `trueAlign_ticketactivity`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_ticketactivity` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `action` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `details` longtext NOT NULL,
  `ticket_id` bigint NOT NULL,
  `user_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketacti_ticket_id_812010d6_fk_trueAlign` (`ticket_id`),
  KEY `trueAlign_ticketactivity_user_id_39616151_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_ticketacti_ticket_id_812010d6_fk_trueAlign` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_ticketactivity_user_id_39616151_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_ticketattachment`
--

DROP TABLE IF EXISTS `trueAlign_ticketattachment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_ticketattachment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `file` varchar(100) NOT NULL,
  `uploaded_at` datetime(6) NOT NULL,
  `description` varchar(255) NOT NULL,
  `original_filename` varchar(255) NOT NULL,
  `formatted_filename` varchar(255) NOT NULL,
  `file_size` int unsigned NOT NULL,
  `file_type` varchar(100) NOT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `ticket_id` bigint NOT NULL,
  `uploaded_by_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketatta_ticket_id_84e3681b_fk_trueAlign` (`ticket_id`),
  KEY `trueAlign_ticketatta_uploaded_by_id_8bca47bb_fk_auth_user` (`uploaded_by_id`),
  CONSTRAINT `trueAlign_ticketatta_ticket_id_84e3681b_fk_trueAlign` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_ticketatta_uploaded_by_id_8bca47bb_fk_auth_user` FOREIGN KEY (`uploaded_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `truealign_ticketattachment_chk_1` CHECK ((`file_size` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_ticketcomment`
--

DROP TABLE IF EXISTS `trueAlign_ticketcomment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_ticketcomment` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `content` longtext NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `is_internal` tinyint(1) NOT NULL,
  `ticket_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_ticketcomm_ticket_id_dc0044c9_fk_trueAlign` (`ticket_id`),
  KEY `trueAlign_ticketcomment_user_id_6c79e01c_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_ticketcomm_ticket_id_dc0044c9_fk_trueAlign` FOREIGN KEY (`ticket_id`) REFERENCES `trueAlign_support` (`id`),
  CONSTRAINT `trueAlign_ticketcomment_user_id_6c79e01c_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_tictactoegame`
--

DROP TABLE IF EXISTS `trueAlign_tictactoegame`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_tictactoegame` (
  `id` char(32) NOT NULL,
  `board` varchar(9) NOT NULL,
  `status` varchar(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `last_move_at` datetime(6) NOT NULL,
  `allow_spectators` tinyint(1) NOT NULL,
  `creator_id` int NOT NULL,
  `creator_icon_id` bigint DEFAULT NULL,
  `current_turn_id` int DEFAULT NULL,
  `opponent_id` int NOT NULL,
  `opponent_icon_id` bigint DEFAULT NULL,
  `winner_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_tictactoegame_creator_id_1cc20ce1_fk_auth_user_id` (`creator_id`),
  KEY `trueAlign_tictactoeg_creator_icon_id_3a35e004_fk_trueAlign` (`creator_icon_id`),
  KEY `trueAlign_tictactoegame_current_turn_id_380a1e08_fk_auth_user_id` (`current_turn_id`),
  KEY `trueAlign_tictactoegame_opponent_id_2488dc03_fk_auth_user_id` (`opponent_id`),
  KEY `trueAlign_tictactoeg_opponent_icon_id_437226f2_fk_trueAlign` (`opponent_icon_id`),
  KEY `trueAlign_tictactoegame_winner_id_004fba22_fk_auth_user_id` (`winner_id`),
  CONSTRAINT `trueAlign_tictactoeg_creator_icon_id_3a35e004_fk_trueAlign` FOREIGN KEY (`creator_icon_id`) REFERENCES `trueAlign_gameicon` (`id`),
  CONSTRAINT `trueAlign_tictactoeg_opponent_icon_id_437226f2_fk_trueAlign` FOREIGN KEY (`opponent_icon_id`) REFERENCES `trueAlign_gameicon` (`id`),
  CONSTRAINT `trueAlign_tictactoegame_creator_id_1cc20ce1_fk_auth_user_id` FOREIGN KEY (`creator_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_tictactoegame_current_turn_id_380a1e08_fk_auth_user_id` FOREIGN KEY (`current_turn_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_tictactoegame_opponent_id_2488dc03_fk_auth_user_id` FOREIGN KEY (`opponent_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_tictactoegame_winner_id_004fba22_fk_auth_user_id` FOREIGN KEY (`winner_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_timesheet`
--

DROP TABLE IF EXISTS `trueAlign_timesheet`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_timesheet` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `week_start_date` date NOT NULL,
  `task_name` varchar(255) NOT NULL,
  `task_description` longtext NOT NULL,
  `hours` double NOT NULL,
  `adjusted_hours` double DEFAULT NULL,
  `approval_status` varchar(25) NOT NULL,
  `rejection_reason` varchar(30) DEFAULT NULL,
  `manager_comments` longtext,
  `submitted_at` datetime(6) NOT NULL,
  `reviewed_at` datetime(6) DEFAULT NULL,
  `original_submission_id` int DEFAULT NULL,
  `version` int unsigned NOT NULL,
  `project_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_timesheet_user_id_week_start_date__ea170292_uniq` (`user_id`,`week_start_date`,`project_id`,`task_name`,`version`),
  KEY `trueAlign_timesheet_project_id_ac8599af_fk_trueAlign_project_id` (`project_id`),
  CONSTRAINT `trueAlign_timesheet_project_id_ac8599af_fk_trueAlign_project_id` FOREIGN KEY (`project_id`) REFERENCES `trueAlign_project` (`id`),
  CONSTRAINT `trueAlign_timesheet_user_id_b322d602_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `truealign_timesheet_chk_1` CHECK ((`version` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_useractionlog`
--

DROP TABLE IF EXISTS `trueAlign_useractionlog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_useractionlog` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `action_type` varchar(20) NOT NULL,
  `timestamp` datetime(6) NOT NULL,
  `details` longtext,
  `action_by_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_useractionlog_action_by_id_9d5bb9bc_fk_auth_user_id` (`action_by_id`),
  KEY `trueAlign_useractionlog_user_id_2e26b9dd_fk_auth_user_id` (`user_id`),
  CONSTRAINT `trueAlign_useractionlog_action_by_id_9d5bb9bc_fk_auth_user_id` FOREIGN KEY (`action_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_useractionlog_user_id_2e26b9dd_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_userdetails`
--

DROP TABLE IF EXISTS `trueAlign_userdetails`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_userdetails` (
  `id` bigint NOT NULL AUTO_INCREMENT,
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
  `hire_date` date DEFAULT NULL,
  `start_date` date DEFAULT NULL,
  `probation_end_date` date DEFAULT NULL,
  `notice_period_days` int unsigned NOT NULL,
  `job_description` longtext,
  `employment_status` varchar(50) NOT NULL,
  `exit_date` date DEFAULT NULL,
  `exit_reason` longtext,
  `rehire_eligibility` tinyint(1) DEFAULT NULL,
  `salary_currency` varchar(3) NOT NULL,
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
  `previous_experience_years` int unsigned DEFAULT NULL,
  `onboarding_date` datetime(6) NOT NULL,
  `last_updated` datetime(6) NOT NULL,
  `last_status_change` datetime(6) DEFAULT NULL,
  `skills` longtext,
  `confidential_notes` longtext,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `onboarded_by_id` int DEFAULT NULL,
  `reporting_manager_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  `office_location_id` bigint DEFAULT NULL,
  `role` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_id` (`user_id`),
  UNIQUE KEY `personal_email` (`personal_email`),
  UNIQUE KEY `company_email` (`company_email`),
  KEY `trueAlign_u_employm_5039f7_idx` (`employment_status`),
  KEY `trueAlign_u_employe_bda06a_idx` (`employee_type`),
  KEY `trueAlign_u_hire_da_98da4c_idx` (`hire_date`),
  KEY `trueAlign_u_start_d_f34b79_idx` (`start_date`),
  KEY `trueAlign_userdetails_onboarded_by_id_48fcb744_fk_auth_user_id` (`onboarded_by_id`),
  KEY `trueAlign_userdetail_reporting_manager_id_6b80f879_fk_auth_user` (`reporting_manager_id`),
  KEY `trueAlign_userdetails_employment_status_4af1e698` (`employment_status`),
  KEY `trueAlign_u_office__bfd620_idx` (`office_location_id`),
  CONSTRAINT `trueAlign_userdetail_office_location_id_a151bf2a_fk_trueAlign` FOREIGN KEY (`office_location_id`) REFERENCES `trueAlign_officelocation` (`id`),
  CONSTRAINT `trueAlign_userdetail_reporting_manager_id_6b80f879_fk_auth_user` FOREIGN KEY (`reporting_manager_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_userdetails_onboarded_by_id_48fcb744_fk_auth_user_id` FOREIGN KEY (`onboarded_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_userdetails_user_id_c5e60317_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `truealign_userdetails_chk_1` CHECK ((`notice_period_days` >= 0)),
  CONSTRAINT `truealign_userdetails_chk_2` CHECK ((`previous_experience_years` >= 0))
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_userleavebalance`
--

DROP TABLE IF EXISTS `trueAlign_userleavebalance`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_userleavebalance` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `year` int NOT NULL,
  `allocated` decimal(5,1) NOT NULL,
  `used` decimal(5,1) NOT NULL,
  `carried_forward` decimal(5,1) NOT NULL,
  `additional` decimal(5,1) NOT NULL,
  `leave_type_id` bigint NOT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trueAlign_userleavebalan_user_id_leave_type_id_ye_dd0affca_uniq` (`user_id`,`leave_type_id`,`year`),
  KEY `trueAlign_userleaveb_leave_type_id_72addf12_fk_trueAlign` (`leave_type_id`),
  CONSTRAINT `trueAlign_userleaveb_leave_type_id_72addf12_fk_trueAlign` FOREIGN KEY (`leave_type_id`) REFERENCES `trueAlign_leavetype` (`id`),
  CONSTRAINT `trueAlign_userleavebalance_user_id_c558436a_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_usersession`
--

DROP TABLE IF EXISTS `trueAlign_usersession`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_usersession` (
  `id` char(32) NOT NULL,
  `parent_session_id` char(32) DEFAULT NULL,
  `tab_id` varchar(100) DEFAULT NULL,
  `is_primary_tab` tinyint(1) NOT NULL,
  `session_fingerprint` varchar(255) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `login_time` datetime(6) NOT NULL,
  `last_activity` datetime(6) NOT NULL,
  `ended_at` datetime(6) DEFAULT NULL,
  `tab_opened_time` datetime(6) DEFAULT NULL,
  `tab_last_focus` datetime(6) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL,
  `is_idle` tinyint(1) NOT NULL,
  `idle_start_time` datetime(6) DEFAULT NULL,
  `total_idle_time` bigint NOT NULL,
  `working_time` bigint NOT NULL,
  `focus_time` bigint NOT NULL,
  `session_duration` double DEFAULT NULL,
  `ip_address` char(39) DEFAULT NULL,
  `user_agent` longtext,
  `browser_fingerprint` longtext,
  `csrf_token` varchar(64) DEFAULT NULL,
  `csrf_token_created` datetime(6) DEFAULT NULL,
  `device_type` varchar(20) DEFAULT NULL,
  `screen_resolution` varchar(20) DEFAULT NULL,
  `timezone_offset` int DEFAULT NULL,
  `language` varchar(10) DEFAULT NULL,
  `battery_level` double DEFAULT NULL,
  `connection_type` varchar(20) DEFAULT NULL,
  `location_country` varchar(100) DEFAULT NULL,
  `location_region` varchar(100) DEFAULT NULL,
  `location_city` varchar(100) DEFAULT NULL,
  `location_latitude` double DEFAULT NULL,
  `location_longitude` double DEFAULT NULL,
  `location_accuracy` double DEFAULT NULL,
  `location_type` varchar(20) DEFAULT NULL,
  `tab_title` json NOT NULL,
  `tab_url` json NOT NULL,
  `url` json NOT NULL,
  `title` json NOT NULL,
  `referrer` json NOT NULL,
  `page_views` json NOT NULL,
  `clicks` json NOT NULL,
  `scrolls` json NOT NULL,
  `keyboard_events` json NOT NULL,
  `mouse_movements` int NOT NULL,
  `tab_visibility_log` json NOT NULL,
  `tab_switches` int NOT NULL,
  `background_time` bigint NOT NULL,
  `idle_state_changes` json NOT NULL,
  `performance_metrics` json NOT NULL,
  `network_events` json NOT NULL,
  `error_events` json NOT NULL,
  `custom_timeout` int unsigned DEFAULT NULL,
  `inactivity_warnings_sent` int NOT NULL,
  `last_warning_time` datetime(6) DEFAULT NULL,
  `auto_logout_enabled` tinyint(1) NOT NULL,
  `offline_data` json NOT NULL,
  `last_sync_time` datetime(6) DEFAULT NULL,
  `pending_sync_count` int NOT NULL,
  `related_tabs` json NOT NULL,
  `broadcast_messages_sent` int NOT NULL,
  `broadcast_messages_received` int NOT NULL,
  `cross_tab_activity_syncs` int NOT NULL,
  `visited_urls` json NOT NULL,
  `most_visited_url` varchar(2000) DEFAULT NULL,
  `most_visited_count` int NOT NULL,
  `productivity_score` double DEFAULT NULL,
  `engagement_score` double DEFAULT NULL,
  `session_quality` varchar(20) DEFAULT NULL,
  `security_score` double DEFAULT NULL,
  `security_anomalies` json NOT NULL,
  `user_id` int NOT NULL,
  `logout_time` datetime(6) DEFAULT NULL,
  `session_key` varchar(40) NOT NULL,
  `idle_time` bigint DEFAULT NULL,
  `location_history` json DEFAULT NULL,
  `browser` varchar(100) DEFAULT NULL,
  `end_reason` varchar(50) DEFAULT NULL,
  `os` varchar(100) DEFAULT NULL,
  `session_end_time` datetime(6) DEFAULT NULL,
  `start_time` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_is_active_idx` (`user_id`,`is_active`),
  KEY `tab_id_idx` (`tab_id`),
  KEY `parent_session_id_idx` (`parent_session_id`),
  KEY `created_at_idx` (`created_at`),
  KEY `last_activity_idx` (`last_activity`),
  CONSTRAINT `trueAlign_usersession_user_id_0f639eb6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `truealign_usersession_chk_1` CHECK ((`custom_timeout` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_voucher`
--

DROP TABLE IF EXISTS `trueAlign_voucher`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_voucher` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `voucher_number` varchar(50) NOT NULL,
  `type` varchar(20) NOT NULL,
  `date` date NOT NULL,
  `reference_no` varchar(100) DEFAULT NULL,
  `party_name` varchar(255) NOT NULL,
  `purpose` longtext NOT NULL,
  `amount` decimal(15,2) NOT NULL,
  `status` varchar(25) NOT NULL,
  `attachments` varchar(100) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  `created_by_id` int NOT NULL,
  `department_approved_by_id` int DEFAULT NULL,
  `finance_approved_by_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `voucher_number` (`voucher_number`),
  KEY `trueAlign_voucher_created_by_id_5539a132_fk_auth_user_id` (`created_by_id`),
  KEY `trueAlign_voucher_department_approved__9c178513_fk_auth_user` (`department_approved_by_id`),
  KEY `trueAlign_voucher_finance_approved_by__f8eafa4b_fk_auth_user` (`finance_approved_by_id`),
  CONSTRAINT `trueAlign_voucher_created_by_id_5539a132_fk_auth_user_id` FOREIGN KEY (`created_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_voucher_department_approved__9c178513_fk_auth_user` FOREIGN KEY (`department_approved_by_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `trueAlign_voucher_finance_approved_by__f8eafa4b_fk_auth_user` FOREIGN KEY (`finance_approved_by_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `trueAlign_voucherdetail`
--

DROP TABLE IF EXISTS `trueAlign_voucherdetail`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `trueAlign_voucherdetail` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `debit_amount` decimal(15,2) NOT NULL,
  `credit_amount` decimal(15,2) NOT NULL,
  `description` longtext,
  `account_id` bigint NOT NULL,
  `voucher_id` bigint NOT NULL,
  PRIMARY KEY (`id`),
  KEY `trueAlign_voucherdet_account_id_22f7027e_fk_trueAlign` (`account_id`),
  KEY `trueAlign_voucherdet_voucher_id_8af8ffbb_fk_trueAlign` (`voucher_id`),
  CONSTRAINT `trueAlign_voucherdet_account_id_22f7027e_fk_trueAlign` FOREIGN KEY (`account_id`) REFERENCES `trueAlign_chartofaccount` (`id`),
  CONSTRAINT `trueAlign_voucherdet_voucher_id_8af8ffbb_fk_trueAlign` FOREIGN KEY (`voucher_id`) REFERENCES `trueAlign_voucher` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-08-03 11:51:17
