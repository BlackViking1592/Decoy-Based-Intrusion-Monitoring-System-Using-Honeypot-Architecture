CREATE DATABASE IF NOT EXISTS honeypot_db;
USE honeypot_db;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255),
  dob DATE,
  gender ENUM('M','F','O') DEFAULT 'O',
  email VARCHAR(255) UNIQUE,
  password_hash VARCHAR(512),
  hash_algo ENUM('sha256','bcrypt') DEFAULT 'sha256',
  is_honeypot TINYINT(1) DEFAULT 0,
  reset_token VARCHAR(255),
  reset_token_expiry DATETIME,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_email VARCHAR(255),
  attempted_password VARCHAR(512),
  ip VARCHAR(100),
  user_agent VARCHAR(512),
  endpoint VARCHAR(255),
  action TEXT,
  result ENUM('success','failure','suspicious') DEFAULT 'failure',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS honeypot_intrusions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  attacker_ip VARCHAR(100),
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS attacker_activity_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  intrusion_id INT,
  action VARCHAR(255),
  details TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (intrusion_id) REFERENCES honeypot_intrusions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS stolen_snapshots (
  id INT AUTO_INCREMENT PRIMARY KEY,
  attacker_ip VARCHAR(100),
  attacker_ua VARCHAR(512),
  data_snapshot TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fake_corporate_data (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255),
  body TEXT
);

INSERT INTO fake_corporate_data (title, body) VALUES
('Q4 Strategy','Confidential Q4 strategy — revenue targets and client list.'),
('Payroll','Fake payroll data: employee salaries and bank details.'),
('API Keys','fake-api-key-12345; secret=xxxxx');
