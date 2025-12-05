# README – CPIT-455 Security Project

# Title
Comprehensive Security Assessment of Sehhaty

# Course
CPIT-455

# Student
Nawaf Abdullah Al-Thobaiti

# Section
IT1

# Submitted to
Prof. Adeeb Noor

# Project Description
This Java proof-of-concept demonstrates core cybersecurity controls for the national Sehhaty healthcare platform  
It accompanies the written security assessment submitted for CPIT-455  
The code simulates authentication access control encryption secure logging and safe exception handling  
This implementation is educational only and does not represent real Sehhaty production security

# Features Demonstrated
• Login validation and password hashing  
• Role Based Access Control RBAC  
• Encryption of sensitive medical data fields  
• Audit logging for data access accountability  
• Input validation and secure exception handling  

# Code Structure
• SehhatySecurityDemo  Main execution and demonstration scenario  
• AuthService  User authentication and verification  
• PasswordHasher  Demonstration hashing logic  
• HealthRecordService  Permission checking for record access  
• CryptoService  Placeholder encryption for sensitive fields  
• In memory stores  Temporary user and record storage  
• AuditService  Logging of security relevant actions  
• GlobalExceptionHandler  Centralized secure error handling  

# How to Run

## Requirements
Java JDK 8 or later

## Commands
javac SehhatySecurityDemo.java  
java SehhatySecurityDemo  

## Expected Behavior
• Patient can login and view own medical record only  
• Patient blocked from accessing other records  
• Doctor role allowed to view patient data  
• Audit log generated for every authorized action  

# Security Notes and Academic Focus
Security techniques are simplified because the goal is concept demonstration  

Example simplifications  
• Base64 instead of AES encryption  
• Simple hashing instead of BCrypt or Argon2  
• No signed authentication tokens  
• Limited RBAC mapping  

These decisions are intentional for educational clarity

# Academic Attribution
Submitted as part of  
**Comprehensive Security Assessment of Sehhaty – CPIT-455**  

Faculty of Computing and Information Technology  
King Abdulaziz University  

Instructor  
**Prof. Adeeb Noor**  

Prepared by  
**Nawaf Abdullah Al-Thobaiti**  
Section IT1
