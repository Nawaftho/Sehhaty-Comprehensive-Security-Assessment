# CPIT-455 Resilient Infrastructure Project

## Title
National Resilience Design for SAMA Banking Network

## Course
CPIT-455

## Student
Nawaf Abdullah Al-Thobaiti

## Section
IT1

## Submitted to
Prof. Adeeb Noor

---

## Project Description

This Java proof-of-concept demonstrates **resilient failover** for the national SAMA banking network.  
It accompanies the written national resilience design report developed for CPIT-455.

The simulation models automatic transfer of settlement services from a primary region  
to a backup region when failure is detected ensuring continuous availability  
of essential financial functions in Saudi Arabia

This is not production code  
It is an educational implementation demonstrating the basic **4R resilience principles**  
used in critical national infrastructure design

---

## Features Demonstrated

• Automatic failover between settlement nodes  
• Continuous processing of financial transactions  
• Service availability even during system failure  
• Recovery and return to the primary node when restored  
• Clear logging of system state for analysis  

---

## Code Structure

- **ResilientBankingDemo.java**  
  Console application simulating:
  - Primary and backup settlement nodes  
  - Transaction processing under node failure  
  - Recovery and resilience workflow  

---

## How to Run

### Requirements
Java JDK 8 or later

### Commands
```bash
javac ResilientBankingDemo.java
java ResilientBankingDemo
