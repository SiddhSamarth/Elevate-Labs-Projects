# Cyber Security Internship – Task 1  
## Understanding Cyber Security Basics and Attack Surface

---

## 1. Introduction
This task is designed to establish a strong conceptual foundation in cyber security by covering core security principles, common threat actors, attack surfaces, and real-world application data flows. The goal is to develop threat awareness, analytical thinking, and a security-first mindset aligned with industry best practices.

---

## 2. Cyber Security Fundamentals
Cyber security is the practice of protecting information systems, networks, applications, and digital assets from unauthorized access, misuse, disruption, modification, or destruction. It focuses on safeguarding data across its entire lifecycle while ensuring business continuity and risk mitigation against evolving cyber threats.

---

## 3. CIA Triad (Core Security Principles)
The CIA Triad forms the foundation of information security and guides the design of secure systems and policies.

### 3.1 Confidentiality
Confidentiality ensures that sensitive information is accessible only to authorized individuals, systems, or processes.

**Examples:**
- Encryption of financial and banking transactions
- User authentication and role-based authorization in social media platforms
- Access control policies in enterprise environments

### 3.2 Integrity
Integrity ensures that data remains accurate, consistent, and unaltered unless modified by authorized entities.

**Mechanisms:**
- Cryptographic hashing algorithms
- Digital signatures and checksums
- Database constraints, versioning, and audit logs

### 3.3 Availability
Availability ensures that systems, applications, and data remain accessible and operational when required.

**Controls:**
- Redundancy and failover architectures
- Backup and disaster recovery strategies
- DDoS mitigation, load balancing, and monitoring

---

## 4. Types of Cyber Attackers
Understanding attacker profiles helps in threat modeling and risk assessment.

- **Script Kiddies:** Low-skill individuals using publicly available tools and exploits
- **Insiders:** Authorized users who misuse access, either maliciously or negligently
- **Hacktivists:** Ideology-driven attackers targeting organizations or governments
- **Nation-State Actors:** Highly skilled, government-backed attackers involved in espionage or cyber warfare

---

## 5. Attack Surface
An attack surface represents the total set of points where an attacker can attempt to gain unauthorized access to a system or manipulate its behavior.

### 5.1 Common Attack Surfaces
- Web applications
- Mobile applications
- Application Programming Interfaces (APIs)
- Network infrastructure
- Cloud platforms and services
- User endpoints, credentials, and devices

A larger or poorly managed attack surface increases the likelihood of successful exploitation.

---

## 6. OWASP Top 10
The OWASP Top 10 is a globally recognized list of the most critical web application security risks. It serves as a baseline for secure application development and testing.

**Common Vulnerabilities Include:**
- SQL Injection
- Cross-Site Scripting (XSS)
- Broken Authentication and Authorization
- Security Misconfiguration
- Insecure Design

Understanding the OWASP Top 10 helps organizations prioritize remediation efforts and reduce exposure to common attack vectors.

---

## 7. Application Data Flow and Attack Points

### 7.1 Typical Application Data Flow
User → Application → Server → Database <img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/0d6e9c70-46c0-4379-8f66-d34664dda0fb" />



### 7.2 Potential Attack Points
- **User Input Layer:** Injection attacks, XSS, input validation flaws
- **Data Transmission Layer:** Man-in-the-middle (MITM) attacks, insecure protocols
- **Server Logic Layer:** Authentication bypass, business logic vulnerabilities
- **Database Layer:** Unauthorized queries, data leakage, privilege escalation

Identifying attack points at each stage enables proactive security design and defense strategies.

---

## 8. Key Security Concepts Applied
- Attack Surface Management
- Threat Modeling
- Vulnerability Assessment
- Risk Analysis
- Defense in Depth
- Secure Software Development Lifecycle (SSDLC)

