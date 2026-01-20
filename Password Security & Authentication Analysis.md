# **Task 1: Learn How Passwords Are Stored (Hashing vs Encryption)**

## **Explanation**
When users create passwords, operating systems and applications **never store them in plain text**.  
Instead, they store them using secure techniques designed to protect credentials even if the database is compromised.

There are **two major methods** used for storing or protecting passwords:

---

## **1. Hashing (Recommended for Password Storage)**

### **What is Hashing?**
Hashing is a **one-way, irreversible** process that converts a password into a fixed-length string.  
Hashing **cannot be decrypted**, even by the system — it can only be *matched*.

### **Examples of Hash Functions**
| Hash Type | Output Length | Secure? | Notes |
|----------|---------------|---------|-------|
| **MD5** | 32 chars | No | Very fast, easily crackable |
| **SHA-1** | 40 chars | Weak | Collision attacks possible |
| **SHA-256** | 64 chars | Strong | Secure modern hashing |
| **bcrypt** | 60 chars | Very Strong | Slow, salted, recommended |
| **Argon2** | Variable | Very Strong | Winner of PHC, secure |

### **Why Hashing?**
- One-way + irreversible  
- Even if an attacker steals hashes, they cannot reverse them easily  
- Can be enhanced with **salting** and **key stretching**  

---

## **2. Encryption (Not Recommended for Password Storage)**

### **What is Encryption?**
Encryption is a **two-way, reversible** process.  
Data is encrypted using a key and can be decrypted back into original form.

### **Why NOT use encryption to store passwords?**
- If the encryption key is stolen → all passwords are exposed  
- Reversible methods increase risk  
- Violates modern authentication standards

Encryption is used for:
- Securing files  
- Securing communications (HTTPS, SSH)  

NOT for password storage.

---

### **3. Difference Between Hashing and Encryption**

| Feature | Hashing | Encryption |
|--------|---------|------------|
| Reversible | No | Yes |
| Purpose | Password storage | Secure communication |
| Uses Key | No | Yes |
| Vulnerability | Weak hashes crackable | Key theft exposes data |

---

### **4. Code: Generate Basic Hashes**

Here are simple commands to generate password hashes on Linux.

```bash
echo -n "password123" | md5sum                 # Generates an MD5 hash
echo -n "password123" | sha1sum                # SHA-1 hash
echo -n "password123" | sha256sum              # SHA-256 hash

# bcrypt (uses openssl or mkpasswd)
mkpasswd --method=bcrypt "password123"         # Generates bcrypt hash
```
# **Task 2: Identify Different Hash Types (MD5, SHA-1, bcrypt)**

## **Explanation**
Different systems and applications use different hashing algorithms to store passwords.  
Being able to identify hash types is an essential skill in cybersecurity, digital forensics, and password-cracking analysis.

Hash identification is based on:
- Hash length  
- Structure/prefix patterns  
- Character set  
- Algorithm-specific formatting  

---

### **a) Common Hash Types and Their Characteristics**

| Hash Type | Length | Characters | Secure? | Notes |
|-----------|--------|------------|---------|-------|
| **MD5** | 32 | Hexadecimal | No | Fast → easy to crack |
| **SHA-1** | 40 | Hexadecimal | Weak | Collision attacks exist |
| **SHA-256** | 64 | Hexadecimal | Strong | Standard modern hashing |
| **bcrypt** | 60 | Mixed ASCII | Very Strong | Slow, salted (recommended) |
| **SHA-512** | 128 | Hexadecimal | Very Strong | Used in Linux shadow files |
| **Argon2** | Variable | Encoded string | Very Strong | Memory-hard, modern |

---

### **b) Identify Hashes by Length and Format**

### **MD5 (32 characters)**
# Task 3: Generate Password Hashes

## Explanation
In this task, you generate password hashes using different algorithms to understand how the same password produces different hash outputs depending on the hashing method used.

Generating hashes helps demonstrate:
- How hashing works in practice
- Why strong hashing algorithms are preferred
- How weak hashes can be easily targeted by attackers

---

## a) Generate Hashes Using Basic Hashing Algorithms

### Explanation
Basic hashing algorithms convert input data into fixed-length hashes.  
These algorithms are fast, which makes them insecure for password storage.

### Code
```bash
echo -n "password123" | md5sum         # Generate MD5 hash
echo -n "password123" | sha1sum        # Generate SHA-1 hash
echo -n "password123" | sha256sum      # Generate SHA-256 hash
```
### bcrypt Characteristics

- Built-in salting  
- Adjustable cost factor  
- Resistant to GPU cracking attacks  

---

### c) Compare Hash Outputs

**Explanation**

Even when the same password is used, each algorithm produces a different hash output.  
bcrypt hashes are longer and structured, while MD5/SHA hashes are simple hex strings.

**Security Comparison**

- Same password ≠ same hash across algorithms  
- bcrypt hashes look different each time due to salting  
- Weak hashes remain identical for same input (no salt)  



### Mini Guide – Expanded Professional Version (Points 4 to 8)
(Task 4: Password Security & Authentication Analysis)

---

## 4. Attempt Cracking Weak Hashes Using Wordlists  
Cracking helps you understand how attackers identify weak passwords by testing them against massive wordlists containing millions of leaked passwords.

### Step-by-Step Example (John the Ripper)
1. **Identify the hash type**  
   Example hashed password (MD5):  
```

5f4dcc3b5aa765d61d8327deb882cf99

```
2. **Save the hash to a file (`hashes.txt`)**  
```

echo "user1:5f4dcc3b5aa765d61d8327deb882cf99" > hashes.txt

```
3. **Run John using a wordlist (e.g., rockyou.txt)**  
```

john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

```
4. **Check cracked passwords**  
```

john --show hashes.txt

```

### Step-by-Step Example (Hashcat)
1. **MD5 hash (mode 0)**  
```

hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

```
2. **View cracked results**  
```

hashcat --show -m 0 hashes.txt

```

### What You Learn  
- Weak passwords appear in wordlists and are cracked instantly.  
- Hashing alone is not enough—password strength matters.

---

## 5. Understand Brute Force vs Dictionary Attacks  

### Dictionary Attack  
A dictionary attack tries passwords from a known list.  
Effective when users select predictable or common passwords.

**Example (Hashcat):**
```

hashcat -m 0 -a 0 hash.txt rockyou.txt

```

**When it works well:**  
- Passwords like “password123”, “qwerty”, “iloveyou”, “admin@123”.

---

### Brute Force Attack  
Tries **every possible combination** of characters.  
Time increases exponentially with password length.

**Example (Hashcat Mask Attack):**  
Brute-forcing a 6-digit numeric PIN:
```

hashcat -m 0 -a 3 hash.txt ?d?d?d?d?d?d

```

Brute-forcing an 8-character alphanumeric password:
```

hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a

```

**Why brute force is slow:**  
- Total combinations for 8 characters using full ASCII set:  
  95^8 ≈ 6.6 quadrillion possibilities.

### Comparison Table  
| Attack Type | Speed | Success Rate | Best Use Case |
|-------------|--------|--------------|---------------|
| Dictionary  | Fast   | High (if password is weak/common) | Guessing human-like passwords |
| Brute Force | Slow   | Guaranteed eventually | Guessing short/simple passwords |

---

## 6. Analyze Why Weak Passwords Fail  

Weak passwords fail because they follow human tendencies:

### Common Weak Password Traits  
1. **Too Short** – 6–8 characters are easily brute-forced.  
2. **Predictable Patterns** – Names, birthdays, “123456”, “qwerty”.  
3. **Reused Across Sites** – Makes credential-stuffing easy.  
4. **Found in Leaked Databases** – Attackers use billions of real-world leaked passwords.

### Entropy Example  
- “password123” → ~20 bits entropy → weak  
- “D$k8!fLzP3#Q” → ~70+ bits entropy → strong

### Demonstration  
Example weak hash cracked instantly:
```

5f4dcc3b5aa765d61d8327deb882cf99 → "password"

````

Why? Because:
- It appears in rockyou.txt  
- MD5 is outdated and fast to compute  
- Password is predictable

---

## 7. Study MFA and Its Importance  

Multi-Factor Authentication (MFA) adds a second verification layer.

### MFA Types  
1. **Something You Know** – Password, PIN  
2. **Something You Have** – OTP, Authenticator app, YubiKey  
3. **Something You Are** – Fingerprint, Face ID

### Why MFA Matters  
Even if the password is cracked, the attacker still needs the second factor.

### Attack Scenarios Without MFA  
- Phishing → instant account takeover  
- Password reuse → multiple accounts compromised  
- Keylogging → attacker steals credentials and logs in

### Attack Scenarios With MFA  
- Phishing → attacker gets password but not OTP  
- Leaked password → MFA blocks login  
- Brute force → useless without second factor

### Example MFA Workflow  
User enters password → App sends OTP → Login allowed only after OTP verification.

---

## 8. Write Recommendations for Strong Authentication  

### Password Policy Recommendations  
1. Use **12–16+ characters** minimum.  
2. Include **uppercase, lowercase, numbers, symbols**.  
3. Avoid dictionary words and personal information.  
4. Encourage users to use **password managers**.

### Hashing Recommendations  
- Use slow, modern password hashing algorithms:  
  - **bcrypt**  
  - **scrypt**  
  - **Argon2id** (most recommended)

### Examples of Secure Hashing (Python)

**bcrypt Example:**
```python
import bcrypt

password = b"StrongPassword123!"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed)
````

**Argon2 Example:**

```python
from argon2 import PasswordHasher

ph = PasswordHasher()
hash = ph.hash("SuperSecurePassword!")
print(hash)
```

### System Security Recommendations

* Enable MFA for all users
* Enforce account lockout after failed attempts
* Implement rate-limiting for login endpoints
* Monitor suspicious login patterns in SIEM
* Use CAPTCHA to slow automated attacks

### Infrastructure Recommendations

* Always salt password hashes
* Do not store passwords in plaintext
* Secure backup storage
* Use HTTPS everywhere

---


```
```
