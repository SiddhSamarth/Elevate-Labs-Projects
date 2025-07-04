# 🔐 VPN Setup and Privacy Report

---

## 🎯 Objective

To understand how Virtual Private Networks (VPNs) protect user privacy and secure online communication, by setting up a free VPN client, testing its functionality, and documenting the results.

---

## 🛠️ Tools Used

| Tool              | Purpose                                   |
|-------------------|-------------------------------------------|
| ProtonVPN / Windscribe | VPN provider to secure traffic         |
| whatismyipaddress.com | Check public IP before and after VPN    |
| Browser            | Verify encryption and browsing behaviour   |
| Screenshot Tool    | Document VPN status and IP check results  |

---

## 🧭 Step-by-Step Setup & Testing

### 🔸 Step 1: Choose and Register for VPN
- **Chosen VPN:** ProtonVPN (Free Tier)
- Go to [https://protonvpn.com](https://protonvpn.com) and create a free account.

---

### 🔸 Step 2: Download and Install the VPN Client
- Download the appropriate client for your OS.
- Install and sign in using your registered credentials.

---

### 🔸 Step 3: Connect to a VPN Server
- Launch the VPN app.
- Connect to the **closest available server** for optimal speed (e.g., Netherlands or India).
![image](https://github.com/user-attachments/assets/9b468abb-ee2c-4275-bf9e-d3d7cf7fbca5)


---

### 🔸 Step 4: Verify IP Change
- Visit [WhatIsMyIpAdress](https://whatismyipaddress.com).
- Confirm that your IP address and location have changed.
![image](https://github.com/user-attachments/assets/f4a2e95c-bae8-4324-acad-c1e926cac3b1)



---

### 🔸 Step 5: Test Encrypted Traffic
- Visit websites like `https://example.com` or any secure site (https). 
- Confirm that browsing works normally and is encrypted.

![image](https://github.com/user-attachments/assets/786aac8b-8d2d-45e1-b931-d34d79504a7b)


---

### 🔸 Step 6: Disconnect VPN & Compare Speed/IP
- Disconnect the VPN and revisit the IP checker site.
- Compare:
  - IP Address
  - Location
  - Page load times/browsing latency

| Speed With VPN | Speed Without VPN |
|----------|-------------|
| ![VPN off](https://github.com/user-attachments/assets/db61d0d7-0e49-4c16-b3e0-c8f102ff3581) | ![Without VPN](https://github.com/user-attachments/assets/42790cb8-89c6-40b1-879d-fb735977f551) |


---

## 🧠 VPN Encryption & Privacy – Summary

### 🔐 What does a VPN do?
- **Encrypts** your internet traffic using secure protocols (e.g., OpenVPN, WireGuard)
- **Masks your IP address** by routing traffic through a VPN server
- **Prevents tracking** by ISPs, advertisers, or public Wi-Fi attackers

---

## ✅ VPN Benefits

| Benefit                       | Description                                                         |
|-------------------------------|---------------------------------------------------------------------|
| IP Anonymity                  | Hides your real IP address from websites and trackers               |
| Secure Wi-Fi Usage            | Encrypts traffic even on public Wi-Fi                               |
| Bypass Censorship & Geo-blocks| Access websites blocked by country or network policies              |
| Prevent ISP Snooping          | Your ISP can't see your online activity while connected to VPN      |

---

## ⚠️ VPN Limitations

| Limitation                    | Description                                                         |
|-------------------------------|---------------------------------------------------------------------|
| Speed Reduction               | Slight delay due to encrypted routing                               |
| Trust in VPN Provider         | The provider could see your data if they don't follow no-log policy |
| Free Plans are Limited        | Limited servers, slower speed, no P2P or streaming on free tiers    |
| Doesn’t Make You Invisible    | VPNs don’t protect against malware, phishing, or unsafe downloads   |

---

## 📝 Summary Table

| Test                        | Result                                      |
|-----------------------------|---------------------------------------------|
| VPN Client Installed        | ✅ ProtonVPN client setup successfully       |
| Connection Established      | ✅ Connected to secure server                |
| IP Address Changed          | ✅ Verified on whatismyipaddress.com        |
| Traffic Encrypted           | ✅ HTTPS browsing worked as expected         |
| Speed Comparison            | ⚠️ Slight drop in speed noticed post-VPN     |
| VPN Disconnected            | ✅ Original IP and speed restored            |


---

## 🔗 References

- [ProtonVPN Free](https://protonvpn.com/free-vpn)
- [Windscribe VPN](https://windscribe.com)
- [WhatIsMyIPAddress.com](https://whatismyipaddress.com)
- [VPN Encryption Explained – Mozilla](https://vpn.mozilla.org/)


