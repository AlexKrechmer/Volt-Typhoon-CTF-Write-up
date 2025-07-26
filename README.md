# 🛰️ Volt Typhoon CTF (TryHackMe)

This is a write-up for the **Volt Typhoon** CTF on TryHackMe, simulating a real-world intrusion by the PRC state-sponsored threat group **Volt Typhoon**. The CTF emphasizes stealthy, “living off the land” techniques rather than malware or exploits.

---

## 🔍 What I Did

- Investigated how the threat actor gained **initial access** through account takeover
- Tracked attacker behavior across **PowerShell logs, RDP artifacts, and registry keys**
- Detected **credential dumping (Mimikatz)**, **lateral movement**, and **web shells**
- Mapped observed activity to **MITRE ATT&CK techniques**
- Documented the attack lifecycle across 9 phases from access to cleanup

---

## ✅ Skills Demonstrated

- Log and Event Analysis (Windows + app logs)
- Threat Actor TTP Mapping (MITRE ATT&CK)
- PowerShell & LOLBin Forensics
- Report Writing / Incident Documentation

---

## 📁 Files Included

- `README.md` – This file
- `Volt_Typhoon_Write-up`– Full write-up with screenshots
- `/screenshots/` – Evidence from the analysis

---

## ✍️ Reflection

This was my first full CTF write-up. Next time, I plan to improve by:
- Documenting as I go
- Capturing clearer, better-organized screenshots
- Structuring the report with reusability in mind

Still, I’m proud of the techniques and real-world relevance in this analysis.

---

## 📚 References

- [CISA Advisory: Volt Typhoon](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a)
- [MITRE ATT&CK Techniques](https://attack.mitre.org/)
