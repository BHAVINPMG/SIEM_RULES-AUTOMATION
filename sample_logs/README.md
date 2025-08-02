# SIEM Sample Log Files

This directory contains authentic raw log files that correspond to each SIEM rule in the project. Each log file contains 50 realistic log entries that would trigger the corresponding SIEM detection rule.

## Log Files Overview

| Log File | SIEM Rule | MITRE Technique | Description |
|----------|-----------|-----------------|-------------|
| `admin_privileges_t1098_logs.txt` | Admin Privileges Assignment | T1098 - Account Manipulation | Windows Security Auditing logs showing privilege assignments to user accounts |
| `brute_force_t1110_logs.txt` | Brute Force Attack Detection | T1110 - Brute Force | Windows Security Auditing logs showing multiple failed login attempts from same source |
| `log4j_scanner_t1595_logs.txt` | Log4j Scanner Detection | T1595 - Active Scanning | Apache/IIS access logs showing Log4j JNDI injection attempts in User-Agent and Referer headers |
| `firewall_disabled_t1562_logs.txt` | Windows Firewall Disabled | T1562 - Impair Defenses | Windows Firewall logs showing firewall being disabled across different profiles |
| `impossible_travel_logs.txt` | Impossible Travel Detection | No MITRE | Windows Security Auditing logs showing same user logging in from geographically distant locations within short time frames |
| `1password_unusual_usage_t1555_logs.txt` | 1Password Unusual Usage | T1555 - Credentials from Password Stores | 1Password application logs showing bulk export/download activities |
| `rottenpotato_t1557_logs.txt` | RottenPotato Attack Pattern | T1557 - Adversary-in-the-Middle | Windows Security Auditing logs showing explicit credential logon attempts to localhost:6666 (RottenPotato signature) |
| `domain_admin_changed_t1098_logs.txt` | Domain Admin Group Changes | T1098 - Account Manipulation | Windows Security Auditing logs showing additions and removals from Domain Admins group |
| `new_location_login_t1078_logs.txt` | New Location Login Detection | T1078 - Valid Accounts | Windows Security Auditing logs showing logins from new/unusual geographic locations |

## Log Format Details

### Windows Security Auditing Logs
- **Format**: Standard Windows Event Log format with syslog-style timestamps
- **Fields**: Event ID, Security ID, Account Name, Domain, Logon ID, Network Information
- **Common Event IDs**:
  - 4624: Successful logon
  - 4625: Failed logon  
  - 4648: Logon using explicit credentials
  - 4728: Member added to security-enabled global group
  - 4729: Member removed from security-enabled global group
  - 4950: Windows Firewall setting changed

### Apache/IIS Access Logs
- **Format**: Combined Log Format with additional fields
- **Fields**: IP, timestamp, method, URL, status, size, referer, user-agent
- **Special**: Contains Log4j JNDI injection payloads in various fields

### Application Logs (1Password)
- **Format**: Application-specific format with structured fields
- **Fields**: Timestamp, process ID, user, action, vault, item count
- **Actions**: bulk_export, bulk_download, mass_access, rapid_access

## Usage Notes

1. **Realistic Data**: All logs contain realistic timestamps, IP addresses, usernames, and system names that would be found in actual enterprise environments.

2. **Geographic Diversity**: Logs include references to various global locations, IP ranges, and time zones to simulate real-world distributed environments.

3. **Attack Patterns**: Each log file demonstrates the specific attack pattern or suspicious behavior that the corresponding SIEM rule is designed to detect.

4. **Volume**: Each file contains exactly 50 log entries to provide sufficient data for testing and validation while remaining manageable.

5. **Field Consistency**: All logs maintain consistent field structures and naming conventions that align with the SIEM rule filter conditions.

## Testing with SIEM Rules

These log files can be used to:
- Test SIEM rule effectiveness
- Validate detection logic
- Perform rule tuning and threshold adjustment
- Conduct security team training exercises
- Simulate incident response scenarios

## File Maintenance

When updating SIEM rules, ensure corresponding log files are updated to maintain alignment between detection logic and test data. All logs should continue to represent authentic system-generated events that would realistically trigger the associated SIEM rules.