# Brute Force Attack Detection (T1110) - SIEM Rule

## Description
Detects brute force authentication attacks where multiple failed login attempts occur within a short time window, indicating potential credential stuffing or password spraying attacks.

## Condition/Query
- **Threshold**: ≥10 failed logins in 15 minutes
- **Logic**: Monitor Windows OCSF authentication events for repeated failures
- **Pattern**: OCSF class UID 3002 + "Logon" activity + "Failure" status

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Credential Access - Brute Force Attack Detected (T1110)"
- **policy.type**: "Log"
- **policy.description**: "Detects brute force authentication attacks with multiple failed login attempts"
- **policy.tags**: ["Default", "Security", "Authentication", "T1110", "TA0006"]
- **policy.scheduled**: "no"
- **log.policy.type**: "threshold"

### Context Configuration
- **entity.type**: "event.source.type"
- **policy.severity**: "MAJOR"
- **entities**: ["Windows", "Linux"]
- **data.point**: "message"
- **aggregator**: "count"
- **operator**: ">="
- **value**: 10
- **trigger.mode**: "individual"
- **evaluation.window**: 15
- **evaluation.window.unit**: "minute"
- **evaluation.frequency**: 1
- **evaluation.frequency.unit**: "minute"
- **policy.result.by**: ["event.source"]

### Filter Conditions
- **operand**: "@ocsf.class_uid", **operator**: "=", **value**: "3002"
- **operand**: "@ocsf.activity_name", **operator**: "=", **value**: "Logon"
- **operand**: "@ocsf.status", **operator**: "=", **value**: "Failure"

### Actions and Settings
- **policy.actions**: {
  "Notification": {
    "Email": {},
    "channels": {}
  },
  "Integration": {}
}
- **policy.renotify**: "no"
- **policy.suppress.action**: "no"
- **policy.clear.state**: "no"