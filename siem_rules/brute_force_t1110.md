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
- **policy.tags**: ["Default", "Security", "Authentication", "T1110", "TA0006", "Windows"]
- **policy.scheduled**: "no"
- **policy.severity**: "MAJOR"
- **id**: 10000000000032

### Context Configuration
- **entity.type**: "event.source.type"
- **entities**: ["Windows"]
- **data.point**: "message"
- **aggregator**: "count"
- **operator**: ">="
- **value**: 10
- **trigger.mode**: "individual"
- **evaluation.window**: 15
- **evaluation.window.unit**: "minute"
- **evaluation.frequency**: 15
- **evaluation.frequency.unit**: "minute"
- **policy.result.by**: ["event.source"]

### Filter Conditions
- **operand**: "@ocsf.class_uid", **operator**: "=", **value**: "3002"
- **operand**: "@ocsf.activity_name", **operator**: "=", **value**: "Logon"
- **operand**: "@ocsf.status", **operator**: "=", **value**: "Failure"

### Static Fields (Always Same)
- **policy.trigger.occurrences**: 1
- **policy.auto.clear.timer.seconds**: 0
- **policy.email.notification.recipients**: []
- **policy.renotify**: "yes"
- **policy.monitor.polling.failed.notification.timer.seconds**: 0
- **policy.monitor.polling.failed.notification.status**: "no"
- **policy.renotification.timer.seconds**: 0
- **policy.actions**: {}
- **policy.suppress.action**: "no"
- **policy.archived**: "no"
- **policy.state**: "no"
- **_type**: "1"
- **policy.creation.time**: Unix timestamp