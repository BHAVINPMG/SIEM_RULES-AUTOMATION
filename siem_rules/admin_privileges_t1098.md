# Administrative Privileges Assignment (T1098) - SIEM Rule

## Description
Detects when administrative privileges are assigned to user accounts, indicating potential privilege escalation attempts or unauthorized access elevation.

## Condition/Query
- **Threshold**: ≥1 occurrence in 5 minutes
- **Logic**: Monitor Windows OCSF events for privilege assignment activities
- **Pattern**: OCSF class UID 3005/3006 + "Assign Privileges" activity + ADMIN_PRIVILEGES_ASSIGNED

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Privilege Escalation - Administrative Privileges Assigned (T1098)"
- **policy.type**: "Log"
- **policy.tags**: ["Default", "Security", "Authentication", "T1098", "TA0004", "Windows"]
- **policy.scheduled**: "no"
- **policy.severity**: "MAJOR"
- **id**: 10000000000031

### Context Configuration
- **entity.type**: "event.source.type"
- **entities**: ["Windows"]
- **data.point**: "message"
- **aggregator**: "count"
- **operator**: ">="
- **value**: 1
- **trigger.mode**: "individual"
- **evaluation.window**: 5
- **evaluation.window.unit**: "minute"
- **evaluation.frequency**: 5
- **evaluation.frequency.unit**: "minute"
- **policy.result.by**: ["event.source"]

### Filter Conditions
- **operand**: "@ocsf.class_uid", **operator**: "in", **value**: "3005,3006"
- **operand**: "@ocsf.activity_name", **operator**: "=", **value**: "Assign Privileges"
- **operand**: "@ocsf.privileges", **operator**: "=", **value**: "ADMIN_PRIVILEGES_ASSIGNED"

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