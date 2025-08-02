# Login Attempt from New Location (T1078) - SIEM Rule

## Description
Detects login attempts from new or unusual geographic locations, which could indicate account compromise, credential theft, or unauthorized access using valid credentials.

## Condition/Query
- **Threshold**: ≥1 occurrence in 5 minutes
- **Logic**: Monitor abnormal security audit logs for new location login events
- **Pattern**: Abnormal security service + login event name

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Initial Access - Login Attempt from New Location (T1078)"
- **policy.type**: "Log"
- **policy.tags**: ["Default", "Security", "Initial Access", "T1078", "TA0001", "Geolocation", "Anomaly Detection"]
- **policy.scheduled**: "no"
- **policy.severity**: "WARNING"
- **id**: 10000000000038

### Context Configuration
- **entity.type**: "event.source.type"
- **entities**: ["Security"]
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
- **operand**: "source", **operator**: "=", **value**: "abnormal-security"
- **operand**: "@service", **operator**: "=", **value**: "abnormal-security-audit-logs"
- **operand**: "@evt.name", **operator**: "=", **value**: "login"

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