# Windows RottenPotato Attack Pattern (T1557) - SIEM Rule

## Description
Detects RottenPotato-like privilege escalation attacks that exploit Windows authentication mechanisms through localhost connections and anonymous logons to escalate privileges.

## Condition/Query
- **Threshold**: ≥1 occurrence in 5 minutes
- **Logic**: Monitor Windows Event ID 4624 for suspicious localhost anonymous logons
- **Pattern**: Event ID 4624 + localhost IP + LogonType 3 + ANONYMOUS LOGON

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Privilege Escalation - Windows RottenPotato Attack Pattern (T1557)"
- **policy.type**: "Log"
- **policy.tags**: ["Default", "Security", "Privilege Escalation", "T1557", "TA0004", "Windows"]
- **policy.scheduled**: "no"
- **policy.severity**: "CRITICAL"
- **id**: 10000000000033

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
- **operand**: "source", **operator**: "=", **value**: "windows.events"
- **operand**: "@evt.id", **operator**: "=", **value**: "4624"
- **operand**: "@network.client.ip", **operator**: "=", **value**: "127.0.0.1"
- **operand**: "@Event.EventData.Data.LogonType", **operator**: "=", **value**: "3"
- **operand**: "@Event.EventData.Data.TargetUserName", **operator**: "=", **value**: "ANONYMOUS LOGON"

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