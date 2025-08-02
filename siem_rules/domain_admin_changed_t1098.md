# Windows Domain Admin Group Changed (T1098) - SIEM Rule

## Description
Detects changes to the Windows Domain Admins group, which is a critical security event that could indicate privilege escalation, persistence establishment, or administrative account compromise.

## Condition/Query
- **Threshold**: ≥1 occurrence in 5 minutes
- **Logic**: Monitor Windows Event ID 4737 for Domain Admins group changes
- **Pattern**: Event ID 4737 + TargetUserName "Domain Admins"

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Persistence - Windows Domain Admin Group Changed (T1098)"
- **policy.type**: "Log"
- **policy.tags**: ["Default", "Security", "Persistence", "T1098", "TA0003", "Windows", "Domain Admin"]
- **policy.scheduled**: "no"
- **policy.severity**: "CRITICAL"
- **id**: 10000000000036

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
- **operand**: "@evt.id", **operator**: "=", **value**: "4737"
- **operand**: "@Event.EventData.Data.TargetUserName", **operator**: "=", **value**: "Domain Admins"

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