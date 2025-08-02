# Windows Firewall Disabled (T1562) - SIEM Rule

## Description
Detects when Windows Firewall is disabled, which is a common defense evasion technique used by attackers to remove network security barriers and enable unrestricted communication.

## Condition/Query
- **Threshold**: ≥1 occurrence in 5 minutes
- **Logic**: Monitor Windows Event ID 4950 for firewall setting changes to disabled
- **Pattern**: Event ID 4950 + SettingValue "No"

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Defense Evasion - Windows Firewall Disabled (T1562)"
- **policy.type**: "Log"
- **policy.tags**: ["Default", "Security", "Defense Evasion", "T1562", "TA0005", "Windows"]
- **policy.scheduled**: "no"
- **policy.severity**: "MAJOR"
- **id**: 10000000000034

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
- **operand**: "@evt.id", **operator**: "=", **value**: "4950"
- **operand**: "@Event.EventData.Data.SettingValue", **operator**: "=", **value**: "No"

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