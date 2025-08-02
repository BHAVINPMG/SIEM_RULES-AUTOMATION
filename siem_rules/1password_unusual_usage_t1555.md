# Unusual 1Password Item Usage (T1555) - SIEM Rule

## Description
Detects unusual 1Password item usage patterns that could indicate credential harvesting, unauthorized access to password vaults, or compromised password manager accounts.

## Condition/Query
- **Threshold**: ≥1 occurrence in 5 minutes
- **Logic**: Monitor 1Password audit logs for unusual item usage activities
- **Pattern**: 1Password source + item usage event type + any event name

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Credential Access - Unusual 1Password Item Usage (T1555)"
- **policy.type**: "Log"
- **policy.tags**: ["Default", "Security", "Credential Access", "T1555", "TA0006", "1Password", "Password Manager"]
- **policy.scheduled**: "no"
- **policy.severity**: "WARNING"
- **id**: 10000000000039

### Context Configuration
- **entity.type**: "event.source.type"
- **entities**: ["Linux,Windows"]
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
- **operand**: "source", **operator**: "=", **value**: "1password"
- **operand**: "@evt.type", **operator**: "=", **value**: "1password-item-usages"
- **operand**: "@evt.name", **operator**: "contains", **value**: "*"

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