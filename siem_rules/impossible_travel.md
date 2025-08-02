# Impossible Travel Time Login Detection - SIEM Rule

## Description
Detects when a user logs in from two different geographical locations within a timeframe that makes physical travel impossible, indicating potential account compromise or credential theft.

## Condition/Query
- **Threshold**: ≥1 occurrence in 60 minutes
- **Logic**: Monitor application login events with geolocation data for impossible travel patterns
- **Pattern**: Login activity + User ID + Geographic location data

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Authentication - Detected Login from Two IPs with Impossible Travel Time"
- **policy.type**: "Log"
- **policy.tags**: ["Default", "Security", "Authentication", "Impossible Travel", "Geolocation"]
- **policy.scheduled**: "no"
- **policy.severity**: "CRITICAL"
- **id**: 10000000000035

### Context Configuration
- **entity.type**: "event.source.type"
- **entities**: ["Application"]
- **data.point**: "message"
- **aggregator**: "count"
- **operator**: ">="
- **value**: 1
- **trigger.mode**: "individual"
- **evaluation.window**: 60
- **evaluation.window.unit**: "minute"
- **evaluation.frequency**: 60
- **evaluation.frequency.unit**: "minute"
- **policy.result.by**: ["event.source"]

### Filter Conditions
- **operand**: "@bottomline.mainframe.activity.resource.code", **operator**: "=", **value**: "login"
- **operand**: "@bottomline.mainframe.activity.usr.id", **operator**: "contains", **value**: "*"
- **operand**: "@network.client.geoip", **operator**: "contains", **value**: "*"

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