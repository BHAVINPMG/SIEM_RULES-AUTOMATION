# Log4j Scanner Detection (T1595) - SIEM Rule

## Description
Detects Log4j vulnerability scanning attempts in HTTP User-Agent headers and referrer fields, indicating potential exploitation attempts of CVE-2021-44228 (Log4Shell) vulnerability.

## Condition/Query
- **Threshold**: ≥1 occurrence in 5 minutes
- **Logic**: Monitor Apache/Nginx logs for JNDI lookup patterns in HTTP headers
- **Pattern**: JNDI strings (ldap/rmi/dns) in User-Agent or Referer headers

## Fields Needed for JSON Generation

### Required Policy Fields
- **policy.name**: "Reconnaissance - Log4j Scanner Detected in User Agent (T1595)"
- **policy.type**: "Log"
- **policy.tags**: ["Default", "Security", "Reconnaissance", "T1595", "TA0043", "Log4j", "Vulnerability Scanning"]
- **policy.scheduled**: "no"
- **policy.severity**: "MAJOR"
- **id**: 10000000000037

### Context Configuration
- **entity.type**: "event.source.type"
- **entities**: ["Apache", "Nginx"]
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

### Filter Conditions (OR Logic)
- **operand**: "source", **operator**: "in", **value**: "apache,nginx"
- **operand**: "@http.referer", **operator**: "contains", **value**: "jndi:ldap"
- **operand**: "@http.referer", **operator**: "contains", **value**: "jndi:rmi"
- **operand**: "@http.referer", **operator**: "contains", **value**: "jndi:dns"
- **operand**: "@http.user_agent", **operator**: "contains", **value**: "jndi:ldap"
- **operand**: "@http.user_agent", **operator**: "contains", **value**: "jndi:rmi"
- **operand**: "@http.user_agent", **operator**: "contains", **value**: "jndi:dns"

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