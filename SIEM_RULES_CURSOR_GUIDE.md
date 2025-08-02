# SIEM Rules Project - Cursor Rules

## Project Overview
This project contains SIEM (Security Information and Event Management) rules in JSON format with a corresponding JSON schema for validation.

## File Structure
- `*.json` - SIEM rule files
- `siem_rule_schema.json` - JSON schema for validating SIEM rules
- `.cursorrules` - This file with coding guidelines

## JSON Standards

### SIEM Rule Structure
- All SIEM rules must follow the schema defined in `siem_rule_schema.json`
- Policy names should be descriptive and follow the format: "Category - Specific Event Description"
- Use consistent indentation (2 spaces)
- Include all required fields as defined in the schema

### Required Fields
- `policy.name`: Descriptive name for the rule
- `policy.type`: Always "Log"
- `policy.tags`: Array of relevant tags (e.g., ["Default", "Security", "Linux"])
- `policy.scheduled`: Always "no"
- `policy.context`: Complete context object with all required sub-fields
- `policy.trigger.occurrences`: Always 1
- `policy.auto.clear.timer.seconds`: Always 0
- `policy.email.notification.recipients`: Always empty array []
- `policy.renotify`: Always "yes"
- `policy.monitor.polling.failed.notification.timer.seconds`: Always 0
- `policy.monitor.polling.failed.notification.status`: Always "no"
- `policy.renotification.timer.seconds`: Always 0
- `policy.actions`: Always empty object {}
- `policy.suppress.action`: Always "no"
- `policy.archived`: Always "no"
- `policy.state`: Always "no"
- `_type`: Always "1"
- `id`: Unique numeric identifier (format: 100000000000XX)

### Context Configuration
- `entity.type`: Must be one of ["event.source.type", "group", "event.source"]
- `data.point`: Must be one of ["event.source", "event.category", "message", "event.source.type", "event.severity"]
- `aggregator`: Use "count" for most cases, "sum"/"avg" only when appropriate
- `operator`: Choose appropriate comparison operator ("=", ">=", "<=", ">", "<", "contains", "in", "start with", "end with", "range")
- For "range" operator, use string format "min#max" (e.g., "10#20")
- `trigger.mode`: Always "individual"
- `policy.severity`: Use "WARNING", "MAJOR", or "CRITICAL" based on impact

### Filter Configuration
- Use the exact filter structure as defined in the schema
- Include/exclude filters with proper conditions
- Use appropriate operators: "=", "contains", "in", "start with", "end with"

#### Filter Condition Operators
- **=** - Exact match
- **contains** - Contains the specified value
- **in** - Value is in a list/array
- **start with** - Starts with the specified value
- **end with** - Ends with the specified value

#### Filter Types
- **include** - Include records that match the condition
- **exclude** - Exclude records that match the condition

#### Logical Operators
- **and** - All conditions must be true
- **or** - Any condition can be true

#### Filter Group Constraints
- **Data Filter (data.filter.groups)**: Maximum 3 groups per data filter
- **Conditions per Group**: Maximum 3 conditions per group

## Filter Structure Rules

### Data Filter Template
```json
{
  "data.filter": {
    "operator": "and|or",
    "filter": "include|exclude",
    "groups": [
      {
        "filter": "include|exclude",
        "operator": "and|or",
        "conditions": [
          {
            "operand": "field_name",
            "operator": "=|contains|in|start with|end with",
            "value": "string|number|boolean"
          }
        ]
      }
    ]
  }
}
```

### Filter Rules
1. **Top-level structure**: Must contain `data.filter` object with `operator`, `filter`, and `groups`
2. **Operator values**: Only `"and"` or `"or"` allowed
3. **Filter values**: Only `"include"` or `"exclude"` allowed
4. **Groups**: Array of filter groups, each with `filter`, `operator`, and `conditions`
5. **Group constraints**: Maximum 3 groups per data filter
6. **Conditions**: Array of condition objects with `operand`, `operator`, and `value`
7. **Condition constraints**: Maximum 3 conditions per group
8. **Operand**: Must be valid field name from dataset schema
9. **Condition operators**: Only `"="`, `"contains"`, `"in"`, `"start with"`, `"end with"` allowed
10. **Value types**: Must be `string`, `number`, or `boolean`
11. **Field naming**: Use dot notation for nested fields (e.g., `"source.ip"`)
12. **Nesting**: Groups can be nested within groups following same structure
13. **Validation**: All required fields must be present and values must be valid
14. **Performance**: Use `"and"` operators for better performance, limit nesting depth

### Validation Rules
- When `data.point` is "event.source", "event.category", "message", "event.source.type", or "event.severity", `aggregator` must be "count"
- All numeric fields should have appropriate minimum values
- Evaluation window and frequency cannot exceed 7 days (10080 minutes)
- Evaluation window and frequency values and units must always be equal
- Timestamps should be Unix timestamps

## Code Generation Guidelines

### Creating New SIEM Rules
1. Use the schema as a template
2. Generate unique IDs in format 100000000000XX (increment from existing rules)
3. Set appropriate severity based on the security impact
4. Configure filters to match specific log patterns
5. Set evaluation windows and frequencies appropriately (max 7 days, values and units must be equal)

### Example Rule Structure
```json
{
  "policy.name": "Category - Specific Event",
  "policy.type": "Log",
  "policy.tags": ["Default", "Security"],
  "policy.scheduled": "no",
  "policy.context": {
    "entity.type": "event.source.type",
    "entities": ["Linux"],
    "data.point": "message",
    "aggregator": "count",
    "operator": ">=",
    "value": 1,
    "trigger.mode": "individual",
    "evaluation.window": 5,
    "evaluation.window.unit": "minute",
    "evaluation.frequency": 5,
    "evaluation.frequency.unit": "minute",
    "policy.severity": "WARNING",
    "policy.result.by": ["event.source"],
    "policy.trigger.occurrences": 1,
    "policy.auto.clear.timer.seconds": 0,
    "filters": {
      "data.filter": {
        "operator": "and",
        "filter": "include",
        "groups": [
          {
            "filter": "include",
            "operator": "and",
            "conditions": [
              {
                "operand": "message",
                "operator": "contain",
                "value": "specific pattern"
              }
            ]
          }
        ]
      }
    }
  },
  "policy.email.notification.recipients": [],
  "policy.renotify": "yes",
  "policy.monitor.polling.failed.notification.timer.seconds": 0,
  "policy.monitor.polling.failed.notification.status": "no",
  "policy.renotification.timer.seconds": 0,
  "policy.actions": {},
  "policy.suppress.action": "no",
  "policy.archived": "no",
  "policy.creation.time": 1685348945,
  "policy.state": "no",
  "_type": "1",
  "id": 10000000000031
}
```

## Best Practices
1. **Naming**: Use clear, descriptive policy names
2. **Severity**: Match severity to actual security impact
3. **Filters**: Use specific, targeted filters to reduce false positives
4. **Evaluation**: Set appropriate time windows based on the event type
5. **Documentation**: Include comments in complex filter conditions
6. **Testing**: Validate rules against the schema before deployment

## Common Patterns
- **Authentication failures**: Look for failed login attempts
- **System services**: Monitor service starts/stops
- **Network activity**: Track connection attempts and data transfers
- **File access**: Monitor sensitive file access patterns
- **Process execution**: Track suspicious process launches
- **Range-based monitoring**: Use "range" operator for numeric thresholds (e.g., "10#20" for values between 10 and 20)

## SIEM Rule Generation Guide

### Information Required from User Prompts
When generating SIEM rules from user descriptions, gather:

1. **Security Event Type**
   - Attack type (brute force, malware, intrusion, etc.)
   - Threat category (authentication, network, system, application)

2. **Detection Parameters**
   - Threshold count (how many events trigger alert)
   - Time window (minutes, hours, days)
   - Severity level based on impact

3. **Log Source Information**
   - Operating system (Linux, Windows)
   - Service/application (SSH, web server, database)
   - Log format and field names

4. **Filter Conditions**
   - Specific keywords or patterns to match
   - Field names to monitor
   - Value ranges or exact matches
   - Boolean logic (AND/OR combinations)

### Common Field Names by Category
- **Authentication**: user.name, auth.method, auth.result, source.ip
- **Network**: source.ip, dest.ip, source.port, dest.port, protocol
- **System**: process.name, process.pid, file.path, service.name
- **Application**: http.status, http.method, url.path, user.agent

### Severity Guidelines
- **WARNING**: Low impact, informational alerts
- **MAJOR**: Medium impact, requires attention
- **CRITICAL**: High impact, immediate response required

### Default Time Windows by Event Type
- **Brute Force**: 5-15 minutes
- **Network Scanning**: 1-5 minutes  
- **System Changes**: 1-60 minutes
- **File Access**: 1-30 minutes

### Tag Recommendations
- Always include: ["Default", "Security"]
- Add specific tags: ["Authentication", "Network", "System", "Application"]
- Add OS tags: ["Linux", "Windows"] as appropriate
- Add MITRE ATT&CK tags: ["T1110", "T1078", "T1021"] as relevant

### MITRE ATT&CK Integration
When users provide MITRE technique context, incorporate:

1. **MITRE Technique Mapping**
   - Add technique IDs to policy tags (e.g., "T1110" for Brute Force)
   - Include tactic names in policy names where relevant
   - Map techniques to appropriate severity levels

2. **Common MITRE Techniques for SIEM Rules**
   - **T1110** - Brute Force (Authentication attacks)
   - **T1078** - Valid Accounts (Account abuse)
   - **T1021** - Remote Services (Lateral movement)
   - **T1059** - Command and Scripting Interpreter
   - **T1055** - Process Injection
   - **T1003** - OS Credential Dumping
   - **T1087** - Account Discovery
   - **T1083** - File and Directory Discovery
   - **T1057** - Process Discovery
   - **T1018** - Remote System Discovery

3. **MITRE-Based Policy Naming**
   - Format: "MITRE_TACTIC - Technique Description"
   - Examples:
     - "Credential Access - Brute Force Attack (T1110)"
     - "Lateral Movement - Remote Services (T1021)"
     - "Discovery - Account Discovery (T1087)"

4. **Technique-Based Severity Mapping**
   - **CRITICAL**: Credential dumping, privilege escalation, data exfiltration
   - **MAJOR**: Lateral movement, persistence, defense evasion
   - **WARNING**: Discovery, collection, reconnaissance

## Error Prevention
- Always validate JSON against the schema
- Check for required fields
- Ensure proper data types (strings vs numbers)
- Verify enum values are correct
- Test filter conditions for accuracy

## Security Considerations
- Use appropriate severity levels
- Configure notifications for critical events
- Set up proper escalation procedures
- Monitor rule effectiveness and adjust as needed
- Archive old rules instead of deleting them