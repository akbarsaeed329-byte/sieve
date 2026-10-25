"""Detection engineering helpers: rule drafts for coverage gaps.

Curated, reviewed drafts for common techniques (Sigma for portability, Wazuh XML for direct use). Drafts are
never deployed by Sieve: the UI requires a backtest over your own stored alerts first, and you copy the rule
into Wazuh yourself. When an AI provider is enabled, it may propose a draft for other techniques; that draft is
labelled as AI-written, parsed by the same backtest engine, and rejected if it does not parse.
"""

from __future__ import annotations

LIBRARY: dict[str, dict] = {
    "T1110": {
        "title": "Repeated authentication failures from one source",
        "wazuh": """<rule id="100110" level="10" frequency="8" timeframe="120">
  <if_matched_group>authentication_failed</if_matched_group>
  <same_source_ip />
  <description>Brute force: 8 failed logins from $(srcip) in 2 minutes</description>
  <mitre><id>T1110</id></mitre>
</rule>""",
        "sigma": """title: Repeated authentication failures from one source
logsource: {product: linux, service: auth}
detection:
  selection:
    rule.groups|contains: authentication_failed
  condition: selection
tags: [attack.credential_access, attack.t1110]""",
    },
    "T1136": {
        "title": "New local account created",
        "wazuh": """<rule id="100136" level="10">
  <if_group>adduser</if_group>
  <description>New account created: $(dstuser)</description>
  <mitre><id>T1136.001</id></mitre>
</rule>""",
        "sigma": """title: New local account created
detection:
  selection:
    rule.groups|contains: adduser
  condition: selection
tags: [attack.persistence, attack.t1136.001]""",
    },
    "T1059": {
        "title": "Encoded PowerShell command",
        "wazuh": """<rule id="100159" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell.*\\s-(e|en|enc|enco|encodedcommand)\\s</field>
  <description>Encoded PowerShell command line</description>
  <mitre><id>T1059.001</id><id>T1027</id></mitre>
</rule>""",
        "sigma": """title: Encoded PowerShell command
detection:
  selection:
    data.win.eventdata.commandLine|contains: ' -enc '
  condition: selection
tags: [attack.execution, attack.t1059.001]""",
    },
    "T1053": {
        "title": "Scheduled task or cron job created",
        "wazuh": """<rule id="100153" level="8">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\\\schtasks\\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
  <description>Scheduled task created</description>
  <mitre><id>T1053.005</id></mitre>
</rule>""",
        "sigma": """title: Scheduled task created
detection:
  selection:
    data.win.eventdata.image|endswith: '\\schtasks.exe'
    data.win.eventdata.commandLine|contains: '/create'
  condition: selection
tags: [attack.persistence, attack.t1053.005]""",
    },
    "T1003": {
        "title": "LSASS memory access (credential dumping)",
        "wazuh": """<rule id="100103" level="13">
  <if_group>sysmon_event_10</if_group>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)\\\\lsass\\.exe$</field>
  <description>Process accessed LSASS memory: possible credential dumping</description>
  <mitre><id>T1003.001</id></mitre>
</rule>""",
        "sigma": """title: LSASS memory access
detection:
  selection:
    data.win.eventdata.targetImage|endswith: '\\lsass.exe'
  condition: selection
tags: [attack.credential_access, attack.t1003.001]""",
    },
    "T1070": {
        "title": "Security log cleared",
        "wazuh": """<rule id="100170" level="12">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^1102$</field>
  <description>Windows security log cleared</description>
  <mitre><id>T1070.001</id></mitre>
</rule>""",
        "sigma": """title: Security log cleared
detection:
  selection:
    data.win.system.eventID: '1102'
  condition: selection
tags: [attack.defense_evasion, attack.t1070.001]""",
    },
    "T1486": {
        "title": "Mass file modification (possible ransomware)",
        "wazuh": """<rule id="100186" level="13" frequency="50" timeframe="60">
  <if_matched_group>syscheck</if_matched_group>
  <same_location />
  <description>50 file changes in 60 seconds: possible ransomware</description>
  <mitre><id>T1486</id></mitre>
</rule>""",
        "sigma": """title: Mass file modification
detection:
  selection:
    rule.groups|contains: syscheck
  condition: selection
tags: [attack.impact, attack.t1486]""",
    },
    "T1021": {
        "title": "Remote login with a local admin account",
        "wazuh": """<rule id="100121" level="9">
  <if_group>authentication_success</if_group>
  <field name="win.eventdata.logonType">^10$</field>
  <description>RDP logon: $(win.eventdata.targetUserName)</description>
  <mitre><id>T1021.001</id></mitre>
</rule>""",
        "sigma": """title: RDP logon
detection:
  selection:
    rule.groups|contains: authentication_success
    data.win.eventdata.logonType: '10'
  condition: selection
tags: [attack.lateral_movement, attack.t1021.001]""",
    },
}


def draft_for(technique: str) -> dict | None:
    base = technique.split(".")[0]
    d = LIBRARY.get(base)
    return {"technique": technique, **d, "source": "Sieve library (reviewed)"} if d else None
