# Red Mudnester

This repository contains observed attack steps described in the [Red Mudnester report](https://www.huntandhackett.com/redmudnester) shared as TLP:WHITE. The goal of sharing the observed attack steps is to help other SOC analysts, Threat Hunters and Incident Responders to improve their detection capability.

The attack steps are divived in the following categories:

* Indicators of compromise (IOCs)
* Hunting queries
* Detection rules

## Indicators of Compromise

[RedMudnesterIOCs.csv](RedMudnesterIOCs.csv) contains IOCs also shown in the table below related to the threat actor described in the report. Note that usage of these IOCs in different environments can lead to false positives.

Type           |  IOC                                         |  Description
----------------|---------------------------------------------|-------------------------------------------------------------------------------------
File name       |  `bu.exe`                                   |  Ransomware
File name       |  `buren_cryptor.exe`                        |  Ransomware
File name       |  `spools.exe`                               |  Cobalt Strike
File name       |  `tni.exe`                                  |  Total Network Inventory
File name       |  `MEGAsync.exe`                             |  MEGAsync
File name       |  `MEGAupdater.exe`                          |  MEGAsync
Hash (SHA1)     |  `899b02fa31b29c67437b67bff8959d8dee288d9d` |  `bu.exe`, `buren_cryptor.exe`
Hash (SHA1)     |  `d92522dcaec6a3d22a1b05d8f5c9ebae08ec74da` |  `MEGAsync.exe`
Hash (SHA1)     |  `4e7578c638d480da1c3b3b3b54f46b153717981d` |  `MEGAupdater.exe`
Scheduled Task  |  `MEGAsync Update`                          |  MEGAsync update task
Scheduled Task  |  `\crypt!`                                  |  Used to execute the ransomware
Folder name     |  `C:\tmp`                                   |  Used to distribute the ransomware with the Scheduled Task `\crypt!`
Folder name     |  `C:\Windows\Temp`                          |  Used for storing Cobalt Strike and Total Network Inventory
Folder name     |  `C:\users\<USER>\Desktop`                  |  From this location MEGAsync, PCHunter, `bu.exe` and `buren_cryptor.exe` were executed

## Hunting queries

Based on the IoCs and the observed activity from the threat actor the Jupyter notebook [RedMudnester.ipynb](RedMudnester.ipynb) was made. This notebook contains Timesketch queries that can be used to search for traces related to techniques that have been used by the threat actor.

| Name | MITRE technique |
|---|---|
| Remote interactive login to Domain Controller | [T1078.002](https://attack.mitre.org/techniques/T1078/002/), [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| Network login to Domain Controller by the Administrator account | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) |
| Scheduled Task related to MEGAsync | [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) |
| Scheduled Task related the ransomware of the threat actor| [T1486](https://attack.mitre.org/techniques/T1486/) |
| McAfee access protection rule alerts | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |
| Stopped services before execution of the ransomware of the threat actor | [T1489](https://attack.mitre.org/techniques/T1489) |
| MEGAsync process execution | [T1588.002](https://attack.mitre.org/techniques/T1588/002/) |

## Detection rules

The table below shows an overview of detection rules in YARA-L format [1] to detect used techniques by the threat actor.

| Name | MITRE Technique |
|---|---|
| [Brute force attempt](rules/brute_force_attempt.yaral) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| [User added to Domain Admin group](rules/user_added_to_domain_admin_group.yaral) | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| [Total Network Inventory file access](rules/total_network_inventory_file_access.yaral) | [T1046](https://attack.mitre.org/techniques/T1046) |
| [Total Network Inventory process execution](rules/total_network_inventory_process_execution.yaral) | [T1046](https://attack.mitre.org/techniques/T1046) |
| [MEGAsync file access](rules/megasync_file_access.yaral) | [T1567.002](https://attack.mitre.org/techniques/T1567/002/)
| [MEGAsync process execution](rules/megasync_process_execution.yaral) | [T1567.002](https://attack.mitre.org/techniques/T1567/002/)
| [MEGAsync network connection](rules/megasync_network_connection.yaral) | [T1567.002](https://attack.mitre.org/techniques/T1567/002/)
| [MEGAsync scheduled task](rules/megasync_scheduled_task.yaral) | [T1567.002](https://attack.mitre.org/techniques/T1567/002/)

## References

[1] <https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax>
