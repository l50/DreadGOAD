<!-- DOCSIBLE START -->
# mssql_ssms

## Description

Install SQL Server Management Studio

## Requirements

- Ansible >= 2.15

## Role Variables

## Tasks

### main.yml

- **Check if reboot is pending before SSMS install** (ansible.windows.win_powershell)
- **Record pre-reboot boot time baseline (pre-SSMS install)** (ansible.windows.win_powershell) - Conditional
- **Reboot before SSMS install if pending** (block) - Conditional
- **Trigger reboot via win_reboot** (ansible.windows.win_reboot)
- **Check SQL Server Manager Studio installer exists** (ansible.windows.win_stat)
- **Get the installer** (ansible.windows.win_get_url) - Conditional
- **Check SSMS installation already done** (ansible.windows.win_powershell)
- **Ensure BITS is running (VS Installer download engine)** (ansible.windows.win_service) - Conditional
- **Add Windows Defender exclusions for SSMS install paths** (ansible.windows.win_powershell) - Conditional
- **Kill any zombie SSMS installer processes from prior aborted runs** (ansible.windows.win_powershell) - Conditional
- **Purge stale VS Installer instance state (prevents exit 1 from prior aborted SSMS install)** (ansible.windows.win_powershell) - Conditional
- **Kick off SSMS installer in background (avoid aws_ssm session drop)** (ansible.windows.win_powershell) - Conditional
- **Wait for SSMS installer to finish (poll marker file)** (ansible.windows.win_stat) - Conditional
- **Verify SSMS installer exit code (0 = success, 3010 = reboot required)** (block) - Conditional
- **Read SSMS installer exit code** (ansible.windows.win_powershell)
- **Record pre-reboot boot time baseline (post-SSMS install)** (ansible.windows.win_powershell) - Conditional
- **Reboot after install** (block) - Conditional
- **Trigger reboot via win_reboot** (ansible.windows.win_reboot)

## Example Playbook

```yaml
- hosts: servers
  roles:
    - mssql_ssms
```

## Author Information

- **Author**: Dreadnode
- **Company**: Dreadnode
- **License**: GPL-3.0-or-later

## Platforms

- Windows: all
<!-- DOCSIBLE END -->
