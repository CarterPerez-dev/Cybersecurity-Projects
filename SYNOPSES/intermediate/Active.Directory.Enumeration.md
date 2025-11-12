# Active Directory Enumeration Tool

## Overview
Build a comprehensive tool that enumerates Active Directory users, groups, computers, and permission structures via LDAP queries, identifying privileged accounts, stale accounts, and misconfigurations. This project teaches directory services, LDAP protocol, and demonstrates reconnaissance techniques used in enterprise penetration testing and security assessments.

## Step-by-Step Instructions

1. **Understand Active Directory structure and LDAP protocol** by learning that Active Directory stores enterprise identity and security information in hierarchical structure: domains (forests) contain organizational units (OUs), users, groups, and computers. LDAP is the protocol querying AD: connect to domain controller on port 389 (LDAP) or 636 (LDAPS), authenticate with domain credentials, and execute search queries returning objects matching specified criteria. Study LDAP Distinguished Names (DN) format, common object classes (user, group, computer), and useful attributes (userAccountControl flags, lastLogon timestamps, memberOf groups).

2. **Implement LDAP connection and authentication** using `ldap3` Python library to connect to Active Directory domain controller. Build functions that bind to LDAP with provided credentials, handle both simple and NTLM authentication, and gracefully manage connection failures. Implement domain controller discovery using DNS queries (SRV records) to automatically locate AD infrastructure without manual configuration.

3. **Build user enumeration functionality** querying all users in directory, extracting attributes including username, display name, email, last logon timestamp, password last set, account status (enabled/disabled), and User Account Control (UAC) flags. Identify privileged users (members of Domain Admins, Enterprise Admins, Schema Admins groups), detect service accounts (likely to have long-standing passwords), and flag suspicious accounts (never logged in, password never expires, disabled accounts that should be cleaned up).

4. **Create group enumeration and membership analysis** extracting all groups in directory and analyzing membership: identify security groups vs. distribution groups, determine nested group membership (groups containing other groups), find users with unusual group membership, and detect groups with excessive members (often misconfigured). Create dependency graphs showing group hierarchies and membership relationships for permission analysis.

5. **Implement computer enumeration** discovering all domain-joined computers, their operating systems, last logon times, and DNS names. Identify stale computers (not logged in for 90+ days, good cleanup candidates), detect operating system patterns (count of Windows 10 vs. Windows 7, outdated OSes), and flag computers with potentially risky configurations (those without required security patches, unusual hostnames).

6. **Build permission and privilege analysis** determining effective permissions for users/groups over organizational units and resources. Analyze privileged group memberships identifying who can perform administrative actions, trace delegation of authority (who delegated what permissions to whom), and identify privilege accumulation (users with more privileges than their role requires). Create permission matrices showing which users can access which resources.

7. **Add stale account and misconfiguration detection** identifying security risks: accounts not logged in for 90+ days (should be disabled), accounts with passwords set to never expire (contrary to security policy), disabled accounts still present (should be deleted), groups with empty membership (should be removed), and orphaned accounts (belonging to deleted departments). Create remediation recommendations for each finding.

8. **Build comprehensive reporting with visualization** generating reports showing AD structure, user/group statistics, identified risks, and privilege distributions. Create domain trust visualizations showing forest structure and trust relationships, group membership trees showing hierarchies, and access control matrices. Export findings in formats suitable for security assessments (HTML reports, CSV data exports, JSON for tool integration). Include documentation explaining AD concepts, common misconfigurations, remediation steps, and comparison to commercial AD security tools (BloodHound, Adalanche).

## Key Concepts to Learn
- Active Directory structure and organization
- LDAP protocol and query syntax
- DN (Distinguished Names) and object attributes
- Group membership and nested groups
- User Account Control (UAC) flags
- Permission analysis and delegation
- Security risk identification
- Data visualization and reporting

## Deliverables
- LDAP connection and authentication
- User enumeration with privilege identification
- Group enumeration and membership analysis
- Computer enumeration and OS detection
- Permission and privilege analysis
- Stale account and misconfiguration detection
- Visual domain structure and trust diagrams
- Comprehensive security assessment reporting
