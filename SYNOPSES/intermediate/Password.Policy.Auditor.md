# Password Policy Auditor

## Overview
Build a tool that audits Active Directory and local password policies against security best practices, tests for weak password implementations, and generates compliance reports identifying policy violations. This project teaches password security concepts, policy analysis, and demonstrates compliance assessment techniques used in security audits.

## Step-by-Step Instructions

1. **Understand password security best practices and policy standards** by learning NIST guidelines (minimum 12 characters, no composition requirements, avoid periodic changes unless compromised), CIS benchmarks, and regulatory standards (HIPAA, PCI-DSS, SOC 2). Study password policy components: minimum length requirements, complexity requirements (uppercase, lowercase, numbers, symbols), password age (how old password can be), password history (prevent reuse), account lockout policies (lock after N failed attempts). Understand trade-offs: complex requirements improve security but reduce usability and increase password reuse.

2. **Implement Active Directory policy extraction** using LDAP queries to retrieve password policy settings from Domain, Default Domain Policy GPO (Group Policy Object). Extract policy parameters: password minimum length, complexity requirement, maximum age, minimum age, history count, lockout threshold, and lockout duration. Build functions that query multiple domains if forest contains multiple domains, and handle policies applied to specific OUs that override domain defaults.

3. **Create local system policy analysis** for Windows systems, reading password policy settings from Security Policy or Registry: extract local account policies, user rights assignments, and audit policy settings. Build Linux policy analysis querying PAM (Pluggable Authentication Modules) configuration and checking password aging settings (/etc/login.defs, /etc/pam.d files). Support multiple operating systems through abstracted policy readers.

4. **Build policy evaluation and scoring** against best practices and regulatory requirements: compare extracted policies against known good baselines, identify gaps (minimum length too short, no lockout policy, password history too low), and calculate compliance score. Implement configurable evaluation criteria allowing different security levels (strict for financial institutions, moderate for general business, basic for non-critical systems). Generate findings with severity levels indicating which policy gaps present greatest risk.

5. **Implement password strength testing** attempting to crack user passwords: identify accounts with weak/default passwords (common patterns like "Password123!", admin credentials, company names), test password against wordlists and patterns. Build password strength calculator estimating entropy of each password and determining whether it meets minimum strength requirements. Test policy compliance of all user passwords (do they meet minimum length, complexity requirements?).

6. **Create policy violation detection** identifying which users violate password policies: accounts with passwords older than policy maximum age (should have changed password), accounts with identical or similar passwords suggesting weak history implementation (users changing passwords in ways that avoid history), accounts with never-expiring passwords. Build user reports showing each policy violation with user details and recommendations.

7. **Implement remediation recommendations and reporting** generating detailed compliance reports showing policy audit results, identified gaps, vulnerable passwords, and remediation steps. Provide recommendations for policy improvements (increase minimum length to 14 characters, implement account lockout after 5 failed attempts), create action items for administrative remediation, and calculate compliance percentage. Support different report formats for different audiences (executive summary with compliance score, detailed technical report with all findings).

8. **Build comprehensive documentation** explaining password policy concepts and security rationale, providing benchmarks and regulatory requirements comparison, and including deployment guidance. Discuss limitations (password policy is one component of identity security, also need multi-factor authentication, secure password reset procedures, user training), compare to commercial compliance auditing tools, and explain how password auditing fits into broader identity and access management (IAM) assessments. Include examples of policy audit reports and remediation workflows.

## Key Concepts to Learn
- Password security standards (NIST, CIS, regulatory)
- Active Directory and local policy structures
- Policy extraction and parsing
- Password strength assessment
- Compliance scoring and evaluation
- Remediation recommendation generation
- Audit reporting and documentation
- Multi-OS policy analysis

## Deliverables
- Active Directory password policy extraction
- Local system policy analysis (Windows, Linux)
- Policy evaluation against best practices
- Password strength testing
- Policy violation identification
- User compliance reporting
- Remediation recommendations
- Comprehensive audit reports
