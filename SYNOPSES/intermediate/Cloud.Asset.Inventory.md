# Cloud Asset Inventory Tool

## Overview
Build a multi-cloud inventory management tool that automatically discovers and catalogs all resources across AWS, Azure, and GCP, tracks changes over time, identifies untagged resources, and calculates infrastructure costs. This project teaches cloud platform APIs, infrastructure-as-code principles, and demonstrates tools used for cloud security and cost management.

## Step-by-Step Instructions

1. **Understand cloud provider APIs and authentication** by researching AWS SDK (boto3), Azure SDK, and Google Cloud SDK for programmatic resource discovery. Learn authentication methods: AWS IAM roles/credentials, Azure service principals, GCP service accounts. Set up appropriate permissions allowing read-only access to resource inventory without modification rights. Understand API rate limiting and implement backoff strategies preventing throttling.

2. **Implement AWS resource discovery** using boto3 to enumerate EC2 instances, S3 buckets, RDS databases, Lambda functions, security groups, VPCs, and other infrastructure components. Extract metadata: resource IDs, types, creation timestamps, tags, configuration details, and costs. Build recursive discovery following relationships (instances belong to VPCs, security groups protect instances, EBS volumes attach to instances) creating complete infrastructure graph.

3. **Create Azure resource enumeration** using Azure SDK to discover virtual machines, storage accounts, databases, app services, and other managed resources. Extract similar metadata as AWS implementation, handle Azure's hierarchical structure (subscriptions, resource groups, resources), and maintain consistency in data model. Support both Azure Resource Manager (ARM) and classic resources if applicable to target environments.

4. **Build GCP resource discovery** querying Google Cloud APIs to enumerate Compute Engine instances, Cloud Storage buckets, Cloud SQL databases, App Engine services, and Kubernetes clusters. Maintain consistent data model across all three cloud providers enabling unified inventory interface. Handle GCP's project-based organization and service-specific discovery patterns.

5. **Implement change tracking and versioning** storing snapshots of infrastructure at different points in time, detecting what changed between snapshots (new resources created, existing resources modified, resources deleted). Build timeline showing infrastructure evolution, enable before-and-after comparison of configurations, and identify drift from baseline (resources created outside change management processes).

6. **Create tagging and metadata analysis** identifying resources missing required tags (standard tags for cost allocation, ownership, project association), detecting inconsistent tagging across resources, and analyzing tag coverage (what percentage of resources have all required tags). Flag untagged resources for cleanup and implement recommendations for tagging consistency improving cost allocation and resource management.

7. **Build cost analysis and reporting** extracting cost information from each cloud provider's billing APIs: calculate total infrastructure spending, allocate costs to individual resources, identify cost trends (spending increasing or decreasing), and project future costs based on current usage patterns. Identify cost optimization opportunities (unused resources, oversized instances, cheaper alternative configurations). Generate cost allocation reports enabling chargeback and budget management.

8. **Build comprehensive reporting and dashboards** with multi-format export: create inventory reports (CSV, JSON) showing all discovered resources with details, build dashboards visualizing resource distribution across clouds, display cost breakdown by service type/cloud provider, and generate change reports showing infrastructure modifications. Implement alerting on significant changes (major resource creation/deletion) or cost anomalies. Compare your tool to commercial solutions (Zesty, CloudMapper, Forseti) and discuss limitations (API permissions affect visibility, real-time accuracy depends on API polling frequency).

## Key Concepts to Learn
- Cloud provider APIs and SDKs
- IAM and authentication across cloud platforms
- Infrastructure discovery and enumeration
- Resource metadata and relationships
- Change tracking and versioning
- Tagging strategies and compliance
- Cost analysis and optimization
- Multi-cloud unified management
- Infrastructure-as-code concepts

## Deliverables
- AWS resource discovery and enumeration
- Azure resource discovery and enumeration
- GCP resource discovery and enumeration
- Unified inventory data model
- Change tracking with snapshots
- Tagging compliance analysis
- Cost tracking and allocation
- Multi-cloud dashboards and reports
