# Network Baseline Monitor

## Overview
Build a network monitoring system that establishes normal traffic behavior baselines through packet analysis, detects deviations indicating potential compromises or attacks, and generates anomaly reports. This project teaches statistical analysis, network behavior modeling, and demonstrates anomaly detection techniques used in network security operations centers.

## Step-by-Step Instructions

1. **Understand network behavior modeling and anomaly detection principles** by learning that normal networks have relatively consistent patterns: traffic volume varies by time of day and day of week, specific services communicate on expected ports, particular traffic directions dominate, and protocol distributions remain relatively stable. Anomalies deviate from these patterns indicating potential incidents (compromised systems sending unusual traffic, reconnaissance scanning, data exfiltration, malware communications). Study baseline establishment: requires minimum collection period (weeks/months) capturing seasonal variations, filtering known anomalies from baseline, and establishing statistical models (mean, standard deviation, percentiles) for each metric.

2. **Implement network traffic collection and aggregation** using packet sniffing (scapy) or NetFlow/sFlow collection to gather network data: capture or receive traffic statistics, aggregate by protocol, source/destination IP, port, and time window (per-minute, per-hour). Build efficient storage: raw packet capture is too voluminous, statistical aggregation reduces data to manageable sizes. Create time-series database (InfluxDB, Prometheus, or custom) storing traffic statistics with timestamps enabling historical analysis and comparison.

3. **Build baseline establishment workflow** capturing normal network behavior: collect traffic statistics over extended period (minimum 2-4 weeks, ideally 3-6 months capturing seasonal patterns), compute statistics for each metric (traffic volume by protocol, top talkers, port usage, geographic distribution), and store baseline profiles. Implement multiple baseline profiles: hourly baselines (expect different traffic 9am vs. 2am), daily baselines (weekdays different from weekends), and seasonal baselines (holiday traffic patterns differ from normal).

4. **Create statistical anomaly detection** comparing current traffic against baselines: for each metric, compute current values and compare to baseline distribution using statistical methods (z-score detection: flag if current value >3 standard deviations from mean, moving average detection: compare against recent historical average, IQR method: flag values beyond interquartile range). Combine multiple signals into composite anomaly score (weighted combination of individual metric anomalies).

5. **Implement traffic pattern analysis** identifying specific anomalies beyond statistical deviations: detect port scanning (connection attempts to many ports from single source), data exfiltration (unusual volume to external IPs, especially to new/suspicious destinations), command-and-control communication (periodic connections to known malicious IPs, suspicious beaconing patterns), and lateral movement (unusual east-west traffic within network). Build pattern matching rules for known attack signatures.

6. **Create alert and escalation logic** triggering notifications when anomalies detected: graduated alerting (low anomaly score = log only, medium = alert analysts, high = auto-escalate), contextual alerts (alert if same IP repeatedly triggers alerts indicating persistence), and alert correlation (multiple simultaneous anomalies suggest coordinated incident vs. isolated event). Implement alert suppression preventing fatigue from repeated same anomalies.

7. **Build dashboards and visualization tools** displaying network behavior and anomalies: show baseline vs. current traffic metrics side-by-side for comparison, display anomaly timeline highlighting when deviations occurred, create geographic maps showing traffic origins/destinations, build protocol distribution comparisons. Provide drill-down capabilities: click on anomaly to view related traffic, analyze specific flows in detail, investigate source/destination systems.

8. **Build comprehensive documentation** explaining baseline establishment methodology, anomaly detection techniques, and investigation procedures. Discuss limitations (baselines require time to establish, new legitimate services may appear similar to attacks, encrypted traffic limits visibility into content), compare to commercial network security platforms (network behavioral analysis appliances, managed detection and response services). Provide incident investigation procedures: when anomaly detected, what analysis steps to take, how to determine if legitimate or malicious, integration with incident response workflows. Include examples of detected anomalies in real-world incidents demonstrating value of baseline monitoring.

## Key Concepts to Learn
- Network traffic collection and aggregation
- Time-series data storage
- Statistical modeling and baselines
- Anomaly detection algorithms
- Z-score and IQR methods
- Pattern recognition and signatures
- Alert correlation and escalation
- Network behavior analysis

## Deliverables
- NetFlow/sFlow or packet-based collection
- Traffic aggregation and statistics
- Baseline establishment workflow
- Multi-temporal baselines (hourly, daily, seasonal)
- Z-score and moving average anomaly detection
- Pattern-based detection for specific attacks
- Alert generation and escalation
- Correlation engine for multi-signal detection
- Interactive dashboards and visualizations
- Drill-down and investigation capabilities
