<!-- ©AngelaMos | 2026 -->
<!-- 01-CONCEPTS.md -->

# Nadezhda: Concepts

This document explains the ideas the project is built on. If you read only one file to understand *why* nadezhda works the way it does, read this one. Every concept here maps to a package you will meet in [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) and a function you will read in [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md).

## Feeds are a contract, scraping is a fallback

Publishers offer RSS and Atom feeds as a machine readable promise: here are my latest items, structured, with a title, a link, a publish time, and a summary. Nadezhda takes that promise at face value and treats feeds as the primary path. It only falls back to parsing raw HTML when a source offers no feed, and even then it does so per source and behind a switch.

This choice has an ethical edge. Fetching a feed a user configured is user directed retrieval, the same category as a browser loading a page or a feed reader polling for updates. Scraping arbitrary HTML across a site is crawler behavior. The two deserve different rules, and nadezhda enforces that difference: robots.txt is honored on the HTML article scrape path and is deliberately not applied to subscribed feed fetches. Several publishers, The Register among them, blanket disallow generic bots in robots.txt while serving a public feed for exactly this kind of reader. Respecting robots on the feed would mean refusing a document the publisher explicitly built for you.

The seven seed feeds (Krebs on Security, The Hacker News, BleepingComputer, SecurityWeek, Dark Reading, The Register, and CISA) were each verified live. A useful thing you learn immediately: only two of the seven ship the full article body in the feed. The other five are summary only. That bounds how many CVEs you can extract, because you can only find a CVE ID in text the feed actually gives you.

## The CVE intelligence stack

A CVE identifier like CVE-2021-44228 is just a name. It says "this specific vulnerability exists" and nothing about how bad it is, whether it is being exploited, or how likely exploitation is. Four different data sources answer those questions, and each answers a different one. Understanding what each is for is the core of this project.

### CVSS: how severe is it, in theory

The Common Vulnerability Scoring System turns a vulnerability's characteristics into a number from 0.0 to 10.0 and a band (LOW, MEDIUM, HIGH, CRITICAL). There are several versions in circulation. Version 2 is old. Versions 3.0 and 3.1 are the common ones. Version 4.0 arrived in 2023 and is slowly spreading. A single CVE record may carry a score in several versions, one version, or none at all.

Nadezhda resolves this with a fixed precedence: prefer v4.0, then v3.1, then v3.0, then v2.0. Newer is better, and a missing score is a real possibility the code handles rather than assumes away. This is why the stored score is a nullable value and not a plain number.

The subtle part is *where* the score lives. In the CVE Program record for **Log4Shell (CVE-2021-44228)**, the CVSS metric does not sit in the vendor's own container. Apache's container carries only a placeholder `other` metric. The real 10.0 score lives in a second container added by CISA's enrichment program. A parser that only looks at the vendor container reports "no score" for the single most famous vulnerability of the decade. Contrast **Citrix Bleed 2 (CVE-2025-5777)**, whose CVSS 4.0 score of 9.3 sits in the vendor container where you would expect it. The lesson is to look in both places and apply the precedence across everything you find.

### CWE: what kind of weakness is it

Where CVSS scores severity, the Common Weakness Enumeration classifies the *kind* of flaw. CVE-2025-5777 is CWE-125, an out of bounds read. Log4Shell is CWE-502, deserialization of untrusted data. CWE is what lets you say "we keep shipping the same class of bug" across many CVEs, and it is a natural axis to filter or group on.

### CISA KEV: is it being exploited right now

The single most actionable signal in the stack is the CISA Known Exploited Vulnerabilities catalog. A CVE on the KEV catalog is not a theoretical risk. CISA lists it because it has evidence of active exploitation against real targets. A CVSS 6.5 on the KEV catalog frequently deserves your attention before a CVSS 9.8 that nobody has touched.

The catalog is a single JSON download, which makes it cheap to fetch once per run and diff. It carries one field that trips up almost everyone: `knownRansomwareCampaignUse` is not a boolean. It is the string `"Known"` or `"Unknown"`. Treat it as a boolean and every entry looks the same. Map the string explicitly and you recover a genuinely useful signal, because a KEV entry with known ransomware use is about as urgent as security news gets.

### FIRST EPSS: how likely is exploitation

The Exploit Prediction Scoring System, published by FIRST, is a daily updated probability between 0 and 1 that a given CVE will be exploited in the next 30 days, plus a percentile that places it against every other scored CVE. Where KEV tells you exploitation is already happening, EPSS tells you it is coming. Log4Shell's EPSS score sat near the very top of the scale, which is what you would expect for a flaw the whole internet was scanning for.

EPSS has its own trap. In the API response, the `epss` and `percentile` values are JSON *strings*, not numbers. Parse them as floats or the score silently reads as zero, which quietly disables one of your ranking signals without any error to tell you it happened.

## Keyless by default

You can get all of this without an API key. The CVE core comes from the CVE Program's cvelistV5 repository, which publishes every record as raw JSON at a predictable, bucketed URL. CISA KEV is a public download. FIRST EPSS is a public API. None of them gate the data behind a key.

The NVD API 2.0 is the source most tutorials reach for, and nadezhda supports it, but as an optional booster rather than a requirement. Without a key it is rate limited to five requests per thirty seconds, which is painful for a batch. With a key it is faster. The design decision was to make the keyless trio the default so the tool is fully useful the moment it is installed, and to let a user who has an NVD key opt into it. A tool whose core value is locked behind a key setup step is a tool most people never finish setting up.

## Clustering turns coverage into velocity

If BleepingComputer, The Hacker News, and Krebs all publish about the same flaw in the same afternoon, that is a stronger signal than any one of them alone. Measuring it requires recognizing that three differently worded headlines describe one story. That is clustering.

Nadezhda clusters with a connected components approach (union-find). Two items join the same cluster when they fall within a time window (72 hours by default) and either share a CVE ID or, if they come from different outlets, have titles similar enough by token set Jaccard overlap. The cross outlet condition on the title match is deliberate. Grouping two same titled items from the *same* source merges a publisher's own follow up posts, which is noise. Requiring the title match to cross outlets is what killed a real false positive during development, where two distinct CISA advisories happened to share a generic title.

The size and growth rate of a cluster become the *velocity* signal in ranking. A story eight outlets picked up in six hours ranks above a story one outlet ran a day ago, even if the second has a scarier CVE.

## Ranking is deterministic and news first

The final score for a cluster is a weighted sum of normalized signals:

```
score =  w_recency  * recency_decay(age)
       + w_velocity * normalized(cluster_size / age)
       + w_kev      * is_kev
       + w_cvss     * normalized(max_cvss)
       + w_epss     * max_epss
       + w_source   * source_weight
       + w_keyword  * keyword_match(watchlist)
```

`recency_decay` is an exponential half life function, so a story loses half its recency weight every configured number of hours. Every weight lives in configuration, not in the code, so there are no magic numbers to hunt for and the model is fully tunable.

The default weights are news first: recency, velocity, source, and keyword together carry 70 percent, and the CVE signals (KEV, CVSS, EPSS) carry the remaining 30. This reflects a specific product decision. Nadezhda is a security *news* tool. A breach or a campaign with no CVE at all should not be buried beneath a routine patch note just because the patch note has a number attached. The CVE data is intelligence that enriches a story, not the reason the story matters.

Because ranking is a pure function of stored inputs, the same corpus always produces the same order. That property is what lets the project assert its ranking with golden order tests: feed fixed inputs, expect one exact ordering.

## References

- **MITRE CVE**: the identifier system. https://www.cve.org
- **CVE Program cvelistV5**: the keyless record source. https://github.com/CVEProject/cvelistV5
- **CVSS**, published by FIRST: the scoring system and its versions. https://www.first.org/cvss/
- **CWE**, MITRE: the weakness taxonomy. https://cwe.mitre.org
- **CISA KEV**: the exploited-in-the-wild catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **FIRST EPSS**: exploitation probability. https://www.first.org/epss/
- **NVD API 2.0**: the optional booster. https://nvd.nist.gov/developers/vulnerabilities

## Testing your understanding

- Why does a CVSS 6.5 on the KEV catalog often outrank a CVSS 9.8 that is not? What would you change in the weights to make that happen or stop it?
- The project extracts fewer CVEs from five of the seven feeds than from the other two. Why, and where in the pipeline is that limit imposed?
- If EPSS scores are parsed as zero because of the string typing bug, which ranking signal disappears, and would any test catch it?
- Why is the title similarity condition restricted to cross outlet pairs? Construct an example where dropping that restriction produces a wrong cluster.
- Log4Shell's CVSS score is not in the vendor's container of its CVE record. Where is it, and what does a naive parser report instead?
