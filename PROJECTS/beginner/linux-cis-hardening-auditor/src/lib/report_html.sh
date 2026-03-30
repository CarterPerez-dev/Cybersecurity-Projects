#!/usr/bin/env bash
# ©AngelaMos | 2026
# report_html.sh

html_escape() {
    local s="$1"
    s="${s//&/\&amp;}"
    s="${s//</\&lt;}"
    s="${s//>/\&gt;}"
    s="${s//\"/\&quot;}"
    printf '%s' "$s"
}

_html_score_color() {
    local score="$1"
    if [[ "$score" == "N/A" ]]; then
        printf '%s' "#565f89"
        return
    fi
    local int_score="${score%.*}"
    if (( int_score >= 80 )); then
        printf '%s' "#9ece6a"
    elif (( int_score >= 60 )); then
        printf '%s' "#e0af68"
    else
        printf '%s' "#f7768e"
    fi
}

_html_status_class() {
    local status="$1"
    case "$status" in
        "$STATUS_PASS") printf '%s' "pass" ;;
        "$STATUS_FAIL") printf '%s' "fail" ;;
        "$STATUS_WARN") printf '%s' "warn" ;;
        "$STATUS_SKIP") printf '%s' "skip" ;;
    esac
}

_emit_html_head() {
    cat <<'CSSEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIS Benchmark Audit Report</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#1a1b26;--card:#24283b;--text:#c0caf5;--text-dim:#565f89;
  --pass:#9ece6a;--fail:#f7768e;--warn:#e0af68;--skip:#565f89;
  --border:#414868;--code-bg:#1a1b26;--accent:#7aa2f7;
}
html{font-size:16px;scroll-behavior:smooth}
body{
  background:var(--bg);color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;
  line-height:1.6;padding:0;margin:0;
}
.container{max-width:1100px;margin:0 auto;padding:1.5rem}
header{text-align:center;padding:2.5rem 1rem 1.5rem;border-bottom:1px solid var(--border)}
header h1{font-size:1.75rem;font-weight:700;color:#c0caf5;margin-bottom:.5rem}
header .meta{font-size:.85rem;color:var(--text-dim);display:flex;flex-wrap:wrap;justify-content:center;gap:.5rem 1.5rem;margin-top:.5rem}
header .meta span{white-space:nowrap}
.dashboard{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:1rem;margin:2rem 0;
}
.card{
  background:var(--card);border:1px solid var(--border);border-radius:10px;
  padding:1.25rem 1rem;text-align:center;
}
.card .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim);margin-bottom:.35rem}
.card .value{font-size:1.85rem;font-weight:700}
.card.overall .value{font-size:2.5rem}
.card.pass .value{color:var(--pass)}
.card.fail .value{color:var(--fail)}
.card.warn .value{color:var(--warn)}
.card.skip .value{color:var(--skip)}
.card.total .value{color:var(--accent)}
.level-scores{
  display:flex;justify-content:center;gap:2.5rem;margin-bottom:2rem;
  flex-wrap:wrap;
}
.level-scores .ls{
  background:var(--card);border:1px solid var(--border);border-radius:8px;
  padding:.75rem 1.5rem;text-align:center;
}
.level-scores .ls .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-dim)}
.level-scores .ls .val{font-size:1.35rem;font-weight:700}
h2{font-size:1.25rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}
table{width:100%;border-collapse:collapse;margin-bottom:2rem;font-size:.9rem}
thead th{
  text-align:left;padding:.6rem .75rem;border-bottom:2px solid var(--border);
  font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text-dim);
}
thead th.num{text-align:center}
tbody td{padding:.55rem .75rem;border-bottom:1px solid var(--border)}
tbody td.num{text-align:center;font-variant-numeric:tabular-nums}
tbody td.pass{color:var(--pass)}
tbody td.fail{color:var(--fail)}
tbody td.warn{color:var(--warn)}
tbody td.skip{color:var(--skip)}
tbody td.score{font-weight:600}
.progress-bar{
  background:var(--bg);border-radius:6px;height:10px;overflow:hidden;
  min-width:80px;border:1px solid var(--border);
}
.progress-fill{height:100%;border-radius:6px;transition:width .3s ease}
.section-group{margin-bottom:1.5rem}
.section-group h3{font-size:1rem;color:var(--accent);margin-bottom:.75rem}
details.control{
  background:var(--card);border:1px solid var(--border);border-radius:8px;
  margin-bottom:.5rem;overflow:hidden;
}
details.control summary{
  display:flex;align-items:center;gap:.65rem;padding:.65rem 1rem;
  cursor:pointer;user-select:none;font-size:.9rem;list-style:none;
}
details.control summary::-webkit-details-marker{display:none}
details.control summary::before{
  content:"";display:inline-block;width:0;height:0;
  border-left:5px solid var(--text-dim);border-top:4px solid transparent;border-bottom:4px solid transparent;
  transition:transform .2s ease;flex-shrink:0;
}
details.control[open] summary::before{transform:rotate(90deg)}
.badge{
  display:inline-block;padding:.15em .6em;border-radius:999px;
  font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;
  line-height:1.4;flex-shrink:0;
}
.badge.pass{background:rgba(158,206,106,.15);color:var(--pass)}
.badge.fail{background:rgba(247,118,142,.15);color:var(--fail)}
.badge.warn{background:rgba(224,175,104,.15);color:var(--warn)}
.badge.skip{background:rgba(86,95,137,.2);color:var(--skip)}
.badge.level{background:rgba(122,162,247,.12);color:var(--accent);font-size:.65rem}
.control-id{font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:.85rem;color:var(--text-dim);flex-shrink:0}
.control-title{flex:1;min-width:0}
.control-detail{
  padding:.75rem 1rem 1rem 2.5rem;border-top:1px solid var(--border);
  font-size:.85rem;
}
.control-detail .evidence{
  background:var(--code-bg);border:1px solid var(--border);border-radius:6px;
  padding:.6rem .85rem;margin-bottom:.65rem;
  font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;
  font-size:.8rem;color:var(--text-dim);white-space:pre-wrap;word-break:break-word;
}
.control-detail .remediation{color:var(--warn)}
.control-detail .remediation code{
  background:var(--code-bg);border:1px solid var(--border);border-radius:4px;
  padding:.15em .4em;font-size:.8rem;
  font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;
}
footer{
  text-align:center;padding:2rem 1rem;margin-top:2rem;border-top:1px solid var(--border);
  font-size:.8rem;color:var(--text-dim);
}
@media(max-width:640px){
  .dashboard{grid-template-columns:repeat(2,1fr)}
  .card.overall{grid-column:1/-1}
  table{font-size:.8rem}
  thead th,tbody td{padding:.4rem .5rem}
  details.control summary{padding:.5rem .75rem;font-size:.82rem;gap:.45rem}
}
@media print{
  :root{--bg:#fff;--card:#f8f8f8;--text:#1a1a1a;--text-dim:#666;--border:#ddd;--code-bg:#f0f0f0}
  body{background:#fff;color:#1a1a1a}
  .card{box-shadow:none;border:1px solid #ddd}
  details.control{break-inside:avoid}
  .badge.pass{background:#e8f5e9;color:#2e7d32}
  .badge.fail{background:#ffebee;color:#c62828}
  .badge.warn{background:#fff8e1;color:#f57f17}
  .badge.skip{background:#f5f5f5;color:#757575}
}
</style>
</head>
CSSEOF
}

_emit_html_header() {
    local timestamp="$1"
    local hostname="$2"

    local score_color
    score_color=$(_html_score_color "$SCORE_OVERALL")

    local total=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_WARN + TOTAL_SKIP))

    local l1_display
    if [[ "$SCORE_LEVEL1" == "N/A" ]]; then
        l1_display="N/A"
    else
        l1_display="${SCORE_LEVEL1}%"
    fi

    local l2_display
    if [[ "$SCORE_LEVEL2" == "N/A" ]]; then
        l2_display="N/A"
    else
        l2_display="${SCORE_LEVEL2}%"
    fi

    local l1_color
    l1_color=$(_html_score_color "$SCORE_LEVEL1")
    local l2_color
    l2_color=$(_html_score_color "$SCORE_LEVEL2")

    local esc_hostname
    esc_hostname=$(html_escape "$hostname")
    local esc_os
    esc_os=$(html_escape "${DETECTED_ID} ${DETECTED_VERSION}")
    local esc_bench
    esc_bench=$(html_escape "$CIS_BENCHMARK")

    cat <<HEADEREOF
<body>
<div class="container">
<header>
<h1>CIS Benchmark Audit Report</h1>
<div class="meta">
<span>${esc_bench}</span>
<span>${esc_hostname}</span>
<span>OS: ${esc_os}</span>
<span>${timestamp}</span>
</div>
</header>
<section class="dashboard">
<div class="card overall">
<div class="label">Overall Score</div>
<div class="value" style="color:${score_color}">${SCORE_OVERALL}%</div>
</div>
<div class="card total">
<div class="label">Total</div>
<div class="value">${total}</div>
</div>
<div class="card pass">
<div class="label">Pass</div>
<div class="value">${TOTAL_PASS}</div>
</div>
<div class="card fail">
<div class="label">Fail</div>
<div class="value">${TOTAL_FAIL}</div>
</div>
<div class="card warn">
<div class="label">Warn</div>
<div class="value">${TOTAL_WARN}</div>
</div>
<div class="card skip">
<div class="label">Skip</div>
<div class="value">${TOTAL_SKIP}</div>
</div>
</section>
<div class="level-scores">
<div class="ls">
<div class="label">Level 1 Score</div>
<div class="val" style="color:${l1_color}">${l1_display}</div>
</div>
<div class="ls">
<div class="label">Level 2 Score</div>
<div class="val" style="color:${l2_color}">${l2_display}</div>
</div>
</div>
HEADEREOF
}

_emit_html_section_table() {
    cat <<'TABLESTART'
<h2>Section Breakdown</h2>
<table>
<thead>
<tr>
<th>Section</th>
<th class="num">Pass</th>
<th class="num">Fail</th>
<th class="num">Warn</th>
<th class="num">Skip</th>
<th class="num">Score</th>
<th>Progress</th>
</tr>
</thead>
<tbody>
TABLESTART

    local section
    for section in "${SECTION_ORDER[@]}"; do
        local p="${SECTION_PASS[$section]:-0}"
        local f="${SECTION_FAIL[$section]:-0}"
        local w="${SECTION_WARN[$section]:-0}"
        local s="${SECTION_SKIP[$section]:-0}"
        local score="${SCORE_BY_SECTION[$section]:-N/A}"

        local score_display
        if [[ "$score" == "N/A" ]]; then
            score_display="N/A"
        else
            score_display="${score}%"
        fi

        local bar_width
        if [[ "$score" == "N/A" ]]; then
            bar_width="0"
        else
            bar_width="$score"
        fi

        local bar_color
        bar_color=$(_html_score_color "$score")

        local esc_section
        esc_section=$(html_escape "$section")

        printf '<tr>\n'
        printf '<td>%s</td>\n' "$esc_section"
        printf '<td class="num pass">%d</td>\n' "$p"
        printf '<td class="num fail">%d</td>\n' "$f"
        printf '<td class="num warn">%d</td>\n' "$w"
        printf '<td class="num skip">%d</td>\n' "$s"
        printf '<td class="num score" style="color:%s">%s</td>\n' "$bar_color" "$score_display"
        printf '<td><div class="progress-bar"><div class="progress-fill" style="width:%s%%;background:%s"></div></div></td>\n' "$bar_width" "$bar_color"
        printf '</tr>\n'
    done

    cat <<'TABLEEND'
</tbody>
</table>
TABLEEND
}

_emit_html_details() {
    printf '<h2>Detailed Results</h2>\n'

    local section
    for section in "${SECTION_ORDER[@]}"; do
        local has_results=0
        local id
        for id in "${RESULT_ORDER[@]}"; do
            if [[ "${CTRL_SECTION[$id]}" == "$section" ]]; then
                has_results=1
                break
            fi
        done

        if (( has_results == 0 )); then
            continue
        fi

        local esc_section
        esc_section=$(html_escape "$section")

        printf '<div class="section-group">\n'
        printf '<h3>%s</h3>\n' "$esc_section"

        for id in "${RESULT_ORDER[@]}"; do
            if [[ "${CTRL_SECTION[$id]}" != "$section" ]]; then
                continue
            fi

            local status="${RESULT_STATUS[$id]}"
            local title="${CTRL_TITLE[$id]}"
            local level="${CTRL_LEVEL[$id]}"
            local evidence="${RESULT_EVIDENCE[$id]:-}"
            local remediation="${CTRL_REMEDIATION[$id]:-}"

            local cls
            cls=$(_html_status_class "$status")

            local esc_id
            esc_id=$(html_escape "$id")
            local esc_title
            esc_title=$(html_escape "$title")

            local open_attr=""
            if [[ "$status" == "$STATUS_FAIL" ]]; then
                open_attr=" open"
            fi

            printf '<details class="control %s"%s>\n' "$cls" "$open_attr"
            printf '<summary>\n'
            printf '<span class="badge %s">%s</span>\n' "$cls" "$status"
            printf '<span class="control-id">%s</span>\n' "$esc_id"
            printf '<span class="control-title">%s</span>\n' "$esc_title"
            printf '<span class="badge level">L%s</span>\n' "$level"
            printf '</summary>\n'

            if [[ -n "$evidence" || -n "$remediation" ]]; then
                printf '<div class="control-detail">\n'
                if [[ -n "$evidence" ]]; then
                    local esc_evidence
                    esc_evidence=$(html_escape "$evidence")
                    printf '<div class="evidence">%s</div>\n' "$esc_evidence"
                fi
                if [[ -n "$remediation" ]]; then
                    local esc_remediation
                    esc_remediation=$(html_escape "$remediation")
                    printf '<p class="remediation">Remediation: <code>%s</code></p>\n' "$esc_remediation"
                fi
                printf '</div>\n'
            fi

            printf '</details>\n'
        done

        printf '</div>\n'
    done
}

_emit_html_footer() {
    local esc_version
    esc_version=$(html_escape "$VERSION")

    cat <<FOOTEREOF
<footer>
cisaudit v${esc_version}
</footer>
</div>
</body>
</html>
FOOTEREOF
}

emit_html_report() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')
    local hostname
    hostname=$(hostname 2>/dev/null || echo "unknown")

    _emit_html_head
    _emit_html_header "$timestamp" "$hostname"
    _emit_html_section_table
    _emit_html_details
    _emit_html_footer
}
