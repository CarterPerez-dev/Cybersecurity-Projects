#!/usr/bin/env bash
# ©AngelaMos | 2026
# detector-gate.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VULNERABLE_IMAGE="ruby:4.0.2-slim"

echo "boundary detector gate"
echo

output="$(docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=1m \
    --user nobody \
    -v "${HERE}/lib:/app/lib:ro" -w /app "${VULNERABLE_IMAGE}" ruby -Ilib -e '
require "marshalsea"
D = Marshalsea::Marshal::BoundaryDetector
CANARY = "/tmp/marshalsea-canary"

hostile = Marshalsea::Chains::ErbDefMethod.canary(CANARY, "fired").serialize
benign  = Marshal.dump({ "user" => "guest", "roles" => [1, 2, 3] })
sinky   = Marshal.dump(Gem::Requirement.new(">= 0"))

strict_hostile = D.new.inspect_stream(hostile)
strict_benign  = D.new.inspect_stream(benign)
strict_sinky   = D.new.inspect_stream(sinky)
allowlisted    = D.new(allowed_class_names: %w[Gem::Requirement Gem::Version]).inspect_stream(sinky)
loose_hostile  = D.new(policy: D::POLICY_DENY_SINKS_ONLY).inspect_stream(hostile)

observed_reporter = ->(_reason) {}
observing = D.new(policy: D::POLICY_OBSERVE_AND_LOG, reporter: observed_reporter)
observed_sinky = observing.inspect_stream(sinky)
observed_benign = observing.inspect_stream(benign)

puts "strict_rejects_cve=#{strict_hostile.blocked?}"
puts "strict_accepts_benign=#{strict_benign.proceed?}"
puts "strict_rejects_sink=#{strict_sinky.blocked?}"
puts "allowlist_does_not_exempt_sink=#{allowlisted.blocked?}"
puts "deny_sinks_only_accepts_cve=#{loose_hostile.proceed?}"
puts "observe_and_log_never_reports_proceed=#{!observed_sinky.proceed?}"
puts "observe_and_log_reports_observed=#{observed_sinky.observed?}"
puts "observe_and_log_proceeds_on_benign=#{observed_benign.proceed?}"
puts "blocked_is_not_also_observed=#{!strict_sinky.observed?}"

fired = false
if loose_hostile.proceed?
  begin
    Marshal.load(loose_hostile.snapshot).def_method(Module.new, "x")
  rescue StandardError
    nil
  end
  fired = File.exist?(CANARY)
end
puts "documented_bypass_executes=#{fired}"
File.delete(CANARY) if File.exist?(CANARY)

G = Marshalsea::Marshal::LoadGuard
BODIES = []
class GuardGadget
  def marshal_dump = ["x"]
  def marshal_load(_d) = BODIES << :ran
end
class GuardBenign
  def marshal_dump = ["x"]
  def marshal_load(_d) = BODIES << :ran
end

gadget_blob = Marshal.dump(GuardGadget.new)
benign_blob = Marshal.dump(GuardBenign.new)

BODIES.clear
vetoed = begin
  G.new.load(gadget_blob)
  false
rescue Marshalsea::Marshal::GuardedLoadError
  true
end
puts "guard_vetoes_an_unpermitted_hook=#{vetoed}"
puts "guard_vetoes_before_the_body_runs=#{BODIES.empty?}"

BODIES.clear
allowed = begin
  G.new(permitted_class_names: %w[GuardBenign]).load(benign_blob)
  true
rescue Marshalsea::Marshal::GuardedLoadError
  false
end
puts "control_guard_admits_a_permitted_hook=#{allowed}"
puts "control_the_permitted_body_actually_ran=#{BODIES == [:ran]}"

BODIES.clear
guard_run = G.new
begin
  guard_run.load(gadget_blob)
rescue Marshalsea::Marshal::GuardedLoadError
  nil
end
puts "guard_reports_the_hook_it_refused=#{guard_run.observations.map(&:to_s) == ["GuardGadget#marshal_load"]}"

puts "guard_error_is_an_ordinary_standard_error=#{Marshalsea::Marshal::GuardedLoadError < StandardError}"
' 2>&1)"

echo "${output}" | sed 's/^/  /'
echo

failures=0
expect() {
    if echo "${output}" | grep -q "^$1=true$"; then
        echo "  PASS   $2"
    else
        echo "  FAIL   $2"
        failures=$((failures + 1))
    fi
}

expect strict_rejects_cve "strict policy rejects the CVE-2026-41316 payload"
expect strict_accepts_benign "strict policy still accepts a benign primitive stream"
expect strict_rejects_sink "strict policy rejects a sink-bearing stream"
expect allowlist_does_not_exempt_sink "allowlisting a class does not exempt its sink"
expect deny_sinks_only_accepts_cve "deny-sinks-only accepts the CVE payload as documented"
expect observe_and_log_never_reports_proceed "observe-and-log never reports proceed for a flagged stream"
expect observe_and_log_reports_observed "observe-and-log reports the third state instead of hiding it"
expect observe_and_log_proceeds_on_benign "observe-and-log still proceeds on a clean stream"
expect blocked_is_not_also_observed "the three decision states stay mutually exclusive"
expect documented_bypass_executes "the documented bypass actually executes, so the notice is honest"
expect guard_vetoes_an_unpermitted_hook "the runtime guard refuses an unpermitted deserialization hook"
expect guard_vetoes_before_the_body_runs "the guard vetoes before the hook body runs, which the load proc cannot do"
expect control_guard_admits_a_permitted_hook "a guard that refused everything would prove nothing"
expect control_the_permitted_body_actually_ran "the permitted hook really executed, so the control is live"
expect guard_reports_the_hook_it_refused "the guard names the hook it refused rather than failing silently"
expect guard_error_is_an_ordinary_standard_error "the guard raises a StandardError, not a SecurityError that skips every rescue"

echo
if [[ ${failures} -eq 0 ]]; then
    echo "GATE PASSED"
    exit 0
fi

echo "GATE FAILED (${failures})"
exit 1
