# ©AngelaMos | 2026
# render_matrix.rb
# frozen_string_literal: true

require "json"
require "marshalsea"

TRACKED_CLASSES = %w[Gem::SpecFetcher Gem::Source::Git Gem::URI Net::WriteAdapter].freeze
MARK_YES = "yes"
MARK_NO = "no"
MARK_UNKNOWN = "?"
RULE_WIDTH = 78

CHAIN = Marshalsea::Chains::ErbDefMethod

def cve_patched?(version)
  !CHAIN.affects?(version)
end

rows = File.readlines(ARGV.fetch(0)).reject { |line| line.strip.empty? }.map { |line| JSON.parse(line) }
abort "no probe results" if rows.empty?

def mark(value)
  case value
  when true then MARK_YES
  when false then MARK_NO
  else MARK_UNKNOWN
  end
end

def short(image)
  image.sub("ruby:", "")
end

def section(title)
  puts title
  puts "  #{'-' * RULE_WIDTH}"
  yield
  puts
end

section("RUNTIME") do
  puts format("  %-14s %-8s %-9s %-8s %-9s %s", "image", "ruby", "rubygems", "psych", "erb", "marshal")
  rows.each do |r|
    puts format("  %-14s %-8s %-9s %-8s %-9s %-7s",
                short(r["image"]), r["ruby"], r["rubygems"], r["psych"], r["erb"], r["marshal_format"])
  end
end

section("GADGET SURFACE") do
  heads = TRACKED_CLASSES.map { |c| format("%-13s", c.split("::").last) }.join
  puts format("  %-14s %-12s %-14s %s", "image", "git gadget", "safe_marshal", heads)
  rows.each do |r|
    present = TRACKED_CLASSES.map { |c| format("%-13s", mark(r["classes_baseline"][c])) }.join
    puts format("  %-14s %-12s %-14s %s", short(r["image"]), r["git_gadget"], r["safe_marshal"], present)
  end
end

section("ERB @_init GUARD (CVE-2026-41316), anchor = def_method") do
  puts format("  %-14s %-9s %-9s %-24s %-8s", "image", "erb", "guarded", "delegating", "cve says")
  rows.each do |r|
    guard = r["erb_guard"]
    expected = cve_patched?(r["erb"]) ? "patched" : "affected"
    puts format("  %-14s %-9s %-9s %-24s %s",
                short(r["image"]), r["erb"], mark(guard["guarded"]),
                guard["delegating"].join(","), expected)
  end
end

git_states = rows.map { |r| r["git_gadget"] }.uniq
guard_states = rows.map { |r| r["erb_guard"]["guarded"] }.uniq

agreements = rows.map do |r|
  [short(r["image"]), r["erb_guard"]["guarded"] == cve_patched?(r["erb"])]
end
disagreements = agreements.reject { |_, ok| ok }.map(&:first)

section("CONTROLS") do
  puts format("  git gadget states observed : %s", git_states.join(", "))
  puts format("  erb guard states observed  : %s", guard_states.map { |v| mark(v) }.join(", "))
  puts format("  guard vs published CVE     : %d/%d agree", agreements.count { |_, ok| ok }, agreements.length)
end

failures = []
failures << "git gadget reported '#{git_states.first}' on every image" if git_states.length < 2
failures << "erb guard reported the same value on every image" if guard_states.length < 2
failures << "guard disagrees with the CVE ranges on: #{disagreements.join(', ')}" unless disagreements.empty?

if failures.empty?
  puts "PASS - the matrix discriminates on both axes and matches the published CVE ranges"
  exit 0
end

failures.each { |f| puts "FAIL - #{f}" }
exit 1
