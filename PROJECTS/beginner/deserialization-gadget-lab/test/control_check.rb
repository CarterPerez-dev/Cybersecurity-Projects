# ©AngelaMos | 2026
# control_check.rb
# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "marshalsea"

Pair = Struct.new(:x, :y)

failures = []

def check(label, passed, detail)
  puts format("  %-6s %-46s %s", passed ? "PASS" : "FAIL", label, detail)
  passed
end

puts "=== 1 oracle liveness ==="
fired = false
tracer = TracePoint.new(:call, :c_call) do |tp|
  fired = true if tp.method_id == :load && tp.self.equal?(Marshal)
end
tracer.enable { Marshal.load(Marshal.dump([1, 2])) }
failures << "oracle" unless check("TracePoint observes a real Marshal.load", fired, fired ? "fired" : "silent")

puts
puts "=== 2 object link indexing ==="
cyclic = []
cyclic << cyclic
blob = Marshal.dump(cyclic)
link = Marshalsea::Marshal::Parser.new(blob).parse.root.children.first
bytes = blob.bytes.map { |b| format("%02x", b) }.join(" ")
failures << "link index" unless check("self-referential array links to index 0", link.value.zero?, bytes)

puts
puts "=== 3 corpus round-trip ==="
shared = "shared"
aliased = [shared, shared]
cyclic_hash = {}
cyclic_hash[:self] = cyclic_hash
deep = [1]
20.times { deep = [deep] }

corpus = [
  nil, true, false,
  0, 1, -1, 122, 123, -123, -124, 255, -256, 65_536, -65_536,
  1_073_741_823, -1_073_741_824, 2**70, -(2**70), 2**200,
  0.0, -0.0, 3.14, Float::INFINITY, -Float::INFINITY,
  "", "str", "\x00\xff binary".b, "unicode é中",
  :sym, :"with spaces", :marshal_load,
  [], {}, [1, [2, [3, [4]]]], { a: { b: { c: 1 } } },
  (1..5).to_a, Pair.new(1, 2), Pair.new(nil, [1, 2]),
  Object.new, Time.now, /regex/i, //mx, String, Comparable, Marshalsea,
  aliased, cyclic_hash, deep,
  { "mixed" => [1, :two, 3.0, nil, true] },
  Hash.new(0).tap { |h| h[:k] = 1 },
  Gem::Requirement.new(">= 0"), Gem::Version.new("1.2.3")
]

parsed = corpus.count do |item|
  Marshalsea::Marshal::Parser.new(Marshal.dump(item)).parse.root
  true
rescue StandardError => e
  puts "    #{item.class}: #{e.class}: #{e.message}"
  false
end
failures << "corpus" unless check("every corpus entry parsed", parsed == corpus.length, "#{parsed}/#{corpus.length}")

puts
puts "=== 4 stream rejection ==="
rejected = begin
  Marshalsea::Marshal::Parser.new("\x04\x08[\x06@\x63").parse
  false
rescue Marshalsea::Marshal::InvalidLinkError
  true
end
failures << "bounds" unless check("out-of-range object link rejected", rejected, "InvalidLinkError")

puts
puts "=== 5 payload inspection ==="
result = Marshalsea::Marshal::Parser.new(Marshal.dump(Gem::Requirement.new(">= 0"))).parse
from_stream = result.gated_sinks.map { |s| "#{s.class_name}##{s.sink_method}" }.uniq.sort
failures << "class names" unless check("classes extracted", !result.class_names.empty?,
                                       result.class_names.join(", "))
failures << "gated sinks" unless check("gated sinks flagged", !from_stream.empty?,
                                       from_stream.join(", "))

puts
puts "=== 6 parser and scanner agreement ==="
scanned = Marshalsea::Scanner.new(namespace: "Gem").scan.gated.map(&:to_s).sort
missing = from_stream - scanned
located = !from_stream.empty? && missing.empty?
agreement_detail = if from_stream.empty?
                     "vacuous, section 5 produced no sinks to locate"
                   elsif missing.empty?
                     "#{from_stream.length}/#{from_stream.length}"
                   else
                     "missing #{missing.join(', ')}"
                   end
failures << "agreement" unless check("parser sinks located by reflection", located, agreement_detail)

puts
puts "=== 7 scanner precision ==="
full = Marshalsea::Scanner.new.scan
ungated = full.ungated.length
reachable = full.reachable.count { |c| !c.gated? }
kept = ungated.zero? ? 0 : (100.0 * reachable / ungated).round(1)
prism_detail = full.prism_available? ? "Prism.parse_file in use" : "ABSENT, every state verdict is a guess"
failures << "prism" unless check("prism backend live, so reachability is real",
                                 full.prism_available?, prism_detail)
failures << "precision" unless check("reachability filter discriminates",
                                     reachable.positive? && reachable < ungated,
                                     "#{ungated} ungated -> #{reachable} reachable, #{kept}% kept")
failures << "gated located" unless check("gated sinks located", !full.gated.empty?,
                                         full.gated.join(", "))

lossy = full.candidates_lost? ? full.suppressions.join(", ") : "0 lossy suppressions"
failures << "candidates lost" unless check("no candidate was silently dropped",
                                           !full.candidates_lost?, lossy)

unreadable = full.candidates.select(&:unreadable_source?)
fails_open = !unreadable.empty? &&
             unreadable.all? { |c| c.gated? || !c.entry_point? || !c.accepts_dispatch? || c.reachable? }
failures << "unreadable fails open" unless check("an unreadable source fails open, never to inert",
                                                 fails_open,
                                                 "#{unreadable.length} candidates whose source could not be parsed")

unanalysable = full.unanalysable
owned = !unanalysable.empty? && unanalysable.none?(&:state_known?) && !full.fully_analysed?
failures << "unanalysable owned" unless check("C-defined methods are named unanalysable, not inert",
                                              owned,
                                              "#{unanalysable.length} of #{full.candidates.length} have no Ruby source")

flooded = unanalysable.reject(&:gated?).select(&:reachable?)
flood_detail = flooded.empty? ? "0 of #{unanalysable.length} promoted" : "#{flooded.length} promoted with no evidence"
failures << "unanalysable flood" unless check("unanalysable never buys its way into reachable",
                                              !unanalysable.empty? && flooded.empty?, flood_detail)

coverage = "#{full.candidates.count(&:state_known?)} analysed, " \
           "#{unanalysable.length} unanalysable, #{unreadable.length} unreadable"
suppressed = full.complete? ? "none" : full.suppressions_by_site.map { |site, n| "#{site}=#{n}" }.join(" ")
puts format("  %-6s %-46s %s", "INFO", "ObjectSpace coverage is load-bounded",
            "#{full.scanned_modules} modules loaded")
puts format("  %-6s %-46s %s", "INFO", "state analysis coverage", coverage)
puts format("  %-6s %-46s %s", "INFO", "suppressed errors this scan", suppressed)

puts
if failures.empty?
  puts "ALL CONTROLS PASSED"
  exit 0
end

puts "FAILED: #{failures.join(', ')}"
exit 1
