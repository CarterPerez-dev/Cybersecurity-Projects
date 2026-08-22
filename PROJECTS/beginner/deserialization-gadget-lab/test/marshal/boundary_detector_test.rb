# ©AngelaMos | 2026
# boundary_detector_test.rb
# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/adversarial_corpus"

module Marshalsea
  module Marshal
    class BoundaryDetectorTest < Minitest::Test
      BENIGN = { "user" => "guest", "roles" => [1, 2, 3], "flag" => true }.freeze
      CANARY_PATH = "/tmp/marshalsea-canary"
      CANARY_MARKER = "fired"

      def detector(**)
        BoundaryDetector.new(**)
      end

      def benign_blob
        ::Marshal.dump(BENIGN)
      end

      def sink_blob
        ::Marshal.dump(Gem::Requirement.new(">= 0"))
      end

      def cve_blob
        Marshalsea::Chains::ErbDefMethod.canary(CANARY_PATH, CANARY_MARKER).serialize
      end

      def test_default_policy_is_strict_allowlist
        assert_equal BoundaryDetector::POLICY_STRICT_ALLOWLIST,
                     detector.send(:policy)
      end

      def test_accepts_primitive_only_stream_with_an_empty_allowlist
        assert_predicate detector.inspect_stream(benign_blob), :proceed?
      end

      def test_rejects_non_string_input_without_converting_it
        hostile = Object.new
        def hostile.to_s
          raise "to_s must never be called on untrusted input"
        end

        decision = detector.inspect_stream(hostile)
        assert_predicate decision, :blocked?
        assert_equal BoundaryDetector::REASON_INPUT_TYPE, decision.reason
      end

      def test_rejects_a_sink_bearing_stream
        decision = detector.inspect_stream(sink_blob)
        assert_predicate decision, :blocked?
        assert_includes decision.reason, '"Gem::Requirement"#marshal_load',
                        "the class name is attacker-controlled and stays quoted, so an operator " \
                        "can see where it starts and stops"
      end

      def test_allowlisting_a_class_does_not_exempt_its_sink
        decision = detector(allowed_class_names: %w[Gem::Requirement Gem::Version])
                   .inspect_stream(sink_blob)
        assert_predicate decision, :blocked?
        assert_includes decision.reason, "marshal_load"
      end

      def test_rejects_unapproved_class_names
        decision = detector.inspect_stream(cve_blob)
        assert_predicate decision, :blocked?
        assert_includes decision.reason, "ERB"
      end

      def test_accepts_an_approved_class
        decision = detector(allowed_class_names: %w[ERB]).inspect_stream(cve_blob)
        assert_predicate decision, :proceed?
      end

      def test_documented_bypass_is_real_deny_sinks_only_accepts_the_cve_payload
        decision = detector(policy: BoundaryDetector::POLICY_DENY_SINKS_ONLY)
                   .inspect_stream(cve_blob)
        assert_predicate decision, :proceed?,
                         "the limitation notice claims this bypass exists, so it must be demonstrable"
      end

      def test_deny_sinks_only_still_rejects_sinks
        decision = detector(policy: BoundaryDetector::POLICY_DENY_SINKS_ONLY)
                   .inspect_stream(sink_blob)
        assert_predicate decision, :blocked?
      end

      def test_observe_and_log_requires_a_reporter
        assert_raises(ReporterRequiredError) do
          detector(policy: BoundaryDetector::POLICY_OBSERVE_AND_LOG)
        end
      end

      def test_observe_and_log_records_the_violation_without_reporting_proceed
        seen = []
        decision = detector(policy: BoundaryDetector::POLICY_OBSERVE_AND_LOG,
                            reporter: ->(reason) { seen << reason })
                   .inspect_stream(cve_blob)

        assert_predicate decision, :observed?
        refute_predicate decision, :proceed?
        refute_predicate decision, :blocked?
        assert_equal 1, seen.length
      end

      def test_observe_and_log_still_rejects_malformed_input
        decision = detector(policy: BoundaryDetector::POLICY_OBSERVE_AND_LOG,
                            reporter: ->(_) {})
                   .inspect_stream("\x04\x08[\xFA")
        assert_predicate decision, :blocked?
      end

      def test_rejects_a_version_the_parser_accepts_but_no_ruby_emits
        older = "\x04\x07\x30".b

        assert_predicate Parser.new(older).parse, :root,
                         "control: the parser must still accept it, it is a forensic tool"
        decision = detector.inspect_stream(older)
        assert_predicate decision, :blocked?
        assert_includes decision.reason, "4.7"
      end

      def test_canonical_version_is_accepted
        assert_predicate detector.inspect_stream(benign_blob), :proceed?
      end

      def test_deny_sinks_only_does_not_police_the_version
        decision = detector(policy: BoundaryDetector::POLICY_DENY_SINKS_ONLY)
                   .inspect_stream("\x04\x07\x30".b)
        assert_predicate decision, :proceed?,
                         "version canonicality runs no code during load, so it belongs with " \
                         "the allowlist, not with the sink checks"
      end

      def test_rejects_unknown_policy
        assert_raises(ArgumentError) { detector(policy: :yolo) }
      end

      def role_anomaly_streams
        {
          "ivar name is a fixnum" => AdversarialCorpus.stream("I#{AdversarialCorpus.str('a')}\x06i\x060"),
          "ivar name is a string" =>
            AdversarialCorpus.stream("I#{AdversarialCorpus.str('a')}\x06#{AdversarialCorpus.str('n')}0"),
          "ivar name is an array" => AdversarialCorpus.stream("I#{AdversarialCorpus.str('a')}\x06[\x000")
        }
      end

      def ruby_refuses?(bytes)
        ::Marshal.load(bytes)
        false
      rescue ArgumentError, TypeError
        true
      end

      def test_no_stream_the_loader_refuses_is_ever_waved_through
        refused = role_anomaly_streams.select { |_label, bytes| ruby_refuses?(bytes) }
        assert_equal role_anomaly_streams.keys, refused.keys,
                     "control: these fixtures exist because Marshal.load refuses them"

        waved = role_anomaly_streams.select { |_label, bytes| detector.inspect_stream(bytes).proceed? }
        assert_empty waved.keys,
                     "proceed? means the caller may load these bytes, and loading them raises. " \
                     "The defended route then answers 500 instead of a rejection: #{waved.keys.join(', ')}"
      end

      def test_a_role_anomaly_is_named_rather_than_reported_as_a_parse_failure
        decision = detector.inspect_stream(role_anomaly_streams.fetch("ivar name is a fixnum"))

        assert_predicate decision, :blocked?
        assert_includes decision.reason, "instance variable name slot holds fixnum"
        refute_includes decision.reason, "Error",
                        "the parser accepted this on purpose so a hidden sink stays visible; " \
                        "the reason must say what is wrong, not pretend parsing failed"
      end

      def test_the_parser_still_returns_a_graph_for_a_role_anomaly
        result = Parser.new(role_anomaly_streams.fetch("ivar name is an array")).parse

        refute_predicate result, :canonical_roles?
        assert_equal 1, result.role_anomalies.length
        refute_nil result.root, "the forensic graph must survive so a hidden sink stays reportable"
      end

      def test_a_canonical_stream_carries_no_role_anomaly
        assert_predicate Parser.new(benign_blob).parse, :canonical_roles?,
                         "control: an ordinary stream must not trip the role check"
      end

      def test_rejects_malformed_stream_with_a_named_reason
        decision = detector.inspect_stream("\x04\x08[\xFA")
        assert_predicate decision, :blocked?
        assert_includes decision.reason, "MalformedCountError"
      end

      def test_returns_a_frozen_snapshot_on_accept
        decision = detector.inspect_stream(benign_blob)
        assert_predicate decision.snapshot, :frozen?
      end

      def test_snapshot_is_independent_of_a_mutated_original
        original = +benign_blob
        decision = detector.inspect_stream(original)
        original << "tampered"
        refute_includes decision.snapshot, "tampered"
      end

      def assert_ceiling_rejects(blob, error_name, allowed: [], **narrow)
        assert_predicate detector(allowed_class_names: allowed).inspect_stream(blob), :proceed?,
                         "control: this payload must be accepted under default limits, " \
                         "or the ceiling is not what rejected it"

        decision = detector(allowed_class_names: allowed, limits: Limits.new(**narrow)).inspect_stream(blob)
        assert_predicate decision, :blocked?
        assert_includes decision.reason, error_name
        decision
      end

      def test_enforces_a_byte_ceiling_before_parsing
        assert_ceiling_rejects(benign_blob, "LimitExceededError", max_bytes: 8)
      end

      def test_enforces_a_depth_ceiling
        deep = "\x04\x08" + ("[\x06" * 80) + "0"
        shallow = "\x04\x08" + ("[\x06" * 8) + "0"

        assert_predicate detector.inspect_stream(shallow), :proceed?,
                         "control: nesting inside the ceiling must be accepted"
        decision = detector.inspect_stream(deep)
        assert_predicate decision, :blocked?
        assert_includes decision.reason, "DepthLimitError"
      end

      def test_enforces_a_collection_entry_ceiling
        assert_ceiling_rejects(::Marshal.dump([1, 2, 3, 4, 5]), "LimitExceededError",
                               max_collection_entries: 2)
      end

      def test_enforces_a_symbol_ceiling
        assert_ceiling_rejects(::Marshal.dump(%i[a b c d e f]), "LimitExceededError",
                               max_symbol_definitions: 2)
      end

      def test_enforces_a_node_ceiling
        assert_ceiling_rejects(::Marshal.dump((1..50).to_a), "LimitExceededError",
                               max_nodes: 5)
      end

      def test_enforces_a_bignum_magnitude_ceiling
        words = AdversarialCorpus::BIGNUM_HUGE_WORDS
        blob = AdversarialCorpus.stream(AdversarialCorpus.bignum("+", words))
        decision = detector.inspect_stream(blob)

        assert_predicate decision, :blocked?,
                         "#{words * AdversarialCorpus::BIGNUM_WORD_BYTES} magnitude bytes must be " \
                         "charged the same budget a string of that size is charged"
        assert_includes decision.reason, "LimitExceededError"
      end

      def test_enforces_a_symbol_reference_ceiling
        count = AdversarialCorpus::BULK_ENTRY_COUNT
        blob = AdversarialCorpus.stream(
          "[#{AdversarialCorpus.fixnum(count + 1)}#{AdversarialCorpus.symlink_run(count)}"
        )
        assert_ceiling_rejects(blob, "LimitExceededError", max_symbol_references: 8)
      end

      def test_enforces_a_symbol_name_byte_ceiling
        blob = AdversarialCorpus.stream(AdversarialCorpus.sym("A" * AdversarialCorpus::MODEST_NAME_BYTES))
        assert_ceiling_rejects(blob, "LimitExceededError", max_symbol_name_bytes: 32)
      end

      def test_enforces_a_class_name_byte_ceiling
        name = "A" * AdversarialCorpus::MODEST_NAME_BYTES
        blob = AdversarialCorpus.stream("c#{AdversarialCorpus.fixnum(name.bytesize)}#{name}")
        assert_ceiling_rejects(blob, "LimitExceededError", allowed: [name], max_class_name_bytes: 32)
      end

      def test_enforces_an_instance_variable_ceiling
        blob = AdversarialCorpus.stream(
          "o#{AdversarialCorpus.sym('F')}#{AdversarialCorpus.ivar_run(AdversarialCorpus::MODEST_ENTRY_COUNT)}"
        )
        assert_ceiling_rejects(blob, "LimitExceededError", allowed: %w[F], max_instance_variables: 8)
      end

      def test_enforces_a_struct_member_ceiling
        blob = AdversarialCorpus.stream(
          "S#{AdversarialCorpus.sym('F')}#{AdversarialCorpus.ivar_run(AdversarialCorpus::MODEST_ENTRY_COUNT)}"
        )
        assert_ceiling_rejects(blob, "LimitExceededError", allowed: %w[F], max_struct_members: 8)
      end

      def default_limit_probes
        long = "A" * AdversarialCorpus::LONG_NAME_BYTES
        bulk = AdversarialCorpus::BULK_ENTRY_COUNT

        {
          "bignum magnitude" =>
            [AdversarialCorpus.stream(AdversarialCorpus.bignum("+", AdversarialCorpus::BIGNUM_HUGE_WORDS)), []],
          "symbol references" =>
            [AdversarialCorpus.stream(
              AdversarialCorpus.symlink_groups(AdversarialCorpus::SYMLINK_BULK_GROUPS,
                                               AdversarialCorpus::SYMLINK_BULK_PER_GROUP)
            ), []],
          "symbol name bytes" =>
            [AdversarialCorpus.stream(AdversarialCorpus.sym(long)), []],
          "class name bytes" =>
            [AdversarialCorpus.stream("c#{AdversarialCorpus.fixnum(long.bytesize)}#{long}"), [long]],
          "instance variables" =>
            [AdversarialCorpus.stream("o#{AdversarialCorpus.sym('F')}#{AdversarialCorpus.ivar_run(bulk)}"), %w[F]],
          "struct members" =>
            [AdversarialCorpus.stream("S#{AdversarialCorpus.sym('F')}#{AdversarialCorpus.ivar_run(bulk)}"), %w[F]]
        }
      end

      def test_default_limits_bound_every_axis_without_being_asked
        admitted = default_limit_probes.reject do |_axis, (blob, allowed)|
          decision = detector(allowed_class_names: allowed).inspect_stream(blob)
          decision.blocked? && decision.reason.include?("LimitExceededError")
        end

        assert_empty admitted.keys,
                     "Limits.new must bound these without a caller opting in: #{admitted.keys.join(', ')}"
      end

      def test_permissive_limits_admit_what_the_defaults_reject
        admitted = default_limit_probes.count do |_axis, (blob, allowed)|
          detector(allowed_class_names: allowed, limits: Limits.permissive).inspect_stream(blob).proceed?
        end

        assert_operator admitted, :>, 0,
                        "control: permissive must actually differ from the defaults, " \
                        "otherwise the previous test proves nothing about the ceilings"
      end

      def test_never_exposes_a_safety_claiming_api
        %i[safe? trusted? sanitized? safe_load].each do |forbidden|
          refute_respond_to detector, forbidden,
                            "#{forbidden} implies a guarantee this detector cannot make"
        end
      end

      def test_ships_a_limitation_notice_that_names_the_bypass
        notice = BoundaryDetector::LIMITATION_NOTICE
        assert_includes notice, "does not make the payload safe"
        assert_includes notice, "CVE-2026-41316"
        assert_includes notice, "zero sink tags"
      end

      def test_detector_never_calls_marshal_load
        fired = false
        tracer = TracePoint.new(:call, :c_call) do |tp|
          fired = true if tp.method_id == :load && tp.self.equal?(::Marshal)
        end
        tracer.enable { detector.inspect_stream(cve_blob) }
        refute fired
      end

      def policy_options(policy)
        return { policy: policy, reporter: ->(_reason) {} } if
          policy == BoundaryDetector::POLICY_OBSERVE_AND_LOG

        { policy: policy }
      end

      def decision_per_policy(blob, allowed: [])
        BoundaryDetector::POLICIES.to_h do |policy|
          [policy, detector(allowed_class_names: allowed, **policy_options(policy)).inspect_stream(blob)]
        end
      end

      def state_matrix_blobs
        {
          "benign" => benign_blob,
          "sink" => sink_blob,
          "unapproved class" => cve_blob,
          "malformed" => "\x04\x08[\xFA"
        }
      end

      def test_no_policy_reports_proceed_for_a_payload_it_flagged
        admitted = decision_per_policy(sink_blob).select { |_policy, decision| decision.proceed? }

        assert_empty admitted.keys,
                     "every policy flags a marshal_load sink, so no policy may report proceed. " \
                     "Marshal.load(d.snapshot) if d.proceed? would load it under " \
                     "#{admitted.keys.join(', ')}"
      end

      def test_control_every_policy_reports_proceed_for_a_benign_payload
        admitted = decision_per_policy(benign_blob).select { |_policy, decision| decision.proceed? }

        assert_equal BoundaryDetector::POLICIES.length, admitted.length,
                     "control: a proceed? that is never true would pass the previous test vacuously"
      end

      def test_exactly_one_state_predicate_holds_for_every_policy_and_payload
        seen = []

        state_matrix_blobs.each do |name, blob|
          decision_per_policy(blob).each do |policy, decision|
            held = BoundaryDetector::Decision::STATE_PREDICATES.select { |predicate| decision.public_send(predicate) }
            assert_equal 1, held.length,
                         "#{name} under #{policy} reported #{held.length} states: #{held.join(', ')}"
            seen.concat(held)
          end
        end

        assert_equal BoundaryDetector::Decision::STATE_PREDICATES.sort, seen.uniq.sort,
                     "control: the matrix must exercise every state, or exclusivity proves nothing"
      end

      def test_the_ambiguous_accept_predicates_no_longer_exist
        decision = detector(policy: BoundaryDetector::POLICY_OBSERVE_AND_LOG,
                            reporter: ->(_reason) {}).inspect_stream(sink_blob)

        %i[accepted? rejected?].each do |ambiguous|
          refute_respond_to decision, ambiguous,
                            "#{ambiguous} cannot answer whether this payload may be deserialized, " \
                            "and a reader who copies it loads a flagged stream"
        end
      end

      def test_observe_and_log_still_hands_back_bytes_for_an_explicit_opt_in
        decision = detector(policy: BoundaryDetector::POLICY_OBSERVE_AND_LOG,
                            reporter: ->(_reason) {}).inspect_stream(sink_blob)

        assert_predicate decision, :observed?
        refute_nil decision.snapshot,
                   "observe-and-log must stay non-blocking, so a caller who writes " \
                   "proceed? || observed? can still load"
        assert_equal ::Marshal.load(sink_blob), ::Marshal.load(decision.snapshot)
      end

      def test_a_blocked_decision_carries_no_snapshot_to_load
        decision = detector.inspect_stream(sink_blob)

        assert_predicate decision, :blocked?
        assert_nil decision.snapshot
      end

      def test_decision_rejects_an_unknown_state
        assert_raises(ArgumentError) { BoundaryDetector::Decision.new(state: :yolo) }
      end

      def hostile_named_streams(name)
        sym = AdversarialCorpus.sym(name)
        {
          "unapproved class" => AdversarialCorpus.stream("o#{sym}#{AdversarialCorpus.fixnum(0)}"),
          "sink" => AdversarialCorpus.stream("U#{sym}#{AdversarialCorpus.fixnum(0)}"),
          "hash key dispatch" =>
            AdversarialCorpus.stream(
              "{#{AdversarialCorpus.fixnum(1)}o#{sym}#{AdversarialCorpus.fixnum(0)}0"
            )
        }
      end

      def test_no_reject_reason_repeats_a_raw_control_byte_from_the_stream
        forged = "Evil\r\n2026-07-29 INFO session validated user=admin\e[0m\x00"
        raw = hostile_named_streams(forged).transform_values do |blob|
          detector.inspect_stream(blob).reason.to_s
        end

        assert_equal 3, raw.values.count { |reason| !reason.empty? },
                     "control: every reason kind must actually fire, or this proves nothing"
        raw.each do |kind, reason|
          offending = reason.bytes.select { |byte| byte < 0x20 }
          assert_empty offending,
                       "#{kind} reason carried raw control bytes #{offending.inspect} straight " \
                       "into a caller-supplied logger"
        end
      end

      def test_a_reject_reason_still_identifies_the_class_it_refused
        blob = hostile_named_streams("Evil\nInjected").fetch("unapproved class")

        assert_includes detector.inspect_stream(blob).reason, 'Evil\nInjected',
                        "escaping must not cost the operator the name that was refused"
      end

      def test_a_reject_reason_bounds_how_much_attacker_text_it_repeats
        ceiling = Limits::DEFAULT_MAX_CLASS_NAME_BYTES
        long = "A" * ceiling
        blob = hostile_named_streams(long).fetch("unapproved class")
        decision = detector.inspect_stream(blob)

        assert_predicate decision, :blocked?
        assert_includes decision.reason, BoundaryDetector::REASON_TRUNCATED_MARKER
        assert_operator decision.reason.bytesize, :<, ceiling,
                        "a 1 KiB class name is inside the parser ceiling, so the reason is the " \
                        "only thing bounding what reaches the log"
      end

      def test_control_a_short_class_name_is_not_truncated
        blob = hostile_named_streams("Evil").fetch("unapproved class")
        reason = detector.inspect_stream(blob).reason

        assert_includes reason, '"Evil"'
        refute_includes reason, BoundaryDetector::REASON_TRUNCATED_MARKER
      end
    end
  end
end
