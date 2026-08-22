# ©AngelaMos | 2026
# boundary_detector.rb
# frozen_string_literal: true

module Marshalsea
  module Marshal
    class ReporterRequiredError < StandardError; end

    class BoundaryDetector
      POLICY_STRICT_ALLOWLIST = :strict_allowlist
      POLICY_DENY_SINKS_ONLY = :deny_sinks_only
      POLICY_OBSERVE_AND_LOG = :observe_and_log

      POLICIES = [POLICY_STRICT_ALLOWLIST, POLICY_DENY_SINKS_ONLY, POLICY_OBSERVE_AND_LOG].freeze

      REASON_INPUT_TYPE = "input is not a String"
      REASON_MALFORMED = "stream is not canonical Marshal: %s"
      REASON_SINK = "stream reaches %s#%s during load, before any allowlist can run"
      REASON_UNAPPROVED = "stream references unapproved class %s"
      REASON_ROLE_ANOMALY = "stream is not canonical Marshal: %s, so Marshal.load refuses it " \
                            "and there is nothing here to permit"
      REASON_KEY_HASH = "stream puts %s in a hash key, so its #hash runs during load, before " \
                        "any allowlist can act"
      REASON_KEY_EQL = "stream puts %s in a hash key, so its #eql? runs during load as soon as " \
                       "two keys collide, before any allowlist can act"
      REASON_RANGE_ENDPOINT = "stream puts %s in a Range endpoint, so its #<=> runs during " \
                              "load, before any allowlist can act"
      REASON_NONCANONICAL_VERSION = "stream declares Marshal %d.%d; every Ruby that can produce " \
                                    "this format emits %d.%d"

      REASON_MAX_NAME_BYTES = 96
      REASON_MAX_NAMES = 8
      REASON_TRUNCATED_MARKER = "[truncated"
      REASON_TRUNCATED = "#{REASON_TRUNCATED_MARKER}, +%d bytes]".freeze
      REASON_ELIDED_NAMES = ", and %d more"
      REASON_NAME_SEPARATOR = ", "

      LIMITATION_NOTICE = <<~NOTICE
        SECURITY LIMITATION

        Marshalsea::Marshal::BoundaryDetector examines a bounded snapshot of Marshal bytes and
        applies a caller-selected policy before deserialization. An ACCEPT decision means
        only that this snapshot matched that policy.

        Acceptance does not make the payload safe, trusted, authenticated, or free of
        gadget behavior. This detector does not sandbox Ruby, audit the current
        implementations of allowlisted classes, freeze the runtime class graph, or prevent
        callbacks and implicit method dispatch that its parser or policy fails to model.
        Class allowlisting compares serialized names. It does not prove that the
        corresponding Ruby code is harmless.

        A payload carrying no sink tag can still reach dangerous code. The published
        CVE-2026-41316 chain produces zero sink tags because ERB defines no marshal_load.
        It is caught by class allowlisting alone, and an application that allowlists ERB
        will accept it.
      NOTICE

      class Decision
        STATE_PROCEED = :proceed
        STATE_BLOCKED = :blocked
        STATE_OBSERVED = :observed

        STATES = [STATE_PROCEED, STATE_BLOCKED, STATE_OBSERVED].freeze
        STATE_PREDICATES = %i[proceed? blocked? observed?].freeze

        UNKNOWN_STATE = "unknown decision state %p, expected one of %s"

        attr_reader :state, :reason, :snapshot, :result

        def initialize(state:, reason: nil, snapshot: nil, result: nil)
          raise ArgumentError, format(UNKNOWN_STATE, state, STATES.join(", ")) unless STATES.include?(state)

          @state = state
          @reason = reason
          @snapshot = snapshot
          @result = result
        end

        def proceed?
          state == STATE_PROCEED
        end

        def blocked?
          state == STATE_BLOCKED
        end

        def observed?
          state == STATE_OBSERVED
        end
      end

      def initialize(policy: POLICY_STRICT_ALLOWLIST, allowed_class_names: [], limits: Limits.new, reporter: nil)
        raise ArgumentError, "unknown policy #{policy}" unless POLICIES.include?(policy)
        raise ReporterRequiredError, "#{POLICY_OBSERVE_AND_LOG} requires a reporter" if
          policy == POLICY_OBSERVE_AND_LOG && reporter.nil?

        @policy = policy
        @allowed_class_names = allowed_class_names.map(&:to_s).freeze
        @limits = limits
        @reporter = reporter
      end

      def inspect_stream(input)
        return reject(REASON_INPUT_TYPE) unless input.is_a?(String)

        snapshot = input.dup.force_encoding(Encoding::BINARY).freeze
        result = Parser.new(snapshot, limits: limits).parse
        evaluate(result, snapshot)
      rescue StreamError => e
        reject(format(REASON_MALFORMED, e.class.name.split("::").last))
      end

      private

      attr_reader :policy, :allowed_class_names, :limits, :reporter

      def evaluate(result, snapshot)
        violation = violation_for(result)
        return accept(snapshot, result) unless violation

        return observe(violation, snapshot, result) if policy == POLICY_OBSERVE_AND_LOG

        reject(violation)
      end

      def quoted(name)
        raw = name.to_s.dup.force_encoding(Encoding::BINARY)
        return raw.inspect if raw.bytesize <= REASON_MAX_NAME_BYTES

        "#{raw.byteslice(0, REASON_MAX_NAME_BYTES).inspect}" \
          "#{format(REASON_TRUNCATED, raw.bytesize - REASON_MAX_NAME_BYTES)}"
      end

      def quoted_list(names)
        shown = names.first(REASON_MAX_NAMES).map { |name| quoted(name) }.join(REASON_NAME_SEPARATOR)
        elided = names.length - REASON_MAX_NAMES
        return shown unless elided.positive?

        "#{shown}#{format(REASON_ELIDED_NAMES, elided)}"
      end

      def violation_for(result)
        anomaly = result.role_anomalies.first
        return format(REASON_ROLE_ANOMALY, anomaly) if anomaly

        sink = result.sinks.first
        return format(REASON_SINK, quoted(sink.class_name), sink.sink_method) if sink

        hashed = result.hash_dispatching_keys.first
        return format(REASON_KEY_HASH, quoted(hashed.effective_class_name)) if hashed

        compared = result.eql_dispatching_keys.first
        return format(REASON_KEY_EQL, quoted(compared.effective_class_name)) if compared

        endpoint = result.range_endpoint_dispatchers.first
        return format(REASON_RANGE_ENDPOINT, quoted(endpoint.effective_class_name)) if endpoint

        return nil if policy == POLICY_DENY_SINKS_ONLY

        unless result.canonical_version?
          return format(REASON_NONCANONICAL_VERSION, result.major, result.minor,
                        Constants::MAJOR_VERSION, Constants::MINOR_VERSION)
        end

        unapproved = result.class_names.reject { |name| allowed_class_names.include?(name) }
        return format(REASON_UNAPPROVED, quoted_list(unapproved)) unless unapproved.empty?

        nil
      end

      def observe(violation, snapshot, result)
        reporter.call(violation)
        Decision.new(state: Decision::STATE_OBSERVED, reason: violation,
                     snapshot: snapshot, result: result)
      end

      def accept(snapshot, result)
        Decision.new(state: Decision::STATE_PROCEED, snapshot: snapshot, result: result)
      end

      def reject(reason)
        Decision.new(state: Decision::STATE_BLOCKED, reason: reason)
      end
    end
  end
end
