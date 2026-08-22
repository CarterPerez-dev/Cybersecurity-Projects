# ©AngelaMos | 2026
# load_guard.rb
# frozen_string_literal: true

module Marshalsea
  module Marshal
    class GuardedLoadError < StandardError; end

    class LoadGuard
      GATED_HOOKS = %i[marshal_load _load _load_data].freeze
      DISPATCH_HOOKS = %i[method_missing respond_to_missing?].freeze
      KEY_HOOKS = %i[hash eql?].freeze

      DEFAULT_HOOKS = (GATED_HOOKS + DISPATCH_HOOKS).freeze
      STRICT_HOOKS = (DEFAULT_HOOKS + KEY_HOOKS).freeze

      EVENTS = %i[call c_call].freeze

      REASON = "deserialization hook %s#%s is not permitted"
      ANONYMOUS_OWNER = "(class with no name)"

      CLASS_OF = ::Object.instance_method(:class).freeze
      KIND_OF = ::Object.instance_method(:is_a?).freeze
      NAME_OF = ::Module.instance_method(:name).freeze

      LIMITATION_NOTICE = <<~NOTICE
        SECURITY LIMITATION

        Marshalsea::Marshal::LoadGuard vetoes a deserialization hook before its body runs,
        which is the thing a Marshal.load allowlist proc cannot do. It is defense in depth
        and a tripwire. It is not a boundary, and it never makes Marshal.load on untrusted
        input safe.

        It covers the load window only. A class carrying no hook at all is instantiated
        freely and fires whenever the application later touches it, which is outside any
        window this guard can see.

        With the default hook set it does not watch #hash or #eql?. Rebuilding a Hash
        rehashes its keys, so a key object's #hash runs inside Marshal.load with no
        deserialization hook involved. Pass strict: true to watch those two as well, and
        accept that they are among the hottest methods in Ruby: the cost and the
        false-positive profile both change completely. Marshalsea::Marshal::BoundaryDetector
        catches that same shape before any bytes are loaded, which is the cheaper place
        to catch it.

        The guard is thread-scoped. A load on another thread is not covered.

        Its cost is not a multiplier. Enabling a TracePoint costs roughly 46 microseconds
        per load on a stock ruby:4.0-slim, near enough constant, so the ratio is decided by
        how much work the load itself does. Measured 2026-07-30: 40x on a 45-byte session
        cookie, 21x on a 142-byte session, 1.1x on a 46 KB document, 1.0x on a 488 KB one.
        Guarding a large payload is close to free. Guarding a session cookie on every
        request is not, and a cookie is exactly what this lab deserializes.
      NOTICE

      class Observation
        attr_reader :class_name, :method_name

        def initialize(class_name:, method_name:, permitted:)
          @class_name = class_name
          @method_name = method_name
          @permitted = permitted
        end

        def permitted?
          @permitted
        end

        def to_s
          "#{class_name}##{method_name}"
        end
      end

      attr_reader :observations

      def initialize(permitted_class_names: [], strict: false)
        @permitted_class_names = permitted_class_names.map(&:to_s).freeze
        @hooks = strict ? STRICT_HOOKS : DEFAULT_HOOKS
        @observations = [].freeze
      end

      def load(blob)
        seen = []
        tracer = TracePoint.new(*EVENTS) { |event| inspect_event(event, seen) }
        result = nil
        begin
          tracer.enable { result = ::Marshal.load(blob) }
        ensure
          @observations = seen.freeze
        end
        result
      end

      def watches?(hook)
        hooks.include?(hook)
      end

      private

      attr_reader :permitted_class_names, :hooks

      def inspect_event(event, seen)
        return unless hooks.include?(event.method_id)

        owner = owner_name(event.self)
        label = owner || ANONYMOUS_OWNER
        permitted = !owner.nil? && permitted_class_names.include?(owner)
        seen << Observation.new(class_name: label, method_name: event.method_id,
                                permitted: permitted)
        return if permitted

        raise GuardedLoadError, format(REASON, label, event.method_id)
      end

      def owner_name(receiver)
        owner = KIND_OF.bind_call(receiver, ::Module) ? receiver : CLASS_OF.bind_call(receiver)
        name = NAME_OF.bind_call(owner)
        name if name.is_a?(String) && !name.empty?
      rescue StandardError
        nil
      end
    end
  end
end
