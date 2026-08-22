# ©AngelaMos | 2026
# load_guard_test.rb
# frozen_string_literal: true

require_relative "../test_helper"

module Marshalsea
  module Marshal
    class LoadGuardTest < Minitest::Test
      BODIES = []

      class Permitted
        def marshal_dump = ["payload"]

        def marshal_load(_data)
          BODIES << "Permitted#marshal_load"
        end
      end

      class Gadget
        def marshal_dump = ["payload"]

        def marshal_load(_data)
          BODIES << "Gadget#marshal_load"
        end
      end

      class UserDefGadget
        def _dump(_depth) = "opaque"

        def self._load(_data)
          BODIES << "UserDefGadget._load"
          allocate
        end
      end

      class MethodMissingGadget
        def marshal_dump = ["payload"]

        def respond_to_missing?(name, include_private = false)
          name == :marshal_load || super
        end

        def method_missing(name, *args)
          return BODIES << "MethodMissingGadget via method_missing" if name == :marshal_load

          super
        end
      end

      class KeyTrigger
        def hash
          BODIES << "KeyTrigger#hash"
          7
        end

        def eql?(_other) = false
      end

      class Deferred
        def to_s
          BODIES << "Deferred#to_s"
          ""
        end
      end

      def setup
        BODIES.clear
      end

      def guard(permitted: [], strict: false)
        LoadGuard.new(permitted_class_names: permitted, strict: strict)
      end

      def name_of(klass) = klass.name

      def true_name_of(klass) = LoadGuard::NAME_OF.bind_call(klass)

      def key_trigger_blob
        blob = ::Marshal.dump({ KeyTrigger.new => 1 })
        BODIES.clear
        blob
      end

      def test_it_vetoes_a_gadget_before_the_hook_body_runs
        blob = ::Marshal.dump(Gadget.new)

        error = assert_raises(GuardedLoadError) { guard.load(blob) }
        assert_includes error.message, "#{name_of(Gadget)}#marshal_load"
        assert_empty BODIES,
                     "the veto is the whole point: a Marshal.load proc fires after the body, " \
                     "a TracePoint on :call fires before it"
      end

      def test_control_a_permitted_hook_runs_its_body
        blob = ::Marshal.dump(Permitted.new)

        guard(permitted: [name_of(Permitted)]).load(blob)
        assert_equal ["Permitted#marshal_load"], BODIES,
                     "control: a guard that blocks everything would pass the previous test " \
                     "without proving anything"
      end

      def test_control_a_benign_payload_passes_with_nothing_permitted
        revived = guard.load(::Marshal.dump({ "a" => 1, "b" => ["x", :y, 2.5, nil, true] }))

        assert_equal({ "a" => 1, "b" => ["x", :y, 2.5, nil, true] }, revived)
        assert_empty BODIES
      end

      def test_it_vetoes_a_gadget_buried_at_depth
        blob = ::Marshal.dump([[[{ "a" => [Gadget.new] }]]])

        assert_raises(GuardedLoadError) { guard.load(blob) }
        assert_empty BODIES, "nesting must not buy a gadget a pass"
      end

      def test_it_vetoes_the_singleton_load_path
        blob = ::Marshal.dump(UserDefGadget.new)

        error = assert_raises(GuardedLoadError) { guard.load(blob) }
        assert_includes error.message, "_load"
        assert_empty BODIES
      end

      def test_it_vetoes_the_method_missing_evasion
        blob = ::Marshal.dump(MethodMissingGadget.new)

        assert_raises(GuardedLoadError) { guard.load(blob) }
        assert_empty BODIES,
                     "Marshal honours respond_to_missing?, so a hook list without " \
                     "method_missing and respond_to_missing? is evaded by a proxy"
      end

      def test_a_guard_that_has_not_run_reports_nothing
        assert_empty guard.observations,
                     "an empty report must mean nothing was observed, never that a load " \
                     "has not happened yet"
      end

      def test_observations_name_every_hook_the_load_reached
        subject = guard(permitted: [name_of(Permitted)])
        subject.load(::Marshal.dump([Permitted.new, Permitted.new]))

        assert_equal ["#{name_of(Permitted)}#marshal_load"] * 2, subject.observations.map(&:to_s)
        assert(subject.observations.all?(&:permitted?))
      end

      def test_a_vetoed_load_still_records_what_it_saw
        subject = guard
        assert_raises(GuardedLoadError) { subject.load(::Marshal.dump(Gadget.new)) }

        refute_empty subject.observations, "an ensure block must record the observation that " \
                                           "caused the veto, or the report loses the reason"
        refute_predicate subject.observations.first, :permitted?
      end

      def test_the_default_hook_set_does_not_watch_the_hottest_methods
        subject = guard

        assert subject.watches?(:marshal_load)
        assert subject.watches?(:method_missing)
        refute subject.watches?(:hash)
        refute subject.watches?(:eql?)
      end

      def test_documented_bypass_the_default_guard_misses_a_hash_key_trigger
        guard.load(key_trigger_blob)

        assert_equal ["KeyTrigger#hash"], BODIES,
                     "the notice claims this bypass exists, so it must be demonstrable"
      end

      def test_strict_mode_closes_the_hash_key_bypass
        blob = key_trigger_blob

        assert_raises(GuardedLoadError) { guard(strict: true).load(blob) }
        assert_empty BODIES
      end

      def test_the_boundary_detector_catches_that_same_shape_before_any_bytes_load
        decision = BoundaryDetector.new(allowed_class_names: [name_of(KeyTrigger)])
                                   .inspect_stream(key_trigger_blob)

        assert_predicate decision, :blocked?,
                         "the cheap place to catch a key-position gadget is before the load, " \
                         "which is why the guard leaves #hash opt-in"
        assert_empty BODIES
      end

      def test_documented_bypass_a_class_with_no_hook_fires_after_the_window
        subject = guard(permitted: [])
        revived = subject.load(::Marshal.dump({ "template" => Deferred.new }))

        assert_empty subject.observations, "the guard sees nothing, because nothing is dispatched"
        assert_empty BODIES

        format("%s", revived["template"])
        assert_equal ["Deferred#to_s"], BODIES,
                     "the guard covers the load window and nothing after it"
      end

      def test_the_guard_relies_on_tracepoint_being_thread_scoped
        blob = ::Marshal.dump(Permitted.new)
        elsewhere = []
        here = []

        watch_other = TracePoint.new(*LoadGuard::EVENTS) do |event|
          elsewhere << event.method_id if LoadGuard::GATED_HOOKS.include?(event.method_id)
        end
        watch_other.enable { Thread.new { ::Marshal.load(blob) }.join }

        watch_here = TracePoint.new(*LoadGuard::EVENTS) do |event|
          here << event.method_id if LoadGuard::GATED_HOOKS.include?(event.method_id)
        end
        watch_here.enable { ::Marshal.load(blob) }

        refute_empty here, "control: the same tracer must fire for a load on this thread"
        assert_empty elsewhere,
                     "enable with a block defaults target_thread to the current thread, which " \
                     "is why one request's guard does not tax the whole process"
      end

      class HostileName
        def self.name = raise(NameError, "name unavailable")

        def marshal_dump = ["payload"]

        def marshal_load(_data)
          BODIES << "HostileName#marshal_load"
        end
      end

      def test_an_owner_that_refuses_to_name_itself_is_named_truthfully_anyway
        blob = ::Marshal.dump(HostileName.new)

        error = assert_raises(GuardedLoadError) { guard.load(blob) }
        assert_includes error.message, true_name_of(HostileName),
                        "the guard reads Module#name unbound, so a class that overrides .name " \
                        "cannot control what the guard calls it"
        assert_raises(NameError) { name_of(HostileName) }
        assert_empty BODIES
      end

      def test_control_an_owner_that_refuses_to_name_itself_cannot_be_permitted
        blob = ::Marshal.dump(HostileName.new)

        assert_raises(GuardedLoadError) do
          guard(permitted: [LoadGuard::ANONYMOUS_OWNER]).load(blob)
        end
        assert_empty BODIES, "the placeholder must not be spellable as an allowlist entry"
      end

      class DispatchTattle
        DISPATCHED = []

        instance_methods.each do |method_name|
          undef_method(method_name) unless %i[__send__ __id__ object_id].include?(method_name)
        end

        def marshal_dump = ["payload"]

        def respond_to_missing?(name, _include_private = false) = name == :marshal_load

        def method_missing(name, *args)
          DISPATCHED << name
          return BODIES << "DispatchTattle via method_missing" if name == :marshal_load

          super
        end
      end

      def test_the_guard_never_dispatches_a_method_on_the_receiver_it_inspects
        DispatchTattle::DISPATCHED.clear
        blob = ::Marshal.dump(DispatchTattle.new)
        DispatchTattle::DISPATCHED.clear
        BODIES.clear

        error = assert_raises(GuardedLoadError) { guard.load(blob) }

        assert_includes error.message, name_of(DispatchTattle),
                        "resolving the owner must still produce the real class name"
        assert_empty BODIES, "the hook body must not run"
        assert_empty DispatchTattle::DISPATCHED & %i[class is_a? name],
                     "identifying the receiver must not call a method ON the receiver. A " \
                     "method-erased proxy answers .class and .is_a? through method_missing, " \
                     "so a guard that asks the receiver what it is detonates the chain it " \
                     "was about to veto, inside a TracePoint handler that does not trace itself"
      end

      def test_the_error_is_catchable_by_an_ordinary_rescue
        assert_operator GuardedLoadError, :<, StandardError,
                        "SecurityError descends from Exception and would bypass every " \
                        "rescue => e in the stack"
      end

      def test_it_ships_a_notice_that_names_its_own_limits
        notice = LoadGuard::LIMITATION_NOTICE

        assert_includes notice, "not a boundary"
        assert_includes notice, "#hash"
        assert_includes notice, "thread-scoped"
      end
    end
  end
end
