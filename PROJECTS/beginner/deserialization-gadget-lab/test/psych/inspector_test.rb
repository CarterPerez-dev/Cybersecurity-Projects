# ©AngelaMos | 2026
# inspector_test.rb
# frozen_string_literal: true

require_relative "../test_helper"

module Marshalsea
  module Psych
    class InspectorTest < Minitest::Test
      FIRED = []

      class WipedProxy
        instance_methods.each { |m| undef_method m unless /^__|^object_id$/.match?(m) }

        def method_missing(name, *_args)
          FIRED << name
          name
        end

        def respond_to_missing?(_name, _include_private = false)
          true
        end
      end

      class Revived
        def init_with(coder)
          FIRED << :init_with
          @cmd = coder["cmd"]
        end
      end

      class MarshalGadget
        def marshal_load(_data)
          FIRED << :marshal_load
        end

        def marshal_dump = ["x"]
      end

      BENIGN = "---\nuser: guest\nroles:\n  - 1\n  - 2\n"

      def setup
        FIRED.clear
      end

      def inspector(**)
        Inspector.new(**)
      end

      def object_document(class_name)
        "--- !ruby/object:#{class_name}\ncmd: id\n"
      end

      def test_a_document_of_plain_scalars_proceeds
        assert_predicate inspector.inspect_document(BENIGN), :proceed?
      end

      def test_it_rejects_non_string_input_without_converting_it
        hostile = Object.new
        def hostile.to_s = raise("to_s must never be called on untrusted input")

        decision = inspector.inspect_document(hostile)
        assert_predicate decision, :blocked?
        assert_equal Inspector::REASON_INPUT_TYPE, decision.reason
      end

      def revival_documents
        {
          "!ruby/object" => ["--- !ruby/object:Alpha\na: 1\n", "init_with"],
          "!ruby/hash" => ["--- !ruby/hash:Beta\na: 1\n", "[]="],
          "!ruby/array" => ["--- !ruby/array:Gamma\ninternal: [1]\n", "init_with"],
          "!ruby/struct" => ["--- !ruby/struct:Delta\na: 1\n", "init_with"],
          "!ruby/exception" => ["--- !ruby/exception:Epsilon\nmessage: x\n", "init_with"],
          "!ruby/marshalable" => ["--- !ruby/marshalable:Zeta\na: 1\n", "marshal_load"]
        }
      end

      def test_every_revival_tag_is_reported_with_the_method_it_would_dispatch
        missed = revival_documents.reject do |_tag, (document, method_name)|
          decision = inspector.inspect_document(document)
          decision.blocked? && decision.reason.include?(method_name)
        end

        assert_empty missed.keys,
                     "a reject reason must name how the class gets revived: #{missed.keys.join(', ')}"
      end

      def test_a_class_in_a_mapping_key_is_reported_as_key_dispatch
        decision = inspector.inspect_document("---\n? !ruby/object:KeyClass {}\n: value\n")

        assert_predicate decision, :blocked?
        assert_includes decision.reason, "mapping key"
        assert_includes decision.reason, "KeyClass"
      end

      def test_the_same_class_in_a_value_is_reported_as_revival_not_key_dispatch
        decision = inspector.inspect_document("---\nk: !ruby/object:KeyClass {}\n")

        assert_predicate decision, :blocked?
        assert_includes decision.reason, "init_with"
        refute_includes decision.reason, "mapping key",
                        "position is the signal, exactly as it is on the Marshal side"
      end

      def test_an_allowlisted_class_proceeds
        decision = inspector(permitted_class_names: %w[Alpha]).inspect_document(object_document("Alpha"))

        assert_predicate decision, :proceed?
      end

      def test_an_allowlist_never_exempts_key_position_dispatch
        decision = inspector(permitted_class_names: %w[KeyClass])
                   .inspect_document("---\n? !ruby/object:KeyClass {}\n: v\n")

        assert_predicate decision, :blocked?,
                         "the mapping is rebuilt before any allowlist can act, so permitting " \
                         "the class does not stop its #hash running"
      end

      def test_it_rejects_a_malformed_document
        decision = inspector.inspect_document("---\n\tbad: [\n")

        assert_predicate decision, :blocked?
        assert_includes decision.reason, "MalformedDocumentError"
      end

      def assert_ceiling_rejects(document, **narrow)
        assert_predicate inspector.inspect_document(document), :proceed?,
                         "control: this document must be accepted under default limits, " \
                         "or the ceiling is not what rejected it"

        decision = inspector(limits: Limits.new(**narrow)).inspect_document(document)
        assert_predicate decision, :blocked?
        assert_includes decision.reason, "LimitExceededError"
      end

      def test_it_enforces_a_byte_ceiling
        assert_ceiling_rejects(BENIGN, max_bytes: 8)
      end

      def test_it_enforces_a_depth_ceiling
        assert_ceiling_rejects("---\n#{'- ' * 40}1\n", max_depth: 4)
      end

      def test_it_enforces_a_node_ceiling
        assert_ceiling_rejects("---\n#{(1..40).map { |i| "k#{i}: #{i}" }.join("\n")}\n", max_nodes: 5)
      end

      def test_it_enforces_an_alias_ceiling
        aliased = "---\na: &x [1, 2]\n#{(1..20).map { |i| "k#{i}: *x" }.join("\n")}\n"

        assert_ceiling_rejects(aliased, max_aliases: 4)
      end

      def test_it_enforces_a_document_ceiling
        assert_ceiling_rejects("--- 1\n--- 2\n--- 3\n", max_documents: 2)
      end

      def test_it_counts_aliases_rather_than_expanding_them
        document = inspector.read("---\na: &x [1, 2]\nb: *x\nc: *x\n")

        assert_equal 2, document.alias_count
        assert_operator document.node_count, :>, 0
        assert_equal 1, document.document_count
      end

      def yaml_watcher(&)
        fired = false
        tracer = TracePoint.new(:call, :c_call) do |tp|
          fired = true if %i[load unsafe_load safe_load].include?(tp.method_id) &&
                          tp.self.equal?(::Psych)
        end
        tracer.enable(&)
        fired
      end

      def test_the_watcher_oracle_is_live
        assert yaml_watcher { ::Psych.unsafe_load(BENIGN) },
               "oracle failed to observe a real load, so the next test would pass vacuously"
      end

      def test_inspecting_never_loads_the_document
        refute yaml_watcher { inspector.inspect_document(object_document("Alpha")) },
               "the inspector called into a Psych loader"
      end

      def test_inspecting_revives_nothing
        inspector.inspect_document("--- !ruby/object:Marshalsea::Psych::InspectorTest::Revived\ncmd: id\n")

        assert_empty FIRED, "init_with must not run during inspection"
      end

      def test_psych_allowlist_is_a_veto_where_the_marshal_proc_is_a_post_mortem
        document = "--- !ruby/object:Marshalsea::Psych::InspectorTest::Revived\ncmd: id\n"
        assert_raises(::Psych::DisallowedClass) { ::Psych.safe_load(document, permitted_classes: []) }
        assert_empty FIRED,
                     "Psych checks the tag before revival, so init_with never ran"

        FIRED.clear
        blob = ::Marshal.dump(MarshalGadget.new)
        begin
          ::Marshal.load(blob, ->(object) { object })
        rescue StandardError
          nil
        end
        assert_equal [:marshal_load], FIRED,
                     "Marshal runs its proc in r_post_proc, after load_funcall has already " \
                     "fired the callback. Same intent, opposite outcome, decided by where " \
                     "the check sits"
      end

      def test_a_fully_wiped_proxy_is_a_yaml_entry_point_and_not_a_marshal_one
        document = "--- !ruby/object:Marshalsea::Psych::InspectorTest::WipedProxy\ncmd: id\n"
        ::Psych.unsafe_load(document)

        assert_includes FIRED, :init_with,
                        "Psych calls respond_to?(:init_with) as an ordinary Ruby call, so a " \
                        "method-erased proxy answers through method_missing"

        FIRED.clear
        stream = "\x04\bU:@Marshalsea::Psych::InspectorTest::WipedProxy0".b
        marshal_outcome = begin
          ::Marshal.load(stream)
          :revived
        rescue StandardError => e
          e.class
        end

        assert_empty FIRED, "the identical class is not reachable through Marshal"
        refute_equal :revived, marshal_outcome
      end

      def test_the_inspector_flags_that_same_proxy_document
        decision = inspector.inspect_document(
          "--- !ruby/object:Marshalsea::Psych::InspectorTest::WipedProxy\ncmd: id\n"
        )

        assert_predicate decision, :blocked?
        assert_includes decision.reason, "init_with"
      end

      def test_it_never_exposes_a_safety_claiming_api
        %i[safe? trusted? sanitized? safe_load].each do |forbidden|
          refute_respond_to inspector, forbidden,
                            "#{forbidden} implies a guarantee this inspector cannot make"
        end
      end

      def test_it_ships_a_notice_that_defers_to_psych_safe_load
        notice = Inspector::LIMITATION_NOTICE

        assert_includes notice, "Prefer YAML.safe_load"
        assert_includes notice, "checks the tag before"
        assert_includes notice, "revives nothing"
      end
    end
  end
end
