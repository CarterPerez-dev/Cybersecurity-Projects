# ©AngelaMos | 2026
# chains_test.rb
# frozen_string_literal: true

require_relative "test_helper"

module Marshalsea
  module Chains
    class ChainsTest < Minitest::Test
      CANARY_PATH = "/tmp/marshalsea-canary"
      CANARY_MARKER = "fired"

      def chain
        ErbDefMethod.canary(CANARY_PATH, CANARY_MARKER)
      end

      def test_the_registry_holds_only_descendants_of_base
        refute_empty Chains.all, "control: an empty registry would make this vacuous"
        assert(Chains.all.all? { |chain| chain < Base },
               "Base never registers itself, so filtering it out afterwards was never live code")
      end

      def test_every_chain_file_on_disk_is_registered
        root = File.expand_path("../lib/marshalsea/chains", __dir__)
        on_disk = Dir[File.join(root, "*.rb")].map { |path| File.basename(path, ".rb") } - ["base"]
        registered = Chains.all.map(&:chain_name)

        refute_empty on_disk, "control: the directory must contain a chain to discover"
        missing = on_disk.reject { |file| registered.include?(file.tr("_", "-")) }
        assert_empty missing,
                     "the directory is the chain identity, so a file nobody requires by hand " \
                     "must still be discovered: #{missing.join(', ')}"
      end

      def test_the_published_ranges_cannot_be_rewritten_through_metadata
        assert_predicate ErbDefMethod::AFFECTED, :frozen?
        assert(ErbDefMethod::AFFECTED.all?(&:frozen?),
               "Array#freeze is shallow, so a nested range stays writable unless frozen too")

        assert_raises(FrozenError) { ErbDefMethod.metadata[:affected][2] << "< 4.0.0" }
        assert_raises(FrozenError) { ErbDefMethod.metadata[:affected] << ["< 9.9.9"] }
        assert_raises(FrozenError) { ErbDefMethod.metadata[:cve] = "CVE-0000-0000" }
      end

      def test_the_ranges_still_classify_after_a_rejected_mutation
        assert ErbDefMethod.affects?("5.0.0"),
               "control: a mutation that silently succeeded would move this boundary"
        refute ErbDefMethod.affects?("6.0.4")
      end

      def test_registry_contains_the_erb_chain
        assert_includes Chains.all, ErbDefMethod
      end

      def test_find_by_name
        assert_equal ErbDefMethod, Chains.find("erb-def-method")
      end

      def test_find_raises_on_unknown_name
        assert_raises(UnknownChainError) { Chains.find("no-such-chain") }
      end

      class KeyPositionProbe < Base
        PROBE_METADATA = {
          name: "key-position-probe", vector: "hash", cve: "none", gem: "none",
          affected: [["> 0"]].freeze, kind: Base::KIND_CHAIN
        }.freeze

        def self.metadata = PROBE_METADATA

        def generate = Object.new

        def serialize = in_hash_key_position(generate)
      end

      class RepeatedObjectProbe < KeyPositionProbe
        def generate
          shared = +"repeated"
          [shared, shared]
        end
      end

      def test_a_spliced_key_position_stream_is_byte_correct
        blob = KeyPositionProbe.new.serialize
        revived = ::Marshal.load(blob)

        assert_kind_of Hash, revived
        assert_equal 1, revived.length
        assert_kind_of Object, revived.keys.first
        assert_nil revived.values.first
      end

      def test_a_spliced_stream_really_puts_the_payload_in_key_position
        result = Marshalsea::Marshal::Parser.new(KeyPositionProbe.new.serialize).parse

        refute_empty result.hash_dispatching_keys,
                     "the whole point of the splice is that #hash runs on load"
      end

      def test_the_splice_refuses_a_graph_whose_link_indices_would_shift
        error = assert_raises(ObjectLinkRefusedError) { RepeatedObjectProbe.new.serialize }

        assert_includes error.message, "object link"
      end

      def test_control_the_refused_graph_really_does_carry_an_object_link
        graph = Marshalsea::Marshal::Parser.new(::Marshal.dump(RepeatedObjectProbe.new.generate)).parse

        assert(graph.nodes.any? { |node| node.type == :object_link },
               "control: without a link in the fixture the guard test proves nothing")
      end

      def test_the_two_erb_payloads_are_labelled_by_kind
        assert_predicate ErbDefMethod, :primitive?
        refute_predicate ErbDefMethod, :chain?
        assert_predicate ErbDefModule, :chain?
        refute_predicate ErbDefModule, :primitive?
      end

      def test_the_chain_declares_the_gem_it_needs_and_the_primitive_does_not
        assert_equal ["activesupport"], ErbDefModule.required_gems
        assert_empty ErbDefMethod.required_gems
      end

      def test_the_two_payloads_enter_through_different_methods
        assert_equal "def_method", ErbDefMethod.vector
        assert_equal "hash", ErbDefModule.vector,
                     "the chain enters through an ungated #hash, which is why it needs no " \
                     "application call"
      end

      def test_dispatcher_availability_predicts_whether_the_chain_can_build
        available = ErbDefModule.dispatcher_available?
        built = begin
          ErbDefModule.canary(CANARY_PATH, CANARY_MARKER).generate
          true
        rescue ChainError
          false
        end

        assert_equal available, built,
                     "the predicate must match reality in whichever environment this runs, " \
                     "or a caller cannot tell whether activesupport is present"
      end

      def test_metadata_is_complete
        assert_equal "erb-def-method", ErbDefMethod.chain_name
        assert_equal "def_method", ErbDefMethod.vector
        assert_equal "CVE-2026-41316", ErbDefMethod.cve
        assert_equal "erb", ErbDefMethod.target_gem
      end

      def test_affects_reproduces_the_published_ranges
        { "2.2.3" => true, "4.0.2" => true, "4.0.3" => true, "4.0.4" => true,
          "5.0.0" => true, "6.0.1" => true, "6.0.2" => true, "6.0.3" => true,
          "4.0.3.1" => false, "4.0.4.1" => false, "6.0.1.1" => false, "6.0.4" => false }.each do |version, expected|
          assert_equal expected, ErbDefMethod.affects?(version), "erb #{version}"
        end
      end

      def test_for_version_selects_matching_chains
        assert_includes Chains.for_version("erb", "6.0.1"), ErbDefMethod
        assert_empty Chains.for_version("erb", "6.0.1.1")
      end

      def test_generate_returns_an_object_not_bytes
        assert_kind_of ERB, chain.generate
      end

      def test_generated_object_carries_the_payload_source
        assert_includes chain.generate.instance_variable_get(:@src), CANARY_PATH
      end

      def test_generated_object_omits_the_init_sentinel
        refute_includes chain.generate.instance_variables, :@_init
      end

      def test_src_closes_the_injected_def_before_the_payload
        assert_match(/\A#\nend\n/, chain.src)
      end

      def test_serialize_produces_a_parseable_marshal_stream
        blob = chain.serialize
        assert_equal [Marshalsea::Marshal::Constants::MAJOR_VERSION, Marshalsea::Marshal::Constants::MINOR_VERSION],
                     [blob.getbyte(0), blob.getbyte(1)]
        assert_equal :object, Marshalsea::Marshal::Parser.new(blob).parse.root.type
      end

      def test_payload_is_visible_to_the_parser_without_deserializing
        result = Marshalsea::Marshal::Parser.new(chain.serialize).parse
        assert_includes result.class_names, "ERB"
      end

      def test_base_refuses_to_generate
        assert_raises(NotImplementedByChainError) { Base.new.generate }
      end

      def test_base_refuses_metadata
        assert_raises(NotImplementedByChainError) { Base.metadata }
      end
    end
  end
end
