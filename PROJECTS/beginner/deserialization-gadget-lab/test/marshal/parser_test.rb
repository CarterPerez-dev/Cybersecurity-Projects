# ©AngelaMos | 2026
# parser_test.rb
# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/adversarial_corpus"

module Marshalsea
  module Marshal
    class ParserTest < Minitest::Test
      def parse(blob)
        Parser.new(blob).parse
      end

      def roundtrip(object)
        parse(::Marshal.dump(object)).root
      end

      def test_rejects_empty_stream
        assert_raises(TruncatedStreamError) { parse("") }
      end

      def test_rejects_header_only
        assert_raises(TruncatedStreamError) { parse("\x04\x08") }
      end

      def test_rejects_wrong_major_version
        assert_raises(UnsupportedVersionError) { parse("\x05\x08\x30") }
      end

      def test_rejects_future_minor_version
        assert_raises(UnsupportedVersionError) { parse("\x04\x09\x30") }
      end

      def test_accepts_older_minor_version
        assert_equal :nil, parse("\x04\x07\x30").root.type
      end

      def ruby_accepts_stream?(bytes)
        ::Marshal.load(bytes)
        true
      rescue ArgumentError, TypeError
        false
      end

      def parser_accepts_stream?(bytes)
        parse(bytes)
        true
      rescue StreamError
        false
      end

      def test_header_version_agreement_with_real_ruby
        probes = (0..9).to_h { |minor| ["4.#{minor}", "\x04#{minor.chr}0".b] }
        observed = probes.transform_values { |bytes| ruby_accepts_stream?(bytes) }

        assert_includes observed.values, true, "no version accepted, so the oracle is dead"
        assert_includes observed.values, false, "every version accepted, so the oracle proves nothing"

        mismatches = probes.filter_map do |label, bytes|
          mine = parser_accepts_stream?(bytes)
          next if mine == observed.fetch(label)

          "#{label}: ruby=#{observed.fetch(label)} parser=#{mine}"
        end

        assert_empty mismatches,
                     "the parser is a forensic tool and must accept exactly what Marshal.load " \
                     "accepts:\n  #{mismatches.join("\n  ")}"
      end

      def test_result_reports_the_declared_version
        result = parse("\x04\x07\x30")
        assert_equal [4, 7], [result.major, result.minor]
        refute_predicate result, :canonical_version?

        assert_predicate parse(::Marshal.dump(nil)), :canonical_version?
      end

      class RoleFixture; end

      def class_name_slot_streams
        name = "Marshalsea::Marshal::ParserTest::RoleFixture"
        symbol = AdversarialCorpus.sym(name)

        {
          "symbol" => AdversarialCorpus.stream("o#{symbol}#{AdversarialCorpus.fixnum(0)}"),
          "ivar wrapped symbol" => AdversarialCorpus.stream(
            "oI#{symbol}#{AdversarialCorpus.fixnum(1)}#{AdversarialCorpus.sym('E')}T#{AdversarialCorpus.fixnum(0)}"
          ),
          "symlink" => AdversarialCorpus.stream(
            "[#{AdversarialCorpus.fixnum(2)}#{symbol}o#{AdversarialCorpus.symlink(0)}#{AdversarialCorpus.fixnum(0)}"
          ),
          "fixnum" => AdversarialCorpus.stream("oi\x0a#{AdversarialCorpus.fixnum(0)}"),
          "string" => AdversarialCorpus.stream("o#{AdversarialCorpus.str(name)}#{AdversarialCorpus.fixnum(0)}"),
          "nil" => AdversarialCorpus.stream("o0#{AdversarialCorpus.fixnum(0)}")
        }
      end

      def test_class_name_slot_role_agreement_with_real_ruby
        observed = class_name_slot_streams.transform_values { |bytes| ruby_accepts_stream?(bytes) }

        assert_includes observed.values, true, "no slot accepted, so the oracle is dead"
        assert_includes observed.values, false, "every slot accepted, so the oracle proves nothing"

        mismatches = class_name_slot_streams.filter_map do |label, bytes|
          mine = parser_accepts_stream?(bytes)
          next if mine == observed.fetch(label)

          "#{label}: ruby=#{observed.fetch(label)} parser=#{mine}"
        end

        assert_empty mismatches,
                     "a class-name slot accepts only a symbol, an ivar-wrapped symbol, or a " \
                     "symlink:\n  #{mismatches.join("\n  ")}"
      end

      def test_rejects_unknown_tag
        assert_raises(UnknownTagError) { parse("\x04\x08\x00") }
      end

      def test_rejects_trailing_bytes
        assert_raises(TrailingBytesError) { parse(::Marshal.dump(nil) + "junk") }
      end

      def test_parses_nil
        assert_equal :nil, roundtrip(nil).type
      end

      def test_parses_booleans
        assert_equal true, roundtrip(true).value
        assert_equal false, roundtrip(false).value
      end

      def test_parses_fixnum_across_every_encoding_width
        [0, 1, 5, 122, 123, 255, 256, 65_535, 65_536, 1_073_741_823,
         -1, -123, -124, -256, -65_536, -1_073_741_824].each do |n|
          assert_equal n, roundtrip(n).value, "fixnum #{n} did not round-trip"
        end
      end

      def test_parses_bignum_both_signs
        [2**64, -(2**64), (2**128) + 7].each do |n|
          assert_equal n, roundtrip(n).value, "bignum #{n} did not round-trip"
        end
      end

      def ruby_rejects_bignum_sign?(bytes)
        ::Marshal.load(bytes)
        false
      rescue ArgumentError, TypeError
        true
      end

      def parser_rejects_bignum_sign?(bytes)
        parse(bytes)
        false
      rescue StreamError
        true
      end

      def test_bignum_sign_byte_agreement_with_real_ruby
        probes = AdversarialCorpus::BIGNUM_SIGNS.to_h do |sign|
          [sign, AdversarialCorpus.stream(AdversarialCorpus.bignum(sign, 1))]
        end
        observed = probes.transform_values { |bytes| ruby_rejects_bignum_sign?(bytes) }

        assert_includes observed.values, true, "no sign was rejected, so the oracle is dead"
        assert_includes observed.values, false, "every sign was rejected, so the oracle proves nothing"

        mismatches = probes.filter_map do |sign, bytes|
          mine = parser_rejects_bignum_sign?(bytes)
          next if mine == observed.fetch(sign)

          "#{sign.inspect}: ruby_rejects=#{observed.fetch(sign)} parser_rejects=#{mine}"
        end

        assert_empty mismatches, "bignum sign handling diverges from Marshal.load:\n  #{mismatches.join("\n  ")}"
      end

      def test_bignum_magnitude_is_charged_the_same_budget_as_a_string
        words = AdversarialCorpus::BIGNUM_HUGE_WORDS
        magnitude = words * AdversarialCorpus::BIGNUM_WORD_BYTES
        limits = Limits.new

        big = AdversarialCorpus.stream(AdversarialCorpus.bignum("+", words))
        str = AdversarialCorpus.stream(AdversarialCorpus.str("A" * magnitude))

        assert_raises(LimitExceededError, "a #{magnitude}-byte string is rejected") do
          Parser.new(str, limits: limits).parse
        end
        assert_raises(LimitExceededError, "so #{magnitude} bignum magnitude bytes must be too") do
          Parser.new(big, limits: limits).parse
        end
      end

      def test_parses_float
        assert_in_delta 3.5, roundtrip(3.5).value, 0.0
      end

      def test_parses_symbol
        assert_equal :marshal_load, roundtrip(:marshal_load).value
      end

      def test_parses_string_through_ivar_wrapper
        node = roundtrip("hello")
        assert_equal :string, node.type
        assert_equal "hello", node.value
      end

      def test_parses_array
        node = roundtrip([1, 2, 3])
        assert_equal :array, node.type
        assert_equal [1, 2, 3], node.children.map(&:value)
      end

      def test_parses_nested_array
        node = roundtrip([1, [2, [3]]])
        assert_equal 3, node.children.last.children.last.children.first.value
      end

      def test_parses_hash
        node = roundtrip({ a: 1 })
        assert_equal :hash, node.type
        assert_equal 1, node.children.length
      end

      def test_object_links_are_zero_indexed
        cyclic = []
        cyclic << cyclic
        node = roundtrip(cyclic)
        link = node.children.first
        assert_equal :object_link, link.type
        assert_equal 0, link.value
      end

      class LinkStringSubclass < String; end

      module LinkExtension; end

      def link_probe(first)
        shared = +"ccc"
        ::Marshal.dump([first, +"bbb", shared, shared])
      end

      def link_probes
        {
          "plain object (o)" => link_probe(Object.new),
          "user_class (C)" => link_probe(LinkStringSubclass.new("aaa")),
          "extended (e)" => link_probe((+"aaa").extend(LinkExtension))
        }
      end

      def test_object_link_indices_match_ruby_for_wrapper_tags
        mismatches = link_probes.filter_map do |label, blob|
          link = parse(blob).nodes.find { |node| node.type == :object_link }
          flunk "#{label}: fixture carries no object link, so it proves nothing" unless link

          ruby_target = ::Marshal.load(blob)[3]
          next if link.link_target&.value == ruby_target

          "#{label}: index #{link.value} resolves to " \
            "#{link.link_target&.value.inspect}, Ruby resolves it to #{ruby_target.inspect}"
        end

        assert_empty mismatches,
                     "a wrapper tag must occupy the same object-table slot Ruby gives it:\n  " \
                     "#{mismatches.join("\n  ")}"
      end

      def test_rejects_out_of_bounds_object_link
        assert_raises(InvalidLinkError) { parse("\x04\x08@\x0a") }
      end

      def test_rejects_out_of_bounds_symlink
        assert_raises(InvalidLinkError) { parse("\x04\x08;\x0a") }
      end

      def test_resolves_symlink_to_prior_symbol
        node = roundtrip(%i[same same])
        assert_equal :symlink, node.children.last.type
        assert_equal :same, node.children.last.value
      end

      def test_extracts_class_name_from_plain_object
        blob = ::Marshal.dump(Fixture.new)
        result = parse(blob)
        assert_includes result.class_names, "Marshalsea::Marshal::ParserTest::Fixture"
      end

      def test_extracts_class_name_without_instantiating
        refute Fixture.instantiated, "parser must not construct the class"
        parse(::Marshal.dump(Fixture.new))
        refute Fixture.instantiated, "parser instantiated a class during parse"
      end

      def test_flags_usermarshal_as_sink
        result = parse(::Marshal.dump(UserMarshalFixture.new))
        sink = result.sinks.first
        refute_nil sink
        assert_equal "marshal_load", sink.sink_method
        assert_equal "Marshalsea::Marshal::ParserTest::UserMarshalFixture", sink.class_name
      end

      def test_flags_userdef_as_sink
        result = parse(::Marshal.dump(UserDefFixture.new))
        assert_equal "_load", result.sinks.first.sink_method
      end

      def test_clean_payload_reports_no_sinks
        assert_empty parse(::Marshal.dump([1, "two", :three, { a: 1 }])).sinks
      end

      def test_rejects_truncated_string_body
        assert_raises(TruncatedStreamError) { parse("\x04\x08\"\x0aab") }
      end

      def test_rejects_truncated_array_elements
        assert_raises(TruncatedStreamError) { parse("\x04\x08[\x08i\x06") }
      end

      def test_rejects_truncated_multibyte_fixnum
        assert_raises(TruncatedStreamError) { parse("\x04\x08i\x03\x01") }
      end

      def test_rejects_negative_array_count
        assert_raises(MalformedCountError) { parse("\x04\x08[\xFA") }
      end

      def test_rejects_negative_hash_count
        assert_raises(MalformedCountError) { parse("\x04\x08{\xFA") }
      end

      def test_rejects_negative_bignum_word_count
        assert_raises(MalformedCountError) { parse("\x04\x08l+\xFA") }
      end

      def test_rejects_negative_instance_variable_count
        assert_raises(MalformedCountError) { parse("\x04\x08I\"\x06a\xFA") }
      end

      def test_rejects_negative_string_length
        assert_raises(MalformedCountError) { parse("\x04\x08\"\xFA") }
      end

      def test_rejects_negative_struct_member_count
        assert_raises(MalformedCountError) { parse("\x04\x08S:\x06A\xFA") }
      end

      def test_negative_length_is_caught_by_the_count_guard_not_the_take_guard
        error = assert_raises(MalformedCountError) { parse("\x04\x08\"\xFA") }
        assert_includes error.message, Constants::ROLE_LENGTH,
                        "take's own guard caught it, so read_count is not enforcing anything"
      end

      def test_negative_counts_never_rewind_the_cursor
        parser = Parser.new("\x04\x08\"\xFA")
        before = parser.instance_variable_get(:@position)
        assert_raises(MalformedCountError) { parser.parse }
        assert_operator parser.instance_variable_get(:@position), :>=, before,
                        "the cursor moved backwards, which is a loop primitive"
      end

      def test_parses_regexp_and_consumes_its_options_byte
        node = roundtrip(/pattern/i)
        assert_equal :regexp, node.type
        assert_equal "pattern", node.value
      end

      def test_parses_regexp_nested_in_a_collection
        node = roundtrip([/first/, /second/mx])
        assert_equal %w[first second], node.children.map(&:value)
      end

      def test_regexp_options_are_decoded_rather_than_discarded
        insensitive = roundtrip(/ab/i)
        plain = roundtrip(/ab/)

        assert_equal plain.value, insensitive.value, "control: the source bytes are identical"
        refute_equal plain.regexp_options, insensitive.regexp_options,
                     "two regexps that differ only in their flags must not parse identically"
        assert_equal 0, plain.regexp_options
        assert_predicate insensitive.regexp_options, :positive?
      end

      def test_regexp_options_byte_is_not_mistaken_for_the_next_value
        node = roundtrip([/pattern/ix, :sentinel])
        assert_equal :symbol, node.children.last.type
        assert_equal :sentinel, node.children.last.value
      end

      def test_every_malformed_count_stays_inside_the_stream_error_hierarchy
        ["\x04\x08[\xFA", "\x04\x08{\xFA", "\x04\x08l+\xFA", "\x04\x08\"\xFA"].each do |blob|
          parse(blob)
          flunk "expected #{blob.inspect} to be rejected"
        rescue StreamError
          pass
        rescue StandardError => e
          flunk "#{blob.inspect} leaked #{e.class} outside StreamError"
        end
      end

      def test_rejects_negative_object_link_index
        assert_raises(InvalidLinkError) { parse("\x04\x08[\x06@\xFA") }
      end

      def test_rejects_negative_symlink_index
        assert_raises(InvalidLinkError) { parse("\x04\x08[\x07:\x06a;\xFA") }
      end

      def test_sink_in_an_instance_variable_name_position_is_still_reported
        result = parse("\x04\x08I\"\x06a\x06u:\x09Evil\x06x0")
        assert_includes result.class_names, "Evil"
        assert_equal(["Evil#_load"], result.sinks.map { |s| "#{s.class_name}##{s.sink_method}" })
      end

      def tripwires(blob)
        parse(blob).sinks.select { |node| node.class_name == AdversarialCorpus::TRIPWIRE_CLASS }
      end

      def test_class_name_node_is_traversable
        result = parse(::Marshal.dump(Fixture.new))
        names = result.nodes.select { |node| node.type == :symbol }.map(&:value)
        assert_includes names, :"Marshalsea::Marshal::ParserTest::Fixture"
      end

      def test_class_name_slot_gadget_is_reachable_in_every_slot
        blind = AdversarialCorpus::CLASS_NAME_SLOTS.reject { |_slot, bytes| tripwires(bytes).any? }

        assert_empty blind.keys,
                     "class-name node discarded, hiding a sink, in: #{blind.keys.join(', ')}"
      end

      def test_class_name_slot_gadget_is_counted_once_per_slot
        duplicated = AdversarialCorpus::CLASS_NAME_SLOTS.select { |_slot, bytes| tripwires(bytes).length > 1 }

        assert_empty duplicated.keys, "a node must be traversed exactly once"
      end

      def test_distinct_instance_variable_names_reach_the_sink
        assert_equal 1, tripwires(AdversarialCorpus::IVAR_DISTINCT_NAMES_CONTROL).length,
                     "control failed, so the collision tests below would prove nothing"
      end

      def test_duplicate_instance_variable_names_do_not_delete_a_sink
        blind = AdversarialCorpus::IVAR_COLLISION_SHAPES.reject { |_shape, bytes| tripwires(bytes).any? }

        assert_empty blind.keys,
                     "duplicate ivar name deleted a subtree in: #{blind.keys.join(', ')}"
      end

      def test_duplicate_instance_variable_names_retain_both_values
        AdversarialCorpus::IVAR_COLLISION_SHAPES.each do |shape, bytes|
          nils = parse(bytes).nodes.count { |node| node.type == :nil }
          assert_equal 2, nils, "#{shape} lost an instance variable value node"
        end
      end

      def test_rejects_depth_beyond_limit
        deep = "\x04\x08" + ("[\x06" * (Constants::DEFAULT_MAX_DEPTH + 5)) + "0"
        assert_raises(DepthLimitError) { parse(deep) }
      end

      def test_parser_defaults_to_bounded_limits_not_permissive
        blob = AdversarialCorpus.stream(AdversarialCorpus.sym("A" * AdversarialCorpus::LONG_NAME_BYTES))

        assert_raises(LimitExceededError, "a bare Parser.new must not be unbounded") do
          Parser.new(blob).parse
        end
        assert_equal :symbol, Parser.new(blob, limits: Limits.permissive).parse.root.type,
                     "control: permissive must admit it, or a ceiling is not what rejected it"
      end

      def test_permissive_lifts_every_ceiling_except_the_stack_safety_one
        lifted = Limits.permissive
        axes = %i[max_bytes max_nodes max_registered_objects max_symbol_definitions
                  max_collection_entries max_scalar_bytes max_total_scalar_bytes
                  max_object_links max_symbol_references max_symbol_name_bytes
                  max_class_name_bytes max_instance_variables max_struct_members]

        bounded = axes.reject { |axis| lifted.public_send(axis) == Limits::UNBOUNDED }
        assert_empty bounded, "permissive must lift these, one assertion per axis"

        assert_equal Limits::STACK_SAFE_MAX_DEPTH, lifted.max_depth,
                     "depth stays bounded on purpose: the parser recurses, so lifting it would " \
                     "trade a rescuable DepthLimitError for an uncatchable SystemStackError"
        assert_raises(DepthLimitError) do
          Parser.new(AdversarialCorpus.stream(
                       AdversarialCorpus.array_nest(Limits::STACK_SAFE_MAX_DEPTH + 5) + "0"
                     ), limits: lifted).parse
        end
      end

      def test_default_depth_ceiling_is_the_limits_value_not_the_permissive_one
        deep = AdversarialCorpus.stream(AdversarialCorpus.array_nest(Limits::DEFAULT_MAX_DEPTH + 5) + "0")

        assert_raises(DepthLimitError) { Parser.new(deep).parse }
        assert_operator Limits::DEFAULT_MAX_DEPTH, :<, Constants::DEFAULT_MAX_DEPTH,
                        "control: the two depth constants must differ, or this test cannot discriminate"
      end

      def test_honours_custom_depth_limit
        blob = ::Marshal.dump([[[1]]])
        assert_raises(DepthLimitError) { Parser.new(blob, max_depth: 2).parse }
      end

      def test_instance_variable_wrapper_counts_toward_the_depth_limit
        chain = AdversarialCorpus.stream(
          AdversarialCorpus.ivar_chain(Constants::DEFAULT_MAX_DEPTH + 5)
        )
        assert_raises(DepthLimitError) { parse(chain) }
      end

      def test_deep_instance_variable_chain_rejects_before_the_ruby_stack_runs_out
        chain = AdversarialCorpus.stream(
          AdversarialCorpus.ivar_chain(AdversarialCorpus::IVAR_CHAIN_DEPTH)
        )
        assert_raises(DepthLimitError) { parse(chain) }
      end

      def parse_class_name_slot_at_ceiling(tail)
        depth = AdversarialCorpus::USERDEF_NEST_DEPTH
        blob = AdversarialCorpus.stream(AdversarialCorpus.array_nest(depth) + tail)
        Parser.new(blob, max_depth: depth + 1).parse
      end

      def test_object_class_name_slot_is_charged_the_enclosing_depth
        tail = "o#{AdversarialCorpus.sym(AdversarialCorpus::OBJECT_CLASS)}#{AdversarialCorpus.fixnum(0)}"
        assert_raises(DepthLimitError, "control failed, so the userdef test proves nothing") do
          parse_class_name_slot_at_ceiling(tail)
        end
      end

      def test_userdef_class_name_slot_does_not_reset_the_depth_budget
        tail = "u#{AdversarialCorpus.sym(AdversarialCorpus::OBJECT_CLASS)}#{AdversarialCorpus.fixnum(1)}x"
        assert_raises(DepthLimitError) { parse_class_name_slot_at_ceiling(tail) }
      end

      def load_watcher(&)
        fired = false
        tracer = TracePoint.new(:call, :c_call) do |tp|
          fired = true if tp.method_id == :load && tp.self.equal?(::Marshal)
        end
        tracer.enable(&)
        fired
      end

      def test_load_watcher_oracle_is_live
        assert load_watcher { ::Marshal.load(::Marshal.dump([1, 2])) },
               "oracle failed to observe a real Marshal.load, so the next test would pass vacuously"
      end

      def test_never_calls_marshal_load
        blob = ::Marshal.dump(UserMarshalFixture.new)
        refute load_watcher { parse(blob) }, "parser invoked Marshal.load"
      end

      def test_never_calls_marshal_load_on_gadget_shaped_payload
        blob = ::Marshal.dump(Gem::Requirement.new(">= 0"))
        refute load_watcher { parse(blob) }, "parser invoked Marshal.load"
      end

      FIRED = []

      module RecordsHash
        def hash
          FIRED << self.class.to_s
          super
        end
      end

      class PlainKey
        include RecordsHash
      end

      class StringKey < String
        include RecordsHash
      end

      class ArrayKey < Array
        include RecordsHash
      end

      StructKey = Struct.new(:a) { include RecordsHash }

      def dispatch_probes
        {
          "plain object (o)" => PlainKey.new,
          "struct (S)" => StructKey.new(1),
          "Array subclass (C)" => ArrayKey.new,
          "String subclass (C)" => StringKey.new("x"),
          "extended object (e)" => PlainKey.new.extend(RecordsHash),
          "extended string (e)" => (+"x").extend(RecordsHash),
          "plain string" => "x",
          "symbol" => :x,
          "integer" => 7,
          "regexp" => /ab/
        }
      end

      def ruby_dispatches?(key)
        FIRED.clear
        ::Marshal.load(::Marshal.dump({ key => nil }))
        !FIRED.empty?
      end

      def parser_predicts_dispatch?(key)
        parse(::Marshal.dump({ key => nil })).hash_dispatching_keys.any?
      end

      def test_hash_key_dispatch_prediction_matches_real_ruby
        observed = dispatch_probes.to_h { |label, key| [label, ruby_dispatches?(key)] }

        assert_includes observed.values, true, "no probe dispatched, so the oracle is dead"
        assert_includes observed.values, false, "every probe dispatched, so the oracle proves nothing"

        mismatches = dispatch_probes.filter_map do |label, key|
          predicted = parser_predicts_dispatch?(key)
          next if predicted == observed.fetch(label)

          "#{label}: ruby=#{observed.fetch(label)} parser=#{predicted}"
        end

        assert_empty mismatches, "parser disagrees with Marshal.load:\n  #{mismatches.join("\n  ")}"
      end

      DISPATCHED = []

      module RecordsBoth
        def hash
          DISPATCHED << :hash
          0
        end

        def eql?(_other)
          DISPATCHED << :eql?
          false
        end
      end

      class BothPlainKey
        include RecordsBoth
      end

      class BothStringKey < String
        include RecordsBoth
      end

      class BothArrayKey < Array
        include RecordsBoth
      end

      def collision_probes
        {
          "plain object (o)" => [BothPlainKey.new, BothPlainKey.new],
          "String subclass (C)" => [BothStringKey.new("x"), BothStringKey.new("x")],
          "Array subclass (C)" => [BothArrayKey.new([1]), BothArrayKey.new([1])],
          "extended string (e)" => [(+"x").extend(RecordsBoth), (+"x").extend(RecordsBoth)],
          "bare array holding a gadget" => [[BothPlainKey.new], [BothPlainKey.new]],
          "bare array of primitives" => [[1, 2], [1, 2]],
          "plain string" => [+"x", +"x"]
        }
      end

      def collision_blob(pair)
        ::Marshal.dump({ pair.first => 1, pair.last => 2 })
      end

      def ruby_dispatches_during_load(pair)
        blob = collision_blob(pair)
        DISPATCHED.clear
        ::Marshal.load(blob)
        DISPATCHED.uniq.sort
      end

      def parser_predicts_during_load(pair)
        result = parse(collision_blob(pair))
        predicted = []
        predicted << :hash if result.hash_dispatching_keys.any?
        predicted << :eql? if result.eql_dispatching_keys.any?
        predicted.sort
      end

      def test_key_dispatch_prediction_matches_real_ruby_for_hash_and_eql
        observed = collision_probes.to_h { |label, pair| [label, ruby_dispatches_during_load(pair)] }
        seen = observed.values.flatten.uniq

        assert_includes seen, :hash, "no probe dispatched #hash, so the oracle is dead"
        assert_includes seen, :eql?, "no probe dispatched #eql?, so a one-key oracle would pass vacuously"
        assert_includes observed.values, [], "every probe dispatched, so the oracle proves nothing"

        mismatches = collision_probes.filter_map do |label, pair|
          predicted = parser_predicts_during_load(pair)
          next if predicted == observed.fetch(label)

          "#{label}: ruby=#{observed.fetch(label).inspect} parser=#{predicted.inspect}"
        end

        assert_empty mismatches,
                     "the detector names both methods in its reject reason, so it must model " \
                     "both:\n  #{mismatches.join("\n  ")}"
      end

      def test_a_string_subclass_key_skips_hash_and_still_reaches_eql
        observed = ruby_dispatches_during_load(collision_probes.fetch("String subclass (C)"))

        assert_equal %i[eql?], observed,
                     "rb_any_hash fast-paths T_STRING so #hash is skipped, but rb_any_cmp " \
                     "requires klass == rb_cString so #eql? is not"
      end

      def test_a_collection_key_is_inspected_through_its_members
        gadget = parse(collision_blob(collision_probes.fetch("bare array holding a gadget")))
        inert = parse(collision_blob(collision_probes.fetch("bare array of primitives")))

        refute_empty gadget.hash_dispatching_keys,
                     "an array key hashes every element, so a gadget inside one dispatches"
        assert_empty inert.hash_dispatching_keys,
                     "control: an array of primitives names no class, so flagging it would be " \
                     "a false positive and the rule would be a blanket reject"
      end

      def test_a_collection_key_reports_the_member_that_dispatches_not_the_container
        result = parse(collision_blob(collision_probes.fetch("bare array holding a gadget")))
        named = result.hash_dispatching_keys.first.effective_class_name

        assert_equal "Marshalsea::Marshal::ParserTest::BothPlainKey", named,
                     "an operator needs the class that runs, not the anonymous array holding it"
      end

      class CmpEndpoint
        def <=>(_other)
          DISPATCHED << :cmp
          0
        end
      end

      def test_range_endpoints_dispatch_and_are_reported
        blob = ::Marshal.dump(CmpEndpoint.new..CmpEndpoint.new)
        DISPATCHED.clear
        ::Marshal.load(blob)

        assert_includes DISPATCHED, :cmp,
                        "Range#marshal_load validates its endpoints, so <=> runs during load"
        assert_empty parse(blob).sinks,
                     "control: Range carries no sink tag on this Ruby, so the sink rule cannot " \
                     "be what catches this"
        assert_equal ["Marshalsea::Marshal::ParserTest::CmpEndpoint"],
                     parse(blob).range_endpoint_dispatchers.map(&:effective_class_name).uniq
        assert_equal 2, parse(blob).range_endpoint_dispatchers.length,
                     "range_init compares both endpoints, so both are reported"
      end

      def test_a_range_of_primitives_is_not_reported
        assert_empty parse(::Marshal.dump(1..5)).range_endpoint_dispatchers,
                     "control: primitive endpoints dispatch only builtin <=>"
      end

      def test_the_same_class_is_only_flagged_in_key_position
        in_key = parse(AdversarialCorpus::HASH_KEY_SHAPES_THAT_DISPATCH[:object])
        in_value = parse(AdversarialCorpus::OBJECT_IN_VALUE_POSITION)

        assert_equal 1, in_key.dispatching_hash_keys.length
        assert_empty in_value.dispatching_hash_keys,
                     "position is the whole signal, so a value-position object must not be flagged"
      end

      def test_every_dispatching_key_shape_is_detected
        blind = AdversarialCorpus::HASH_KEY_SHAPES_THAT_DISPATCH.reject do |_shape, bytes|
          parse(bytes).dispatching_hash_keys.any?
        end

        assert_empty blind.keys, "key-position dispatch missed in: #{blind.keys.join(', ')}"
      end

      def test_non_dispatching_key_shapes_are_not_flagged
        noisy = AdversarialCorpus::HASH_KEY_SHAPES_THAT_DO_NOT_DISPATCH.select do |_shape, bytes|
          parse(bytes).dispatching_hash_keys.any?
        end

        assert_empty noisy.keys, "false positive on: #{noisy.keys.join(', ')}"
      end

      def test_string_backed_key_shapes_are_flagged_on_eql_and_never_on_hash
        shapes = AdversarialCorpus::HASH_KEY_SHAPES_THAT_DISPATCH_EQL_ONLY

        wrong_method = shapes.select { |_shape, bytes| parse(bytes).hash_dispatching_keys.any? }
        assert_empty wrong_method.keys,
                     "rb_any_hash never reaches a user #hash for T_STRING, so claiming it does " \
                     "would make the reject reason a false statement: #{wrong_method.keys.join(', ')}"

        missed = shapes.reject { |_shape, bytes| parse(bytes).eql_dispatching_keys.any? }
        assert_empty missed.keys, "#eql? dispatch missed in: #{missed.keys.join(', ')}"
      end

      def test_every_dispatching_key_shape_is_caught_by_the_hash_rule
        blind = AdversarialCorpus::HASH_KEY_SHAPES_THAT_DISPATCH.reject do |_shape, bytes|
          parse(bytes).hash_dispatching_keys.any?
        end

        assert_empty blind.keys, "#hash dispatch missed in: #{blind.keys.join(', ')}"
      end

      def test_struct_member_name_slot_is_not_scanned_as_a_hash_key
        blob = AdversarialCorpus.stream(
          "S#{AdversarialCorpus.sym(AdversarialCorpus::OBJECT_CLASS)}" \
          "#{AdversarialCorpus.fixnum(1)}#{AdversarialCorpus::PLAIN_OBJECT}0"
        )

        assert_equal 1, parse(blob).nodes.count { |node| node.type == :pair },
                     "control: the fixture must actually contain a struct pair"
        assert_empty parse(blob).dispatching_hash_keys,
                     "read_pair is shared with read_struct, so struct pairs must not be scanned"
      end

      class Fixture
        @instantiated = false

        class << self
          attr_accessor :instantiated
        end

        def initialize
          @marker = "value"
        end
      end

      def nested_result
        parse(::Marshal.dump({ "user" => "guest", "roles" => [1, 2, 3], "on" => true }))
      end

      def test_a_returned_parse_graph_cannot_be_mutated_by_its_consumer
        result = nested_result
        node = result.root

        assert_raises(FrozenError) { node.children << Node.new(type: :nil) }
        assert_raises(FrozenError) { node.auxiliary.clear }
        assert_raises(FrozenError) { node.instance_variables_map[:injected] = Node.new(type: :nil) }
      end

      def test_a_returned_node_cannot_have_its_verdict_fields_rewritten
        node = nested_result.root

        assert_raises(FrozenError) { node.value = "rewritten" }
        assert_raises(FrozenError) { node.class_name = "Innocuous" }
      end

      def test_every_node_in_the_graph_is_frozen_not_just_the_root
        unfrozen = nested_result.nodes.reject(&:frozen?)

        assert_empty unfrozen.map(&:type)
        assert_operator nested_result.nodes.count, :>, 5,
                        "control: a one-node graph would not prove the walk reaches children"
      end

      def test_scalar_values_in_the_graph_are_frozen_too
        strings = nested_result.nodes.filter_map { |n| n.value if n.value.is_a?(String) }

        refute_empty strings, "control: the probe must contain string values"
        assert(strings.all?(&:frozen?))
      end

      def test_the_chain_registry_cannot_be_appended_to_by_a_caller
        assert_raises(FrozenError) { Marshalsea::Chains.registry << Object }
      end

      def test_control_the_registry_still_reports_its_chains
        refute_empty Marshalsea::Chains.all
        assert_includes Marshalsea::Chains.all, Marshalsea::Chains::ErbDefMethod
      end

      FIXNUM_WIDTH_PROBES = [
        0, 1, -1, 122, -123, 123, -124, 255, -256, 256, -257, 65_535, -65_536,
        65_536, 16_777_215, -16_777_216, 16_777_216, 1_073_741_823, -1_073_741_824
      ].freeze

      def test_fixnum_round_trips_every_width_the_format_allows
        mismatched = FIXNUM_WIDTH_PROBES.reject { |n| parse(::Marshal.dump(n)).root.value == n }

        assert_empty mismatched.map(&:inspect)
      end

      def test_no_fixnum_marker_can_request_a_width_beyond_the_format_ceiling
        payloads = FIXNUM_WIDTH_PROBES.map { |n| ::Marshal.dump(n).bytesize - Constants::HEADER_LENGTH - 2 }

        assert_equal (0..Constants::FIXNUM_MAX_WIDTH).to_a, payloads.uniq.sort,
                     "control: the probe set must exercise the inline form and every width"
        assert_operator payloads.max, :<=, Constants::FIXNUM_MAX_WIDTH,
                        "the format cannot express a wider fixnum, so a runtime width guard " \
                        "is unreachable and must not pretend otherwise"
      end

      def float_stream(body)
        AdversarialCorpus.stream("f#{AdversarialCorpus.fixnum(body.bytesize)}#{body}")
      end

      def float_value(body)
        parse(float_stream(body)).root.value
      end

      def marshal_float(body)
        ::Marshal.load(float_stream(body))
      end

      def same_float?(left, right)
        return false unless left.is_a?(Float) && right.is_a?(Float)

        (left.nan? && right.nan?) || left == right
      end

      EMITTED_FLOAT_BODIES = [
        "inf", "-inf", "nan", "0", "-0", "1.5", "-2.5", "1e400", "-1e400",
        "0.0001", "3.141592653589793", "1.7976931348623157e+308", "5.0e-324"
      ].freeze

      HAND_BUILT_FLOAT_BODIES = [
        "1_0", "abc", "", " 1.5", "0x10", "1.5abc", "+2.5", ".5",
        "nan\x00j", "inf\x00x", "INF", "NaN"
      ].freeze

      def test_float_decoding_agrees_with_marshal_load_on_every_body
        bodies = EMITTED_FLOAT_BODIES + HAND_BUILT_FLOAT_BODIES
        disagreements = bodies.reject { |b| same_float?(float_value(b), marshal_float(b)) }

        assert_empty(disagreements.map { |b| "#{b.inspect}: #{float_value(b).inspect} vs #{marshal_float(b).inspect}" })

        observed = bodies.map { |b| marshal_float(b) }
        assert(observed.any?(&:nan?), "control: the table must exercise nan")
        assert(observed.any?(&:infinite?), "control: the table must exercise infinity")
        assert(observed.any?(&:finite?), "control: the table must exercise finite values")
      end

      def test_float_never_reports_nil_for_a_body_marshal_load_accepts
        blind = (EMITTED_FLOAT_BODIES + HAND_BUILT_FLOAT_BODIES).select { |b| float_value(b).nil? }

        assert_empty blind,
                     "a nil value is indistinguishable from a float of zero and hides what the " \
                     "stream actually carried"
      end

      def test_every_float_ruby_dumps_round_trips_through_the_parser
        values = [0.0, -0.0, 1.5, -2.5, 1e308, 1e-308, 0.1, Float::INFINITY,
                  -Float::INFINITY, Float::NAN, Float::MAX, Float::MIN]
        mismatched = values.reject do |v|
          same_float?(parse(::Marshal.dump(v)).root.value, v)
        end

        assert_empty mismatched.map(&:inspect)
      end

      def test_a_legacy_mantissa_tail_is_preserved_rather_than_guessed
        node = parse(float_stream("3.5\x00junk")).root

        assert_in_delta 3.5, node.value, 0.0
        assert_equal "\x00junk".b, node.undecoded_tail
        refute_predicate node, :fully_decoded?
      end

      def test_control_a_float_ruby_actually_emits_is_fully_decoded
        node = parse(::Marshal.dump(3.5)).root

        assert_predicate node, :fully_decoded?
        assert_nil node.undecoded_tail
      end

      def test_the_parser_and_the_scanner_agree_on_which_sinks_are_gated
        from_tags = Constants::GATED_SINK_TAGS.map { |tag| Constants::SINK_METHODS.fetch(tag) }
        from_scanner = Marshalsea::Scanner::GATED_METHODS + Marshalsea::Scanner::GATED_SINGLETON_METHODS

        refute_empty from_tags, "control: an empty gated set would make this vacuous"
        assert_equal from_scanner.sort, from_tags.sort,
                     "a sink method gated in one half and ungated in the other is a contradiction, " \
                     "and the two halves are the only two definitions of gated in this project"
      end

      def test_every_sink_tag_declares_the_method_marshal_load_dispatches
        assert_equal Constants::SINK_TAGS.sort, Constants::SINK_METHODS.keys.sort
      end

      def test_data_tag_is_gated_because_marshal_load_checks_respond_to_first
        assert_includes Constants::GATED_SINK_TAGS, Constants::TAG_DATA,
                        "Thread::Mutex is a real T_DATA with no _load_data and Marshal.load raises " \
                        "TypeError naming the missing method, which is the gate"
      end

      class UserMarshalFixture
        def marshal_dump
          ["payload"]
        end

        def marshal_load(data); end
      end

      class UserDefFixture
        def _dump(_depth)
          "opaque"
        end

        def self._load(_data)
          new
        end
      end
    end
  end
end
