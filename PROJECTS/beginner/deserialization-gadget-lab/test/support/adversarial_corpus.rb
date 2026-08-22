# ©AngelaMos | 2026
# adversarial_corpus.rb
# frozen_string_literal: true

module Marshalsea
  module AdversarialCorpus
    HEADER = "\x04\x08"
    INLINE_OFFSET = 5
    INLINE_CEILING = 122
    INLINE_FLOOR = -123
    BYTE_MODULUS = 256

    VERDICT_ACCEPT = :accept
    VERDICT_REJECT = :reject

    module_function

    def fixnum(value)
      return "\x00".b if value.zero?
      return (value + INLINE_OFFSET).chr if value.positive? && value <= INLINE_CEILING
      return (value - INLINE_OFFSET + BYTE_MODULUS).chr if value.negative? && value >= INLINE_FLOOR

      wide(value)
    end

    def wide(value)
      width = 1
      width += 1 while value >= (1 << (8 * width)) || value < -(1 << (8 * width))
      stored = value.negative? ? value + (1 << (8 * width)) : value
      bytes = (0...width).map { |index| (stored >> (8 * index)) & 0xFF }
      marker = value.negative? ? BYTE_MODULUS - width : width
      (marker.chr + bytes.map(&:chr).join).b
    end

    def sym(name)
      ":#{fixnum(name.bytesize)}#{name}".b
    end

    def symlink(index)
      ";#{fixnum(index)}".b
    end

    def str(text)
      "\"#{fixnum(text.bytesize)}#{text}".b
    end

    def stream(body)
      "#{HEADER}#{body}".b
    end

    def entry(name, bytes, verdict, rationale, allowed: [])
      { name: name, bytes: bytes.b, verdict: verdict, rationale: rationale,
        allowed: allowed.freeze }.freeze
    end

    def ivar_chain(depth)
      (("I" * depth) + "0" + ("\x00" * depth)).b
    end

    def array_nest(depth)
      ("[#{fixnum(1)}" * depth).b
    end

    def regexp(source)
      "/#{fixnum(source.bytesize)}#{source}\x00".b
    end

    def bignum(sign, word_count, fill = "\x01")
      "l#{sign}#{fixnum(word_count)}#{fill * (word_count * BIGNUM_WORD_BYTES)}".b
    end

    def symlink_run(count)
      (sym("s") + (symlink(0) * count)).b
    end

    def symlink_groups(groups, per_group)
      inner = "[#{fixnum(per_group)}#{symlink(0) * per_group}"
      "[#{fixnum(groups + 1)}#{sym('s')}#{inner * groups}".b
    end

    def ivar_run(count)
      "#{fixnum(count)}#{sym('@a')}0#{"#{symlink(1)}0" * (count - 1)}".b
    end

    NESTED_DEPTH = 80
    WIDE_COUNT = 4_096
    MANY_SYMBOLS = 400
    HUGE_SCALAR = 300_000
    IVAR_CHAIN_DEPTH = 6_000
    USERDEF_NEST_DEPTH = 3
    BIGNUM_WORD_BYTES = 2
    BIGNUM_HUGE_WORDS = 200_000
    LONG_NAME_BYTES = 100_000
    BULK_ENTRY_COUNT = 1_000
    MODEST_NAME_BYTES = 64
    MODEST_ENTRY_COUNT = 16
    SYMLINK_BULK_GROUPS = 3
    SYMLINK_BULK_PER_GROUP = 1_000
    BIGNUM_SIGNS = ["-", "+", "!", "\x00", "\xFF", "0"].freeze

    TRIPWIRE_CLASS = "Tripwire"
    HOST_CLASS = "Comparable"
    OBJECT_CLASS = "Foo"
    COLLIDING_IVAR = "@a"
    HIDDEN_IVAR = "@z"

    TRIPWIRE = "U#{sym(TRIPWIRE_CLASS)}0".b

    CLASS_NAME_GADGET = "I#{sym(HOST_CLASS)}#{fixnum(1)}#{sym(HIDDEN_IVAR)}#{TRIPWIRE}".b

    CLASS_NAME_SLOTS = {
      object: stream("o#{CLASS_NAME_GADGET}#{fixnum(0)}"),
      struct: stream("S#{CLASS_NAME_GADGET}#{fixnum(0)}"),
      userdef: stream("u#{CLASS_NAME_GADGET}#{fixnum(1)}x"),
      usermarshal: stream("U#{CLASS_NAME_GADGET}0"),
      data: stream("d#{CLASS_NAME_GADGET}0"),
      user_class: stream("C#{CLASS_NAME_GADGET}#{str('body')}"),
      extended: stream("e#{CLASS_NAME_GADGET}#{str('body')}")
    }.freeze

    CLASS_NAME_SLOTS_WITH_NON_SINK_HOST = %i[object struct user_class extended].freeze

    IVAR_COLLISION_SHAPES = {
      wrapper_symlink_name:
        stream("I#{str('hello')}#{fixnum(2)}#{sym(COLLIDING_IVAR)}#{TRIPWIRE}#{symlink(0)}0"),
      wrapper_redefined_name:
        stream("I#{str('hello')}#{fixnum(2)}#{sym(COLLIDING_IVAR)}#{TRIPWIRE}#{sym(COLLIDING_IVAR)}0"),
      object_symlink_name:
        stream("o#{sym(OBJECT_CLASS)}#{fixnum(2)}#{sym(COLLIDING_IVAR)}#{TRIPWIRE}#{symlink(1)}0"),
      object_redefined_name:
        stream("o#{sym(OBJECT_CLASS)}#{fixnum(2)}#{sym(COLLIDING_IVAR)}#{TRIPWIRE}#{sym(COLLIDING_IVAR)}0")
    }.freeze

    IVAR_COLLISION_SHAPES_INSIDE_OBJECT = %i[object_symlink_name object_redefined_name].freeze

    IVAR_DISTINCT_NAMES_CONTROL =
      stream("I#{str('hello')}#{fixnum(2)}#{sym(COLLIDING_IVAR)}#{TRIPWIRE}#{sym(HIDDEN_IVAR)}0")

    PLAIN_OBJECT = "o#{sym(OBJECT_CLASS)}#{fixnum(0)}".b

    HASH_KEY_SHAPES_THAT_DISPATCH = {
      object: stream("{#{fixnum(1)}#{PLAIN_OBJECT}0"),
      object_link: stream("[#{fixnum(2)}#{PLAIN_OBJECT}{#{fixnum(1)}@#{fixnum(1)}0"),
      struct: stream("{#{fixnum(1)}S#{sym(OBJECT_CLASS)}#{fixnum(0)}0"),
      extended: stream("{#{fixnum(1)}e#{sym(HOST_CLASS)}#{PLAIN_OBJECT}0"),
      user_class_over_array: stream("{#{fixnum(1)}C#{sym(OBJECT_CLASS)}[#{fixnum(0)}0"),
      bare_array: stream("{#{fixnum(1)}[#{fixnum(1)}#{PLAIN_OBJECT}0"),
      nested_bare_array: stream("{#{fixnum(1)}[#{fixnum(1)}[#{fixnum(1)}#{PLAIN_OBJECT}0")
    }.freeze

    HASH_KEY_SHAPES_THAT_DISPATCH_EQL_ONLY = {
      user_class_over_string: stream("{#{fixnum(1)}C#{sym(OBJECT_CLASS)}#{str('x')}0"),
      extended_over_string: stream("{#{fixnum(1)}e#{sym(HOST_CLASS)}#{str('x')}0")
    }.freeze

    HASH_KEY_SHAPES_THAT_DO_NOT_DISPATCH = {
      regexp: stream("{#{fixnum(1)}#{regexp('ab')}0"),
      symbol: stream("{#{fixnum(1)}#{sym('k')}0"),
      string: stream("{#{fixnum(1)}#{str('k')}0"),
      array_of_primitives: stream("{#{fixnum(1)}[#{fixnum(2)}i\x06i\x070"),
      empty_array: stream("{#{fixnum(1)}[#{fixnum(0)}0")
    }.freeze

    RANGE_CLASS = "Range"

    def range_stream(endpoint)
      stream(
        "o#{sym(RANGE_CLASS)}#{fixnum(3)}" \
        "#{sym('excl')}F#{sym('begin')}#{endpoint}#{sym('end')}#{endpoint}"
      )
    end

    RANGE_WITH_OBJECT_ENDPOINTS = range_stream(PLAIN_OBJECT)
    RANGE_WITH_PRIMITIVE_ENDPOINTS = range_stream("i\x06".b)

    OBJECT_IN_VALUE_POSITION =
      stream("{#{fixnum(1)}#{sym('k')}#{PLAIN_OBJECT}")

    CASES = [
      entry(:nil_literal, stream("0"), VERDICT_ACCEPT,
            "the smallest legal stream"),
      entry(:boolean_true, stream("T"), VERDICT_ACCEPT,
            "primitive tag carrying no class reference"),
      entry(:fixnum_zero, stream("i\x00"), VERDICT_ACCEPT,
            "zero uses the dedicated single-byte encoding"),
      entry(:fixnum_inline_max, stream("i#{fixnum(122)}"), VERDICT_ACCEPT,
            "largest value expressible without a width prefix"),
      entry(:fixnum_wide_positive, stream("i#{fixnum(65_536)}"), VERDICT_ACCEPT,
            "three-byte little-endian encoding"),
      entry(:fixnum_wide_negative, stream("i#{fixnum(-65_536)}"), VERDICT_ACCEPT,
            "negative widths sign-extend rather than being malformed"),
      entry(:bare_symbol, stream(sym("marshal_load")), VERDICT_ACCEPT,
            "a symbol naming a sink is not itself a sink"),
      entry(:empty_array, stream("[\x00"), VERDICT_ACCEPT,
            "zero-length collection"),
      entry(:nested_arrays, stream("[\x06[\x06[\x060"), VERDICT_ACCEPT,
            "ordinary nesting well inside the depth ceiling"),
      entry(:empty_hash, stream("{\x00"), VERDICT_ACCEPT,
            "zero-entry hash"),
      entry(:shared_reference, stream("[\x07#{str('shared')}@\x06"), VERDICT_ACCEPT,
            "a legitimate object link to a previously registered string"),
      entry(:self_referential_array, stream("[\x06@\x00"), VERDICT_ACCEPT,
            "zero-indexed cycle, the shape Ruby itself emits"),
      entry(:symlink_reuse, stream("[\x07#{sym('same')};\x00"), VERDICT_ACCEPT,
            "second occurrence of a symbol is a symlink"),

      entry(:empty_stream, "", VERDICT_REJECT,
            "no header at all"),
      entry(:header_only, HEADER, VERDICT_REJECT,
            "header with no value follows"),
      entry(:wrong_major_version, "\x05\x080", VERDICT_REJECT,
            "major version has never been anything but 4"),
      entry(:future_minor_version, "\x04\x090", VERDICT_REJECT,
            "a minor above 8 is a format this parser has not seen"),
      entry(:unknown_tag, stream("\x00"), VERDICT_REJECT,
            "byte zero is not a type tag"),
      entry(:trailing_bytes, stream("0junk"), VERDICT_REJECT,
            "unread bytes after the root value indicate a smuggled second stream"),
      entry(:negative_array_count, stream("[\xFA"), VERDICT_REJECT,
            "a negative count silently yields an empty collection instead of failing"),
      entry(:negative_hash_count, stream("{\xFA"), VERDICT_REJECT,
            "same confusion in hash position"),
      entry(:negative_ivar_count, stream("I#{str('a')}\xFA"), VERDICT_REJECT,
            "negative instance variable count"),
      entry(:negative_struct_count, stream("S#{sym('A')}\xFA"), VERDICT_REJECT,
            "negative struct member count"),
      entry(:negative_bignum_words, stream("l+\xFA"), VERDICT_REJECT,
            "negative word count previously leaked a raw NoMethodError"),
      entry(:negative_string_length, stream("\"\xFA"), VERDICT_REJECT,
            "a negative length rewinds the cursor, which is a loop primitive"),
      entry(:out_of_range_object_link, stream("[\x06@\x63"), VERDICT_REJECT,
            "link index beyond the object table"),
      entry(:negative_object_link, stream("[\x06@\xFA"), VERDICT_REJECT,
            "negative index would count backwards from the end of the table"),
      entry(:negative_symlink, stream("[\x07#{sym('a')};\xFA"), VERDICT_REJECT,
            "negative symbol index"),
      entry(:truncated_string_body, stream("\"\x0aab"), VERDICT_REJECT,
            "declared length exceeds the bytes present"),
      entry(:truncated_array_elements, stream("[\x08i\x06"), VERDICT_REJECT,
            "declares three elements and supplies one"),
      entry(:truncated_multibyte_fixnum, stream("i\x03\x01"), VERDICT_REJECT,
            "declares a three-byte integer and supplies one byte"),
      entry(:deep_nesting, stream(("[\x06" * NESTED_DEPTH) + "0"), VERDICT_REJECT,
            "nesting past the boundary depth ceiling"),
      entry(:deep_instance_variable_chain, stream(ivar_chain(IVAR_CHAIN_DEPTH)), VERDICT_REJECT,
            "the I wrapper must charge depth, or a 12 KB cookie exhausts the Ruby stack " \
            "with a SystemStackError that no rescue StreamError can catch"),
      entry(:wide_collection, stream("[#{fixnum(WIDE_COUNT)}#{'0' * WIDE_COUNT}"), VERDICT_REJECT,
            "one collection consuming the whole node budget"),
      entry(:many_symbols, stream("[#{fixnum(MANY_SYMBOLS)}#{(0...MANY_SYMBOLS).map { |i| sym("s#{i}") }.join}"),
            VERDICT_REJECT,
            "attacker-chosen symbol creation past the definition ceiling"),
      entry(:huge_scalar, stream(str("A" * HUGE_SCALAR)), VERDICT_REJECT,
            "single scalar past the per-scalar byte ceiling"),
      entry(:userdef_sink, stream("u#{sym('Evil')}#{fixnum(1)}x"), VERDICT_REJECT,
            "_load runs during deserialization before any allowlist can act"),
      entry(:usermarshal_sink, stream("U#{sym('Evil')}0"), VERDICT_REJECT,
            "marshal_load runs during deserialization"),
      entry(:data_sink, stream("d#{sym('Evil')}0"), VERDICT_REJECT,
            "_load_data runs during deserialization"),
      entry(:sink_in_ivar_name_position, stream("I#{str('a')}\x06u#{sym('Evil')}#{fixnum(1)}x0"),
            VERDICT_REJECT,
            "a sink hidden where a symbol is expected must not disappear from the report"),
      entry(:plain_object_no_sink, stream("o#{sym('ERB')}\x06#{sym('@src')}#{str('payload')}"),
            VERDICT_REJECT,
            "carries no sink tag at all, which is exactly why sink detection is insufficient"),

      entry(:ivar_collision_wrapper_symlink_name,
            IVAR_COLLISION_SHAPES[:wrapper_symlink_name], VERDICT_REJECT,
            "two ivars share a name under I, so a Hash write must not delete the first value node"),
      entry(:ivar_collision_wrapper_redefined_name,
            IVAR_COLLISION_SHAPES[:wrapper_redefined_name], VERDICT_REJECT,
            "the same collision spelled as a second symbol definition rather than a symlink"),
      entry(:ivar_collision_object_symlink_name,
            IVAR_COLLISION_SHAPES[:object_symlink_name], VERDICT_REJECT,
            "the collision inside an object body, where the allowlist would otherwise pass it",
            allowed: [OBJECT_CLASS]),
      entry(:ivar_collision_object_redefined_name,
            IVAR_COLLISION_SHAPES[:object_redefined_name], VERDICT_REJECT,
            "object body collision spelled as a redefinition",
            allowed: [OBJECT_CLASS]),

      entry(:class_name_slot_object, CLASS_NAME_SLOTS[:object], VERDICT_REJECT,
            "control: the one slot that already retains its class-name node catches this gadget",
            allowed: [HOST_CLASS]),
      entry(:class_name_slot_struct, CLASS_NAME_SLOTS[:struct], VERDICT_REJECT,
            "byte-identical gadget in a struct class-name slot",
            allowed: [HOST_CLASS]),
      entry(:class_name_slot_user_class, CLASS_NAME_SLOTS[:user_class], VERDICT_REJECT,
            "byte-identical gadget in a user-class wrapper slot",
            allowed: [HOST_CLASS]),
      entry(:class_name_slot_extended, CLASS_NAME_SLOTS[:extended], VERDICT_REJECT,
            "byte-identical gadget in an extend wrapper slot",
            allowed: [HOST_CLASS]),

      entry(:object_in_value_position_control, OBJECT_IN_VALUE_POSITION, VERDICT_ACCEPT,
            "control: an allowlisted class is fine as a hash VALUE, which is what makes the " \
            "key-position cases below a statement about position rather than about the class",
            allowed: [OBJECT_CLASS]),

      entry(:hash_key_object, HASH_KEY_SHAPES_THAT_DISPATCH[:object], VERDICT_REJECT,
            "an allowlisted class in KEY position runs its #hash during load",
            allowed: [OBJECT_CLASS]),
      entry(:hash_key_object_link, HASH_KEY_SHAPES_THAT_DISPATCH[:object_link], VERDICT_REJECT,
            "the same dispatch reached through an object link instead of a fresh object",
            allowed: [OBJECT_CLASS]),
      entry(:hash_key_struct, HASH_KEY_SHAPES_THAT_DISPATCH[:struct], VERDICT_REJECT,
            "a struct in key position dispatches too",
            allowed: [OBJECT_CLASS]),
      entry(:hash_key_extended, HASH_KEY_SHAPES_THAT_DISPATCH[:extended], VERDICT_REJECT,
            "an extended object in key position dispatches the module's #hash",
            allowed: [OBJECT_CLASS, HOST_CLASS]),
      entry(:hash_key_user_class_over_array, HASH_KEY_SHAPES_THAT_DISPATCH[:user_class_over_array],
            VERDICT_REJECT,
            "an Array subclass in key position dispatches the subclass #hash",
            allowed: [OBJECT_CLASS]),

      entry(:hash_key_bare_array, HASH_KEY_SHAPES_THAT_DISPATCH[:bare_array], VERDICT_REJECT,
            "an array key names no class of its own, but rb_ary_hash hashes every element, " \
            "so the object inside it dispatches. Both key rules cover this shape, so the " \
            "verdict alone cannot isolate either; parser_test asserts the hash rule directly",
            allowed: [OBJECT_CLASS]),
      entry(:hash_key_nested_bare_array, HASH_KEY_SHAPES_THAT_DISPATCH[:nested_bare_array], VERDICT_REJECT,
            "one more level of anonymous nesting must not buy the same object a pass",
            allowed: [OBJECT_CLASS]),

      entry(:hash_key_user_class_over_string, HASH_KEY_SHAPES_THAT_DISPATCH_EQL_ONLY[:user_class_over_string],
            VERDICT_REJECT,
            "rb_any_hash fast-paths T_STRING so #hash is skipped, but rb_any_cmp requires " \
            "klass == rb_cString, so a String subclass reaches a user #eql? on collision",
            allowed: [OBJECT_CLASS]),
      entry(:hash_key_extended_over_string, HASH_KEY_SHAPES_THAT_DISPATCH_EQL_ONLY[:extended_over_string],
            VERDICT_REJECT,
            "same asymmetry when the string is reached through an extend wrapper",
            allowed: [HOST_CLASS]),

      entry(:hash_key_regexp, HASH_KEY_SHAPES_THAT_DO_NOT_DISPATCH[:regexp], VERDICT_ACCEPT,
            "a regexp key names no class, so the payload cannot choose whose #hash runs"),
      entry(:hash_key_array_of_primitives, HASH_KEY_SHAPES_THAT_DO_NOT_DISPATCH[:array_of_primitives],
            VERDICT_ACCEPT,
            "precision control: recursing into collection keys must not become a blanket " \
            "reject on every array"),
      entry(:hash_key_empty_array, HASH_KEY_SHAPES_THAT_DO_NOT_DISPATCH[:empty_array], VERDICT_ACCEPT,
            "precision control: an empty collection has no member to dispatch anything"),

      entry(:range_with_object_endpoints, RANGE_WITH_OBJECT_ENDPOINTS, VERDICT_REJECT,
            "range_loader calls range_init, which compares the endpoints, so <=> runs during " \
            "load on a stream carrying no sink tag and no hash key",
            allowed: [OBJECT_CLASS, RANGE_CLASS]),
      entry(:range_with_primitive_endpoints, RANGE_WITH_PRIMITIVE_ENDPOINTS, VERDICT_ACCEPT,
            "precision control: primitive endpoints reach only the builtin <=>",
            allowed: [RANGE_CLASS])
    ].freeze
  end
end
