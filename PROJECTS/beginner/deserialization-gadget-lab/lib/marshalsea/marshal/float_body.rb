# ©AngelaMos | 2026
# float_body.rb
# frozen_string_literal: true

module Marshalsea
  module Marshal
    module FloatBody
      module_function

      def decode(body)
        text = body.b
        named = named_value(text)
        return [named, nil] if named

        token = prefix(text)
        tail = text.byteslice(token.bytesize..)
        [value_of(token), tail.empty? ? nil : tail]
      end

      def named_value(text)
        case text.byteslice(0, text.index(Constants::NUL_BYTE) || text.bytesize)
        when Constants::FLOAT_NAN then Float::NAN
        when Constants::FLOAT_INFINITY then Float::INFINITY
        when Constants::FLOAT_NEGATIVE_INFINITY then -Float::INFINITY
        end
      end

      def prefix(text)
        match = Constants::FLOAT_HEX_PREFIX.match(text) ||
                Constants::FLOAT_DECIMAL_PREFIX.match(text)
        match ? match[0] : ""
      end

      def value_of(token)
        stripped = token.strip
        stripped.empty? ? 0.0 : Float(stripped)
      end
    end
  end
end
