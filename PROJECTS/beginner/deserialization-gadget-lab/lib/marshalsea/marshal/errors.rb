# ©AngelaMos | 2026
# errors.rb
# frozen_string_literal: true

module Marshalsea
  module Marshal
    class StreamError < StandardError; end

    class TruncatedStreamError < StreamError; end

    class UnsupportedVersionError < StreamError; end

    class UnknownTagError < StreamError; end

    class TrailingBytesError < StreamError; end

    class InvalidLinkError < StreamError; end

    class DepthLimitError < StreamError; end

    class MalformedCountError < StreamError; end

    class MalformedValueError < StreamError; end

    class LimitExceededError < StreamError; end

    class InputTypeError < StreamError; end
  end
end
