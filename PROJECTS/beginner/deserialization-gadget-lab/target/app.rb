# ©AngelaMos | 2026
# app.rb
# frozen_string_literal: true

require "sinatra/base"
require "base64"
require "erb"
require "yaml"
require "marshalsea"

module Marshalsea
  module Target
    COOKIE_NAME = "session_state"
    CANARY_PATH = "/tmp/marshalsea-canary"

    STATUS_OK = 200
    STATUS_BAD_REQUEST = 400

    CONTENT_TYPE = "text/plain"

    PERMITTED_CLASS_NAMES = [].freeze
    BENIGN_TEMPLATE = "hello"

    SESSION_KEYS = %i[user template].freeze

    DETECTOR = Marshalsea::Marshal::BoundaryDetector.new(
      policy: Marshalsea::Marshal::BoundaryDetector::POLICY_STRICT_ALLOWLIST,
      allowed_class_names: PERMITTED_CLASS_NAMES,
      limits: Marshalsea::Marshal::Limits.new
    )

    INSPECTOR = Marshalsea::Psych::Inspector.new(
      permitted_class_names: PERMITTED_CLASS_NAMES,
      limits: Marshalsea::Psych::Limits.new
    )

    YAML_PERMITTED_CLASSES = [Symbol].freeze
    REFUSED_BY_PSYCH = "Psych refused the tag before reviving it: %s"

    REJECTED = "rejected: %s"
    RENDERED = "rendered template for %s"
    NO_SESSION = "no session cookie"
    NOT_A_SESSION = "payload is not a session hash"
    REFUSED_BY_LOADER = "stream passed inspection and Marshal.load still refused it"
    LOADER_REFUSED = Object.new.freeze

    class App < Sinatra::Base
      set :host_authorization, permitted_hosts: []
      set :show_exceptions, false
      set :dump_errors, false

      get "/" do
        content_type CONTENT_TYPE
        [
          "marshalsea target",
          "erb #{Gem::Specification.find_all_by_name('erb').map(&:version).max}",
          "ruby #{RUBY_VERSION}",
          "",
          "POST /session      issue a benign session cookie",
          "GET  /render       deserialize and compile the session template (VULNERABLE)",
          "GET  /render/safe  inspect the stream before deserializing (DEFENDED)",
          "GET  /yaml/unsafe  YAML.unsafe_load the same session (VULNERABLE)",
          "GET  /yaml/safe    inspect, then YAML.safe_load, which vetoes the tag (DEFENDED)",
          "GET  /canary       report whether the canary file exists"
        ].join("\n")
      end

      post "/session" do
        state = { user: "guest", template: BENIGN_TEMPLATE }
        response.set_cookie(COOKIE_NAME, value: encode(state), path: "/")
        content_type CONTENT_TYPE
        "session issued"
      end

      get "/render" do
        content_type CONTENT_TYPE
        blob = decode(request.cookies[COOKIE_NAME])
        halt STATUS_BAD_REQUEST, NO_SESSION unless blob

        state = ::Marshal.load(blob)
        compile(state)
      end

      get "/render/safe" do
        content_type CONTENT_TYPE
        blob = decode(request.cookies[COOKIE_NAME])
        halt STATUS_BAD_REQUEST, NO_SESSION unless blob

        decision = DETECTOR.inspect_stream(blob)
        halt STATUS_BAD_REQUEST, format(REJECTED, decision.reason) unless decision.proceed?

        state = revive(decision.snapshot)
        halt STATUS_BAD_REQUEST, format(REJECTED, REFUSED_BY_LOADER) if state.equal?(LOADER_REFUSED)
        halt STATUS_BAD_REQUEST, format(REJECTED, NOT_A_SESSION) unless session?(state)

        compile(state)
      end

      get "/yaml/unsafe" do
        content_type CONTENT_TYPE
        document = decode(request.cookies[COOKIE_NAME])
        halt STATUS_BAD_REQUEST, NO_SESSION unless document

        compile(::YAML.unsafe_load(document))
      end

      get "/yaml/safe" do
        content_type CONTENT_TYPE
        document = decode(request.cookies[COOKIE_NAME])
        halt STATUS_BAD_REQUEST, NO_SESSION unless document

        decision = INSPECTOR.inspect_document(document)
        halt STATUS_BAD_REQUEST, format(REJECTED, decision.reason) unless decision.proceed?

        compile(safe_load(document))
      end

      get "/canary" do
        content_type CONTENT_TYPE
        File.exist?(CANARY_PATH) ? File.read(CANARY_PATH) : "absent"
      end

      private

      def encode(state)
        Base64.strict_encode64(::Marshal.dump(state))
      end

      def decode(raw)
        return nil unless raw

        Base64.strict_decode64(raw)
      rescue ArgumentError
        nil
      end

      def safe_load(document)
        ::YAML.safe_load(document, permitted_classes: YAML_PERMITTED_CLASSES, aliases: false)
      rescue ::Psych::DisallowedClass, ::Psych::AliasesNotEnabled, ::Psych::SyntaxError => e
        halt STATUS_BAD_REQUEST, format(REJECTED, format(REFUSED_BY_PSYCH, e.class))
      end

      def revive(blob)
        ::Marshal.load(blob)
      rescue ArgumentError, TypeError
        LOADER_REFUSED
      end

      def session?(state)
        state.is_a?(Hash) && SESSION_KEYS.all? { |key| state.key?(key) }
      end

      def compile(state)
        template = state[:template]
        template.def_method(Module.new, "render_it") if template.respond_to?(:def_method)
        format(RENDERED, state[:user])
      end
    end
  end
end
