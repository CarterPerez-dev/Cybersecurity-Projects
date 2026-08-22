# ©AngelaMos | 2026
# target_client.rb
# frozen_string_literal: true

require "net/http"
require "uri"

FIELD_SEPARATOR = "\t"
BODY_SEPARATOR = "\n"
TRANSPORT_FAILURE = "000"
OPEN_TIMEOUT = 5
READ_TIMEOUT = 10

path = ARGV.fetch(0)
cookie = ARGV[1]

uri = URI.parse("#{ENV.fetch('TARGET_BASE')}#{path}")
request = Net::HTTP::Get.new(uri)
request["Cookie"] = cookie if cookie && !cookie.empty?

begin
  response = Net::HTTP.start(uri.hostname, uri.port,
                             open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT) do |http|
    http.request(request)
  end
  print "#{response.code}#{FIELD_SEPARATOR}#{response.body.to_s.length}#{BODY_SEPARATOR}"
  print response.body
rescue StandardError => e
  print "#{TRANSPORT_FAILURE}#{FIELD_SEPARATOR}0#{BODY_SEPARATOR}"
  print "#{e.class}: #{e.message}"
end
