--[[
ⒸAngelaMos | 2025
fixed_window.lua

Atomic fixed window counter rate limiting.
Simple but has boundary burst problem - use sliding_window for production.
Returns: {allowed (0/1), remaining, reset_after, retry_after}
--]]

local key = KEYS[1]
local window_seconds = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local current_window = math.floor(now / window_seconds)
local window_key = key .. ":" .. current_window

local count = tonumber(redis.call('GET', window_key)) or 0
local reset_after = window_seconds - (now % window_seconds)

if count >= limit then
    return {0, 0, reset_after, reset_after}
end

local new_count = redis.call('INCR', window_key)
if new_count == 1 then
    redis.call('EXPIRE', window_key, window_seconds)
end

local remaining = math.max(0, limit - new_count)

return {1, remaining, reset_after, 0}
