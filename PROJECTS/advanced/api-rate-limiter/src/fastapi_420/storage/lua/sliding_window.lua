--[[
ⒸAngelaMos | 2025
sliding_window.lua

Atomic sliding window counter rate limiting.
Returns: {allowed (0/1), remaining, reset_after}
--]]

local key = KEYS[1]
local window_seconds = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local current_window = math.floor(now / window_seconds)
local previous_window = current_window - 1
local elapsed_ratio = (now % window_seconds) / window_seconds

local current_key = key .. ":" .. current_window
local previous_key = key .. ":" .. previous_window

local current_count = tonumber(redis.call('GET', current_key)) or 0
local previous_count = tonumber(redis.call('GET', previous_key)) or 0

local weighted_count = math.floor(previous_count * (1 - elapsed_ratio) + current_count)
local reset_after = window_seconds - (now % window_seconds)

if weighted_count >= limit then
    return {0, 0, reset_after, reset_after}
end

redis.call('INCR', current_key)
redis.call('EXPIRE', current_key, window_seconds * 2)

local new_weighted = math.floor(previous_count * (1 - elapsed_ratio) + current_count + 1)
local remaining = math.max(0, limit - new_weighted)

return {1, remaining, reset_after, 0}
