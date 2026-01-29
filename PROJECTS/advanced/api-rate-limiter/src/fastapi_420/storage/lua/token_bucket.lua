--[[
ⒸAngelaMos | 2025
token_bucket.lua

Atomic token bucket rate limiting.
Returns: {allowed (0/1), remaining, reset_after, retry_after}
--]]

local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local tokens_to_consume = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local bucket_key = key .. ":bucket"
local data = redis.call('HMGET', bucket_key, 'tokens', 'last_refill')

local tokens = tonumber(data[1])
local last_refill = tonumber(data[2])

if tokens == nil then
    tokens = capacity
    last_refill = now
end

local elapsed = now - last_refill
local tokens_to_add = elapsed * refill_rate
tokens = math.min(capacity, tokens + tokens_to_add)

if tokens >= tokens_to_consume then
    tokens = tokens - tokens_to_consume
    redis.call('HMSET', bucket_key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', bucket_key, 3600)

    local time_to_full = 0
    if refill_rate > 0 then
        time_to_full = (capacity - tokens) / refill_rate
    end

    return {1, math.floor(tokens), time_to_full, 0}
end

redis.call('HMSET', bucket_key, 'tokens', tokens, 'last_refill', now)
redis.call('EXPIRE', bucket_key, 3600)

local tokens_needed = tokens_to_consume - tokens
local wait_time = tokens_needed / refill_rate

return {0, 0, wait_time, wait_time}
