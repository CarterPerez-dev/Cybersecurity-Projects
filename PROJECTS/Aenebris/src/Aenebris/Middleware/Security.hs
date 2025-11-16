{-# LANGUAGE OverloadedStrings #-}

module Aenebris.Middleware.Security
  ( addSecurityHeaders
  , SecurityLevel(..)
  , SecurityConfig(..)
  , defaultSecurityConfig
  , strictSecurityConfig
  , testingSecurityConfig
  ) where

import Data.ByteString (ByteString)
import qualified Data.CaseInsensitive as CI
import Network.HTTP.Types (Header, ResponseHeaders)
import Network.Wai (Middleware, mapResponseHeaders)

-- | Security level presets
data SecurityLevel
  = Testing      -- Short HSTS, permissive CSP, for development
  | Production   -- Balanced security for production
  | Strict       -- Maximum security, strict CSP, HSTS preload
  deriving (Show, Eq)

-- | Security configuration
data SecurityConfig = SecurityConfig
  { scHSTS :: Maybe ByteString                  -- Strict-Transport-Security header
  , scCSP :: Maybe ByteString                   -- Content-Security-Policy header
  , scFrameOptions :: Maybe ByteString          -- X-Frame-Options header
  , scContentTypeOptions :: Bool                -- X-Content-Type-Options: nosniff
  , scReferrerPolicy :: Maybe ByteString        -- Referrer-Policy header
  , scPermissionsPolicy :: Maybe ByteString     -- Permissions-Policy header
  , scXSSProtection :: Maybe ByteString         -- X-XSS-Protection (legacy, but some crawlers check)
  , scExpectCT :: Maybe ByteString              -- Expect-CT (transitional)
  , scServerHeader :: Maybe ByteString          -- Server header (hide or customize)
  , scRemovePoweredBy :: Bool                   -- Remove X-Powered-By headers
  } deriving (Show, Eq)

-- | Testing/development security configuration
-- Use short HSTS for easy testing, permissive CSP
testingSecurityConfig :: SecurityConfig
testingSecurityConfig = SecurityConfig
  { scHSTS = Just "max-age=300"  -- 5 minutes for testing
  , scCSP = Just "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
  , scFrameOptions = Just "SAMEORIGIN"
  , scContentTypeOptions = True
  , scReferrerPolicy = Just "strict-origin-when-cross-origin"
  , scPermissionsPolicy = Just "geolocation=(), microphone=(), camera=()"
  , scXSSProtection = Just "1; mode=block"
  , scExpectCT = Nothing
  , scServerHeader = Just "Aenebris/0.1.0"
  , scRemovePoweredBy = True
  }

-- | Production security configuration
-- Balanced security, 1-month HSTS
defaultSecurityConfig :: SecurityConfig
defaultSecurityConfig = SecurityConfig
  { scHSTS = Just "max-age=2592000; includeSubDomains"  -- 30 days
  , scCSP = Just "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
  , scFrameOptions = Just "DENY"
  , scContentTypeOptions = True
  , scReferrerPolicy = Just "strict-origin-when-cross-origin"
  , scPermissionsPolicy = Just "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
  , scXSSProtection = Just "1; mode=block"
  , scExpectCT = Just "max-age=86400, enforce"
  , scServerHeader = Just "Aenebris"  -- Don't reveal version in production
  , scRemovePoweredBy = True
  }

-- | Strict security configuration for maximum protection
-- 2-year HSTS with preload, very restrictive CSP
strictSecurityConfig :: SecurityConfig
strictSecurityConfig = SecurityConfig
  { scHSTS = Just "max-age=63072000; includeSubDomains; preload"  -- 2 years + preload
  , scCSP = Just "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
  , scFrameOptions = Just "DENY"
  , scContentTypeOptions = True
  , scReferrerPolicy = Just "no-referrer"  -- Strictest, no referrer leakage
  , scPermissionsPolicy = Just "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), bluetooth=(), display-capture=(), document-domain=()"
  , scXSSProtection = Just "1; mode=block"
  , scExpectCT = Just "max-age=86400, enforce"
  , scServerHeader = Nothing  -- Hide completely
  , scRemovePoweredBy = True
  }

-- | Middleware that adds security headers to all responses
addSecurityHeaders :: SecurityConfig -> Middleware
addSecurityHeaders config app req respond =
  app req $ \res ->
    respond $ mapResponseHeaders (addHeaders config) res

-- | Add security headers to response headers
addHeaders :: SecurityConfig -> ResponseHeaders -> ResponseHeaders
addHeaders config headers =
  let
    -- Remove headers we want to control
    cleaned = if scRemovePoweredBy config
              then filter (not . isPoweredBy) headers
              else headers

    -- Build new security headers
    newHeaders = catMaybes
      [ fmap (\v -> ("Strict-Transport-Security", v)) (scHSTS config)
      , fmap (\v -> ("Content-Security-Policy", v)) (scCSP config)
      , fmap (\v -> ("X-Frame-Options", v)) (scFrameOptions config)
      , if scContentTypeOptions config
        then Just ("X-Content-Type-Options", "nosniff")
        else Nothing
      , fmap (\v -> ("Referrer-Policy", v)) (scReferrerPolicy config)
      , fmap (\v -> ("Permissions-Policy", v)) (scPermissionsPolicy config)
      , fmap (\v -> ("X-XSS-Protection", v)) (scXSSProtection config)
      , fmap (\v -> ("Expect-CT", v)) (scExpectCT config)
      ]

    -- Handle Server header specially
    serverHeader = case scServerHeader config of
      Just v -> [("Server", v)]
      Nothing -> []  -- Remove Server header completely

    -- Remove existing Server header if we're replacing it
    withoutServer = filter (not . isServerHeader) cleaned

  in withoutServer ++ newHeaders ++ serverHeader

-- | Check if header is X-Powered-By
isPoweredBy :: Header -> Bool
isPoweredBy (name, _) = CI.mk name == CI.mk "X-Powered-By"

-- | Check if header is Server
isServerHeader :: Header -> Bool
isServerHeader (name, _) = CI.mk name == CI.mk "Server"

-- | catMaybes implementation (since we're not importing Data.Maybe)
catMaybes :: [Maybe a] -> [a]
catMaybes = foldr (\mx xs -> case mx of Just x -> x:xs; Nothing -> xs) []
