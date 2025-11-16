{-# LANGUAGE OverloadedStrings #-}

module Aenebris.Middleware.Redirect
  ( httpsRedirect
  , httpsRedirectWithPort
  ) where

import qualified Data.ByteString.Char8 as BS
import Data.Maybe (fromMaybe)
import Network.HTTP.Types (status301, hLocation)
import Network.Wai (Middleware, responseLBS, requestHeaderHost, rawPathInfo, rawQueryString, isSecure)

-- | Redirect HTTP requests to HTTPS (assumes HTTPS is on port 443)
httpsRedirect :: Middleware
httpsRedirect = httpsRedirectWithPort Nothing

-- | Redirect HTTP requests to HTTPS with optional custom port
-- If port is Nothing, assumes 443 (standard HTTPS port, no port in URL)
-- If port is Just n, includes :n in the redirect URL
httpsRedirectWithPort :: Maybe Int -> Middleware
httpsRedirectWithPort httpsPort app req respond
  | isSecure req = app req respond  -- Already HTTPS, pass through
  | otherwise = do
      -- Get host from Host header
      let hostHeader = fromMaybe "localhost" $ requestHeaderHost req

          -- Build HTTPS URL with optional port
          host = case httpsPort of
            Nothing -> hostHeader  -- Standard 443, don't include port
            Just 443 -> hostHeader  -- Standard 443, don't include port
            Just port -> hostHeader <> ":" <> BS.pack (show port)

          -- Get path and query string (already encoded in rawPathInfo)
          path = rawPathInfo req
          query = rawQueryString req

          -- Build full redirect URL
          redirectUrl = "https://" <> host <> path <> query

      -- Send 301 permanent redirect
      respond $ responseLBS
        status301
        [(hLocation, redirectUrl)]
        "Redirecting to HTTPS"
