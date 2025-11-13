{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Aenebris.Proxy
  ( startProxy
  , proxyApp
  , selectUpstream
  ) where

import Aenebris.Config
import Control.Exception (try, SomeException)
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Client (Manager, httpLbs, parseRequest, RequestBody(..))
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Types
import Network.Wai
import Network.Wai.Handler.Warp (run)
import System.IO (hPutStrLn, stderr)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as LBS

-- | Start the proxy server with given configuration
startProxy :: Config -> Manager -> IO ()
startProxy config manager = do
  -- For now, just use the first listen port
  -- TODO: Support multiple ports with different settings
  case configListen config of
    [] -> error "No listen ports configured"
    (firstPort:_) -> do
      let port = listenPort firstPort
      putStrLn $ "Starting Ᾰenebris reverse proxy on port " ++ show port
      putStrLn $ "Loaded " ++ show (length $ configUpstreams config) ++ " upstream(s)"
      putStrLn $ "Loaded " ++ show (length $ configRoutes config) ++ " route(s)"
      run port (proxyApp config manager)

-- | Main proxy application (WAI)
proxyApp :: Config -> Manager -> Application
proxyApp config manager req respond = do
  -- Log incoming request
  logRequest req

  -- Find matching route based on Host header and path
  let hostHeader = lookup "Host" (requestHeaders req)
      requestPath = rawPathInfo req

  case selectRoute config hostHeader requestPath of
    Nothing -> do
      -- No matching route found - return 404
      hPutStrLn stderr $ "ERROR: No route found for request"
      respond $ responseLBS
        status404
        [("Content-Type", "text/plain")]
        "Not Found: No route configured for this host/path"

    Just (selectedUpstream, _pathRoute) -> do
      -- Find the upstream by name
      case findUpstream config selectedUpstream of
        Nothing -> do
          hPutStrLn stderr $ "ERROR: Upstream not found: " ++ T.unpack selectedUpstream
          respond $ responseLBS
            status500
            [("Content-Type", "text/plain")]
            "Internal Server Error: Upstream configuration error"

        Just upstream -> do
          -- Select a backend server (for now, just use the first one)
          -- TODO: Implement load balancing algorithms
          case selectBackend upstream of
            Nothing -> do
              hPutStrLn stderr $ "ERROR: No backend servers available"
              respond $ responseLBS
                status503
                [("Content-Type", "text/plain")]
                "Service Unavailable: No backend servers available"

            Just server -> do
              -- Try to forward request to backend
              result <- try $ forwardRequest manager req (serverHost server)

              case result of
                Left (err :: SomeException) -> do
                  -- Handle errors gracefully
                  hPutStrLn stderr $ "ERROR: " ++ show err
                  respond $ responseLBS
                    status502
                    [("Content-Type", "text/plain")]
                    "Bad Gateway: Could not connect to backend server"

                Right response -> do
                  -- Log response status
                  logResponse response
                  respond response

-- | Select a route based on Host header and path
selectRoute :: Config -> Maybe BS.ByteString -> BS.ByteString -> Maybe (Text, PathRoute)
selectRoute config hostHeader requestPath =
  case hostHeader of
    Nothing -> Nothing  -- No Host header, can't route
    Just host -> do
      -- Find route matching this host
      let hostText = TE.decodeUtf8 host
          matchingRoutes = filter (\r -> routeHost r == hostText) (configRoutes config)

      -- Find first matching path within the route
      route <- listToMaybe matchingRoutes
      let requestPathText = TE.decodeUtf8 requestPath
          matchingPaths = filter (\p -> pathMatches (pathRoutePath p) requestPathText) (routePaths route)

      pathRoute <- listToMaybe matchingPaths
      return (pathRouteUpstream pathRoute, pathRoute)

-- | Check if a path pattern matches a request path
-- For now, just simple prefix matching
-- TODO: Implement more sophisticated path matching (regex, wildcards)
pathMatches :: Text -> Text -> Bool
pathMatches pattern requestPath =
  pattern == "/" || T.isPrefixOf pattern requestPath

-- | Find an upstream by name
findUpstream :: Config -> Text -> Maybe Upstream
findUpstream config name =
  listToMaybe $ filter (\u -> upstreamName u == name) (configUpstreams config)

-- | Select a backend server from an upstream
-- For now, just returns the first server
-- TODO: Implement load balancing (round-robin, weighted, least-connections)
selectBackend :: Upstream -> Maybe Server
selectBackend upstream = listToMaybe (upstreamServers upstream)

-- | Select an upstream for a request (exported for testing)
selectUpstream :: Config -> Maybe BS.ByteString -> BS.ByteString -> Maybe Text
selectUpstream config hostHeader requestPath =
  fmap fst $ selectRoute config hostHeader requestPath

-- | Forward request to backend server
forwardRequest :: Manager -> Request -> Text -> IO Response
forwardRequest manager clientReq backendHostPort = do
  -- Parse backend host:port
  let backendUrl = "http://" ++ T.unpack backendHostPort ++
                   BS8.unpack (rawPathInfo clientReq) ++
                   BS8.unpack (rawQueryString clientReq)

  -- Parse and build backend request
  initReq <- parseRequest backendUrl

  let backendReq = initReq
        { HTTP.method = requestMethod clientReq
        , HTTP.requestHeaders = filterHeaders (requestHeaders clientReq)
        , HTTP.requestBody = RequestBodyLBS LBS.empty  -- TODO: Forward request body
        }

  -- Make request to backend
  backendResponse <- httpLbs backendReq manager

  -- Convert backend response to WAI response
  let status = HTTP.responseStatus backendResponse
      headers = HTTP.responseHeaders backendResponse
      body = HTTP.responseBody backendResponse

  return $ responseLBS status headers body

-- | Filter headers (remove hop-by-hop headers)
filterHeaders :: [(HeaderName, BS.ByteString)] -> [(HeaderName, BS.ByteString)]
filterHeaders = filter (\(name, _) -> name `notElem` hopByHopHeaders)
  where
    hopByHopHeaders =
      [ "Connection"
      , "Keep-Alive"
      , "Proxy-Authenticate"
      , "Proxy-Authorization"
      , "TE"
      , "Trailers"
      , "Transfer-Encoding"
      , "Upgrade"
      ]

-- | Log incoming request
logRequest :: Request -> IO ()
logRequest req = do
  let method' = BS8.unpack (requestMethod req)
      path = BS8.unpack (rawPathInfo req)
      query = BS8.unpack (rawQueryString req)
      host = fromMaybe "unknown" $ lookup "Host" (requestHeaders req)

  putStrLn $ "[→] " ++ method' ++ " " ++ path ++ query ++ " (Host: " ++ BS8.unpack host ++ ")"

-- | Log response
logResponse :: Response -> IO ()
logResponse res = do
  let (Status code msg) = responseStatus res
  putStrLn $ "[←] " ++ show code ++ " " ++ BS8.unpack msg
