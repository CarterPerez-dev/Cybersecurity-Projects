{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}

module Aenebris.Proxy
  ( ProxyState(..)
  , initProxyState
  , startProxy
  , proxyApp
  , selectUpstream
  ) where

import Aenebris.Backend
import Aenebris.Config
import Aenebris.Connection
import Aenebris.HealthCheck
import Aenebris.LoadBalancer
import Aenebris.TLS
import Aenebris.Tunnel
import Aenebris.Middleware.Security
import Aenebris.Middleware.Redirect
import Control.Concurrent.Async (Async, async, waitAnyCancel)
import Control.Exception (try, SomeException)
import Data.Function ((&))
import Data.List (sortBy)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Ord (comparing)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Client (Manager, httpLbs, withResponse, parseRequest, RequestBody(..), brRead)
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Types
import Network.Wai
import Data.ByteString.Builder (byteString)
import Control.Monad (unless)
import Network.Wai.Handler.Warp (run, defaultSettings, setPort)
import Network.Wai.Handler.WarpTLS (runTLS)
import System.IO (hPutStrLn, stderr)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as LBS

-- | Proxy runtime state
data ProxyState = ProxyState
  { psConfig :: Config
  , psLoadBalancers :: Map Text LoadBalancer  -- upstream name -> load balancer
  , psHealthCheckers :: [Async ()]
  , psManager :: Manager
  }

-- | Initialize proxy state from config
initProxyState :: Config -> Manager -> IO ProxyState
initProxyState config manager = do
  -- Create load balancers for each upstream
  lbs <- mapM createUpstreamLoadBalancer (configUpstreams config)
  let lbMap = Map.fromList (zip (map upstreamName $ configUpstreams config) lbs)

  -- Start health checkers for all upstreams
  checkers <- mapM startUpstreamHealthChecker (configUpstreams config)

  return ProxyState
    { psConfig = config
    , psLoadBalancers = lbMap
    , psHealthCheckers = checkers
    , psManager = manager
    }
  where
    -- Create load balancer for an upstream
    createUpstreamLoadBalancer :: Upstream -> IO LoadBalancer
    createUpstreamLoadBalancer upstream = do
      -- Convert Config Servers to RuntimeBackends
      backends <- zipWithM createRuntimeBackend [0..] (upstreamServers upstream)

      -- Determine strategy (for now, use weighted if weights differ, else round-robin)
      let weights = map serverWeight (upstreamServers upstream)
          strategy = case weights of
            [] -> RoundRobin  -- No backends, shouldn't happen but be safe
            (w:ws) -> if all (== w) ws
                        then RoundRobin
                        else WeightedRoundRobin

      createLoadBalancer strategy backends

    -- Start health checker for an upstream
    startUpstreamHealthChecker :: Upstream -> IO (Async ())
    startUpstreamHealthChecker upstream = do
      backends <- zipWithM createRuntimeBackend [0..] (upstreamServers upstream)

      -- Use health check config from upstream, or defaults
      let hcConfig = case upstreamHealthCheck upstream of
            Just hc -> defaultHealthCheckConfig
              { hcInterval = 10  -- TODO: parse interval from config
              , hcEndpoint = healthCheckPath hc
              }
            Nothing -> defaultHealthCheckConfig

      startHealthChecker manager hcConfig backends

-- | Start the proxy server with given configuration
-- Supports multiple ports with HTTP and HTTPS (including SNI)
startProxy :: ProxyState -> IO ()
startProxy ProxyState{..} = do
  putStrLn $ "Starting Ᾰenebris reverse proxy"
  putStrLn $ "Loaded " ++ show (length $ configUpstreams psConfig) ++ " upstream(s)"
  putStrLn $ "Loaded " ++ show (length $ configRoutes psConfig) ++ " route(s)"
  putStrLn $ "Health checking enabled for all upstreams"

  case configListen psConfig of
    [] -> error "No listen ports configured"
    listenConfigs -> do
      -- Launch a server for each listen port concurrently
      servers <- mapM (launchServer psConfig psLoadBalancers psManager) listenConfigs

      -- Wait for any server to fail (shouldn't happen in normal operation)
      waitAnyCancel servers

      putStrLn "All servers stopped"

-- | Launch a single server instance (HTTP or HTTPS)
launchServer :: Config -> Map Text LoadBalancer -> Manager -> ListenConfig -> IO (Async ())
launchServer config loadBalancers manager listenConfig = async $ do
  let port = listenPort listenConfig
      shouldRedirect = fromMaybe False (listenRedirectHTTPS listenConfig)

      -- Build the base application
      baseApp = proxyApp config loadBalancers manager

      -- Add security headers (production level by default)
      securedApp = addSecurityHeaders defaultSecurityConfig baseApp

  case listenTLS listenConfig of
    Nothing -> do
      -- Plain HTTP server
      let app = if shouldRedirect
                then httpsRedirect securedApp  -- Redirect all HTTP to HTTPS
                else securedApp

      putStrLn $ "✓ HTTP server listening on :" ++ show port
      if shouldRedirect
        then putStrLn $ "  └─ Redirecting all traffic to HTTPS"
        else return ()

      run port app

    Just tlsConfig -> do
      -- HTTPS server - check if single cert or SNI
      let isSNI = case tlsSNI tlsConfig of
            Just domains -> not (null domains)
            Nothing -> False

      if isSNI
        then launchHTTPSWithSNI port tlsConfig securedApp
        else launchHTTPS port tlsConfig securedApp

-- | Launch HTTPS server with single certificate
launchHTTPS :: Int -> TLSConfig -> Application -> IO ()
launchHTTPS port tlsConfig app = do
  case (tlsCert tlsConfig, tlsKey tlsConfig) of
    (Just certFile, Just keyFile) -> do
      -- Load TLS settings
      tlsResult <- createTLSSettings certFile keyFile
      case tlsResult of
        Left err -> do
          hPutStrLn stderr $ "ERROR: Failed to load TLS certificate"
          hPutStrLn stderr $ "  " ++ show err
          error "TLS configuration error"

        Right tlsSettings -> do
          let warpSettings = defaultSettings & setPort port
          putStrLn $ "✓ HTTPS server listening on :" ++ show port
          putStrLn $ "  ├─ Certificate: " ++ certFile
          putStrLn $ "  ├─ TLS 1.2 + TLS 1.3 enabled"
          putStrLn $ "  ├─ HTTP/2 enabled (ALPN)"
          putStrLn $ "  └─ Strong cipher suites enforced"
          runTLS tlsSettings warpSettings app

    _ -> error "TLS configuration error: cert and key required"

-- | Launch HTTPS server with SNI support (multiple certificates)
launchHTTPSWithSNI :: Int -> TLSConfig -> Application -> IO ()
launchHTTPSWithSNI port tlsConfig app = do
  case (tlsSNI tlsConfig, tlsDefaultCert tlsConfig, tlsDefaultKey tlsConfig) of
    (Just sniDomains, Just defaultCert, Just defaultKey) -> do
      -- Convert SNIDomain list to the format expected by createSNISettings
      let domainList = [(sniDomain d, sniCert d, sniKey d) | d <- sniDomains]

      -- Load SNI TLS settings
      tlsResult <- createSNISettings domainList defaultCert defaultKey
      case tlsResult of
        Left err -> do
          hPutStrLn stderr $ "ERROR: Failed to load SNI certificates"
          hPutStrLn stderr $ "  " ++ show err
          error "SNI configuration error"

        Right tlsSettings -> do
          let warpSettings = defaultSettings & setPort port
          putStrLn $ "✓ HTTPS server with SNI listening on :" ++ show port
          putStrLn $ "  ├─ SNI domains: " ++ show (length sniDomains) ++ " configured"
          mapM_ (\d -> putStrLn $ "  │  • " ++ T.unpack (sniDomain d) ++ " -> " ++ sniCert d) sniDomains
          putStrLn $ "  ├─ Default certificate: " ++ defaultCert
          putStrLn $ "  ├─ TLS 1.2 + TLS 1.3 enabled"
          putStrLn $ "  ├─ HTTP/2 enabled (ALPN)"
          putStrLn $ "  └─ Strong cipher suites enforced"
          runTLS tlsSettings warpSettings app

    _ -> error "SNI configuration error: sni, default_cert, and default_key required"

-- | Main proxy application (WAI)
proxyApp :: Config -> Map Text LoadBalancer -> Manager -> Application
proxyApp config loadBalancers manager req respond = do
  logRequest req

  let hostHeader = lookup "Host" (requestHeaders req)
      requestPath = rawPathInfo req
      headers = requestHeaders req
      connType = detectConnectionType headers

  case selectRoute config hostHeader requestPath of
    Nothing -> do
      hPutStrLn stderr $ "ERROR: No route found for request"
      respond $ responseLBS
        status404
        [("Content-Type", "text/plain")]
        "Not Found: No route configured for this host/path"

    Just (upstreamName, _pathRoute) -> do
      case Map.lookup upstreamName loadBalancers of
        Nothing -> do
          hPutStrLn stderr $ "ERROR: Load balancer not found: " ++ T.unpack upstreamName
          respond $ responseLBS
            status500
            [("Content-Type", "text/plain")]
            "Internal Server Error: Upstream configuration error"

        Just loadBalancer -> do
          mBackend <- selectBackend loadBalancer

          case mBackend of
            Nothing -> do
              hPutStrLn stderr $ "ERROR: No healthy backends available"
              respond $ responseLBS
                status503
                [("Content-Type", "text/plain")]
                "Service Unavailable: No healthy backends available"

            Just backend -> do
              case connType of
                WebSocket -> do
                  hPutStrLn stderr $ "[WS] WebSocket upgrade detected"
                  handleWebSocketUpgrade req respond backend

                RegularHttp -> do
                  result <- try $ trackConnection backend $
                    forwardRequest manager req (rbHost backend) respond

                  case result of
                    Left (err :: SomeException) -> do
                      hPutStrLn stderr $ "ERROR: " ++ show err
                      respond $ responseLBS
                        status502
                        [("Content-Type", "text/plain")]
                        "Bad Gateway: Could not connect to backend server"

                    Right responseReceived ->
                      return responseReceived

                _ -> do
                  result <- try $ trackConnection backend $
                    forwardRequest manager req (rbHost backend) respond

                  case result of
                    Left (err :: SomeException) -> do
                      hPutStrLn stderr $ "ERROR: " ++ show err
                      respond $ responseLBS
                        status502
                        [("Content-Type", "text/plain")]
                        "Bad Gateway: Could not connect to backend server"

                    Right responseReceived ->
                      return responseReceived

handleWebSocketUpgrade :: Request -> (Response -> IO ResponseReceived) -> RuntimeBackend -> IO ResponseReceived
handleWebSocketUpgrade req respond backend = do
  let backendHost = rbHost backend
      backupResponse = responseLBS
        status502
        [("Content-Type", "text/plain")]
        "WebSocket upgrade failed"

  respond $ responseRaw (wsHandler req backendHost) backupResponse

wsHandler :: Request -> Text -> IO ByteString -> (ByteString -> IO ()) -> IO ()
wsHandler req backendHost recv send = do
  hPutStrLn stderr $ "[WS] Starting WebSocket tunnel to " ++ T.unpack backendHost
  tunnelWebSocket req backendHost send recv

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
          -- Sort paths by length (longest first) so more specific paths match first
          sortedPaths = sortBy (comparing (negate . T.length . pathRoutePath)) (routePaths route)
          matchingPaths = filter (\p -> pathMatches (pathRoutePath p) requestPathText) sortedPaths

      pathRoute <- listToMaybe matchingPaths
      return (pathRouteUpstream pathRoute, pathRoute)

-- | Check if a path pattern matches a request path
pathMatches :: Text -> Text -> Bool
pathMatches pattern requestPath =
  pattern == "/" || T.isPrefixOf pattern requestPath

-- | Select an upstream for a request (exported for testing)
selectUpstream :: Config -> Maybe BS.ByteString -> BS.ByteString -> Maybe Text
selectUpstream config hostHeader requestPath =
  fmap fst $ selectRoute config hostHeader requestPath

-- | Forward request to backend server with streaming support
forwardRequest :: Manager -> Request -> Text -> (Response -> IO ResponseReceived) -> IO ResponseReceived
forwardRequest manager clientReq backendHost respond = do
  requestBody <- strictRequestBody clientReq

  let backendUrl = "http://" ++ T.unpack backendHost ++
                   BS8.unpack (rawPathInfo clientReq) ++
                   BS8.unpack (rawQueryString clientReq)

  initReq <- parseRequest backendUrl

  let backendReq = initReq
        { HTTP.method = requestMethod clientReq
        , HTTP.requestHeaders = filterHeaders (requestHeaders clientReq)
        , HTTP.requestBody = RequestBodyLBS requestBody
        }

  withResponse backendReq manager $ \backendResponse -> do
    let status = HTTP.responseStatus backendResponse
        headers = HTTP.responseHeaders backendResponse
        bodyReader = HTTP.responseBody backendResponse

    if shouldStreamResponse headers
      then do
        hPutStrLn stderr "[STREAM] Streaming response detected"
        respond $ responseStream status (filterResponseHeaders headers) $ \write flush -> do
          let loop = do
                chunk <- brRead bodyReader
                unless (BS.null chunk) $ do
                  write (byteString chunk)
                  flush
                  loop
          loop
      else do
        body <- readFullBody bodyReader
        respond $ responseLBS status (filterResponseHeaders headers) body

shouldStreamResponse :: [(HeaderName, BS.ByteString)] -> Bool
shouldStreamResponse headers =
  isSSE || isChunkedWithoutLength
  where
    isSSE = case lookup "Content-Type" headers of
      Just ct -> "text/event-stream" `BS.isInfixOf` ct
      Nothing -> False

    isChunkedWithoutLength =
      hasChunkedEncoding && not hasContentLength

    hasChunkedEncoding = case lookup "Transfer-Encoding" headers of
      Just te -> "chunked" `BS.isInfixOf` te
      Nothing -> False

    hasContentLength = case lookup "Content-Length" headers of
      Just _ -> True
      Nothing -> False

readFullBody :: HTTP.BodyReader -> IO LBS.ByteString
readFullBody bodyReader = LBS.fromChunks <$> go
  where
    go = do
      chunk <- brRead bodyReader
      if BS.null chunk
        then return []
        else do
          rest <- go
          return (chunk : rest)

filterResponseHeaders :: [(HeaderName, BS.ByteString)] -> [(HeaderName, BS.ByteString)]
filterResponseHeaders = filter (\(name, _) -> name `notElem` hopByHopHeaders)
  where
    hopByHopHeaders =
      [ "Transfer-Encoding"
      , "Connection"
      , "Keep-Alive"
      ]

-- | Filter headers for regular HTTP (remove hop-by-hop headers)
filterHeaders :: [(HeaderName, BS.ByteString)] -> [(HeaderName, BS.ByteString)]
filterHeaders headers = filter (\(name, _) -> name `notElem` hopByHopHeaders) headers
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

-- | Filter headers for WebSocket upgrade (preserve Upgrade and Connection)
filterHeadersForUpgrade :: [(HeaderName, BS.ByteString)] -> [(HeaderName, BS.ByteString)]
filterHeadersForUpgrade headers = filter (\(name, _) -> name `notElem` hopByHopHeaders) headers
  where
    hopByHopHeaders =
      [ "Keep-Alive"
      , "Proxy-Authenticate"
      , "Proxy-Authorization"
      , "TE"
      , "Trailers"
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

-- Helper: zipWithM
zipWithM :: Monad m => (a -> b -> m c) -> [a] -> [b] -> m [c]
zipWithM f xs ys = sequence (zipWith f xs ys)
