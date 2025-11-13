{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main (main) where

import Network.Wai
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types
import Network.HTTP.Client (Manager, newManager, defaultManagerSettings, httpLbs, parseRequest, method, requestBody, RequestBody(..))
import qualified Network.HTTP.Client as HTTP
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.Maybe (fromMaybe)
import Control.Exception (try, SomeException)
import System.IO (hPutStrLn, stderr)

-- Configuration
backendHost :: String
backendHost = "localhost"

backendPort :: Int
backendPort = 8000

proxyPort :: Int
proxyPort = 8080

main :: IO ()
main = do
  putStrLn $ "Starting Ᾰenebris reverse proxy on port " ++ show proxyPort
  putStrLn $ "Forwarding to backend: http://" ++ backendHost ++ ":" ++ show backendPort
  manager <- newManager defaultManagerSettings
  run proxyPort (proxyApp manager)

proxyApp :: Manager -> Application
proxyApp manager req respond = do
  -- Log incoming request
  logRequest req

  -- Try to forward request to backend
  result <- try $ forwardRequest manager req

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

-- Forward request to backend server
forwardRequest :: Manager -> Request -> IO Response
forwardRequest manager clientReq = do
  -- Build backend URL
  let backendUrl = "http://" ++ backendHost ++ ":" ++ show backendPort ++ BS8.unpack (rawPathInfo clientReq) ++ BS8.unpack (rawQueryString clientReq)

  -- Parse and build backend request
  initReq <- parseRequest backendUrl

  let backendReq = initReq
        { HTTP.method = requestMethod clientReq
        , HTTP.requestHeaders = filterHeaders (requestHeaders clientReq)
        , HTTP.requestBody = RequestBodyLBS LBS.empty  -- For now, empty body
        }

  -- Make request to backend
  backendResponse <- httpLbs backendReq manager

  -- Convert backend response to WAI response
  let statusCode = HTTP.responseStatus backendResponse
      headers = HTTP.responseHeaders backendResponse
      body = HTTP.responseBody backendResponse

  return $ responseLBS statusCode headers body

-- Filter headers (remove hop-by-hop headers)
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

-- Log incoming request
logRequest :: Request -> IO ()
logRequest req = do
  let method' = BS8.unpack (requestMethod req)
      path = BS8.unpack (rawPathInfo req)
      query = BS8.unpack (rawQueryString req)
      host = fromMaybe "unknown" $ lookup "Host" (requestHeaders req)

  putStrLn $ "[→] " ++ method' ++ " " ++ path ++ query ++ " (Host: " ++ BS8.unpack host ++ ")"

-- Log response
logResponse :: Response -> IO ()
logResponse res = do
  let (Status code msg) = responseStatus res
  putStrLn $ "[←] " ++ show code ++ " " ++ BS8.unpack msg
