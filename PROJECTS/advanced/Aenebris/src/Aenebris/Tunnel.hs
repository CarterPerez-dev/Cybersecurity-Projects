{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}

module Aenebris.Tunnel
  ( tunnelWebSocket
  , streamResponse
  , bidirectionalCopy
  ) where

import Control.Concurrent.Async (race_)
import Control.Exception (SomeException, try, bracket)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.CaseInsensitive (original)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Types (HeaderName)
import Network.Socket (Socket)
import qualified Network.Socket as Socket
import qualified Network.Socket.ByteString as SocketBS
import Network.Wai
import System.IO (hPutStrLn, stderr)

tunnelWebSocket
  :: Request
  -> Text
  -> (ByteString -> IO ())
  -> IO ByteString
  -> IO ()
tunnelWebSocket clientReq backendHost clientSend clientRecv = do
  hPutStrLn stderr $ "[WS] Initiating tunnel to " ++ T.unpack backendHost

  result <- try $ do
    let (host, port) = parseHostPort backendHost

    bracket
      (connectToBackend host port)
      Socket.close
      $ \backendSocket -> do
          sendUpgradeRequest backendSocket clientReq
          upgradeResponse <- receiveUpgradeResponse backendSocket

          case parseUpgradeStatus upgradeResponse of
            Just 101 -> do
              hPutStrLn stderr "[WS] Backend accepted upgrade (101)"
              clientSend upgradeResponse
              bidirectionalCopy clientRecv clientSend
                (SocketBS.recv backendSocket 65536)
                (SocketBS.sendAll backendSocket)

            Just code -> do
              hPutStrLn stderr $ "[WS] Backend rejected upgrade: " ++ show code
              clientSend upgradeResponse

            Nothing -> do
              hPutStrLn stderr "[WS] Invalid upgrade response"
              clientSend "HTTP/1.1 502 Bad Gateway\r\n\r\n"

  case result of
    Left (e :: SomeException) ->
      hPutStrLn stderr $ "[WS] Tunnel error: " ++ show e
    Right () ->
      hPutStrLn stderr "[WS] Tunnel closed"

bidirectionalCopy
  :: IO ByteString
  -> (ByteString -> IO ())
  -> IO ByteString
  -> (ByteString -> IO ())
  -> IO ()
bidirectionalCopy clientRecv clientSend backendRecv backendSend = do
  hPutStrLn stderr "[TUNNEL] Starting bidirectional copy"

  race_
    (copyLoop "client->backend" clientRecv backendSend)
    (copyLoop "backend->client" backendRecv clientSend)

  hPutStrLn stderr "[TUNNEL] Bidirectional copy ended"

copyLoop :: String -> IO ByteString -> (ByteString -> IO ()) -> IO ()
copyLoop name recv send = go
  where
    go = do
      chunk <- recv
      if BS.null chunk
        then hPutStrLn stderr $ "[TUNNEL] " ++ name ++ ": connection closed"
        else do
          send chunk
          go

streamResponse
  :: (ByteString -> IO ())
  -> IO ByteString
  -> IO ()
streamResponse clientSend backendRecv = do
  hPutStrLn stderr "[STREAM] Starting streaming response"
  go
  where
    go = do
      chunk <- backendRecv
      if BS.null chunk
        then hPutStrLn stderr "[STREAM] Backend closed"
        else do
          clientSend chunk
          go

parseHostPort :: Text -> (String, Int)
parseHostPort hostPort =
  case T.splitOn ":" hostPort of
    [host, portStr] ->
      case reads (T.unpack portStr) of
        [(port, "")] -> (T.unpack host, port)
        _ -> (T.unpack host, 80)
    [host] -> (T.unpack host, 80)
    _ -> (T.unpack hostPort, 80)

connectToBackend :: String -> Int -> IO Socket
connectToBackend host port = do
  addrInfos <- Socket.getAddrInfo
    (Just Socket.defaultHints { Socket.addrSocketType = Socket.Stream })
    (Just host)
    (Just $ show port)

  case addrInfos of
    [] -> error $ "Cannot resolve: " ++ host ++ ":" ++ show port
    (addr:_) -> do
      sock <- Socket.socket
        (Socket.addrFamily addr)
        Socket.Stream
        Socket.defaultProtocol
      Socket.connect sock (Socket.addrAddress addr)
      return sock

sendUpgradeRequest :: Socket -> Request -> IO ()
sendUpgradeRequest sock req = do
  let method = requestMethod req
      path = rawPathInfo req <> rawQueryString req
      headers = requestHeaders req

      requestLine = method <> " " <> path <> " HTTP/1.1\r\n"
      headerLines = BS.concat
        [ original name <> ": " <> value <> "\r\n"
        | (name, value) <- headers
        ]
      fullRequest = requestLine <> headerLines <> "\r\n"

  SocketBS.sendAll sock fullRequest

receiveUpgradeResponse :: Socket -> IO ByteString
receiveUpgradeResponse sock = do
  chunk <- SocketBS.recv sock 4096
  if "\r\n\r\n" `BS.isInfixOf` chunk
    then return chunk
    else do
      rest <- receiveUpgradeResponse sock
      return $ chunk <> rest

parseUpgradeStatus :: ByteString -> Maybe Int
parseUpgradeStatus response =
  case BS8.words (head $ BS8.lines response) of
    (_:codeBS:_) ->
      case reads (BS8.unpack codeBS) of
        [(code, "")] -> Just code
        _ -> Nothing
    _ -> Nothing
