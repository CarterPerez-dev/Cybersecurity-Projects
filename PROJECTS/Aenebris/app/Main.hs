{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Aenebris.Config
import Aenebris.Proxy
import Network.HTTP.Client (newManager, defaultManagerSettings)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

main :: IO ()
main = do
  args <- getArgs

  -- Get config file path from args or use default
  let configPath = case args of
        (path:_) -> path
        [] -> "config.yaml"

  putStrLn $ "Loading configuration from: " ++ configPath

  result <- loadConfig configPath
  case result of
    Left err -> do
      hPutStrLn stderr $ "ERROR: Failed to load configuration"
      hPutStrLn stderr err
      exitFailure

    Right config -> do
      case validateConfig config of
        Left err -> do
          hPutStrLn stderr $ "ERROR: Invalid configuration"
          hPutStrLn stderr err
          exitFailure

        Right () -> do
          putStrLn "Configuration loaded and validated successfully"

          -- Create HTTP client manager with connection pooling
          manager <- newManager defaultManagerSettings

          -- Initialize proxy state (load balancers + health checkers)
          proxyState <- initProxyState config manager

          -- Start the proxy
          startProxy proxyState
