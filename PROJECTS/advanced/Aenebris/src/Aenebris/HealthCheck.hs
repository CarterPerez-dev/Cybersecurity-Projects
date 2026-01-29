{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Aenebris.HealthCheck
  ( HealthCheckConfig(..)
  , defaultHealthCheckConfig
  , startHealthChecker
  , stopHealthChecker
  , performHealthCheck
  ) where

import Aenebris.Backend
import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
import Control.Concurrent.STM
import Control.Monad (forever)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (getCurrentTime)
import Network.HTTP.Client
import Network.HTTP.Types.Status (statusCode)
import System.Timeout (timeout)

-- | Health check configuration
data HealthCheckConfig = HealthCheckConfig
  { hcInterval :: Int           -- Seconds between checks
  , hcTimeout :: Int            -- Request timeout (seconds)
  , hcEndpoint :: Text          -- Health endpoint path (e.g., "/health")
  , hcMaxFailures :: Int        -- Failures before marking unhealthy
  , hcRecoveryAttempts :: Int   -- Successes before marking healthy
  }

-- | Default health check configuration
defaultHealthCheckConfig :: HealthCheckConfig
defaultHealthCheckConfig = HealthCheckConfig
  { hcInterval = 10
  , hcTimeout = 2
  , hcEndpoint = "/health"
  , hcMaxFailures = 3
  , hcRecoveryAttempts = 2
  }

-- | Start health checker (returns Async handle for stopping)
startHealthChecker :: Manager -> HealthCheckConfig -> [RuntimeBackend] -> IO (Async ())
startHealthChecker manager config backends =
  async $ healthCheckLoop manager config backends

-- | Stop health checker
stopHealthChecker :: Async () -> IO ()
stopHealthChecker = cancel

-- | Main health check loop
healthCheckLoop :: Manager -> HealthCheckConfig -> [RuntimeBackend] -> IO ()
healthCheckLoop manager config backends = forever $ do
  -- Check all backends concurrently
  results <- mapConcurrently (performHealthCheck manager config) backends

  -- Update backend states based on results
  atomically $ zipWithM_ (updateBackendState config) backends results

  threadDelay (hcInterval config * 1000000)

-- | Perform HTTP health check on a backend
performHealthCheck :: Manager -> HealthCheckConfig -> RuntimeBackend -> IO Bool
performHealthCheck manager config backend = do
  let url = "http://" ++ T.unpack (rbHost backend) ++ T.unpack (hcEndpoint config)

  -- Try to make request with timeout
  result <- timeout (hcTimeout config * 1000000) $ do
    req <- parseRequest url
    response <- httpLbs req manager
    return $ statusCode (responseStatus response) == 200

  -- Update last check time
  now <- getCurrentTime
  atomically $ writeTVar (rbLastHealthCheck backend) (Just now)

  return $ case result of
    Just True -> True
    _ -> False

-- | Update backend state based on health check result
updateBackendState :: HealthCheckConfig -> RuntimeBackend -> Bool -> STM ()
updateBackendState config backend healthy =
  if healthy
    then recordSuccess backend (hcRecoveryAttempts config)
    else recordFailure backend (hcMaxFailures config)

-- | Helper: zip with monadic action
zipWithM_ :: Monad m => (a -> b -> m c) -> [a] -> [b] -> m ()
zipWithM_ f xs ys = sequence_ (zipWith f xs ys)
