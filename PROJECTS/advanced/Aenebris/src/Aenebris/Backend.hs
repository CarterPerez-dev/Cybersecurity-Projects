{-# LANGUAGE RecordWildCards #-}

module Aenebris.Backend
  ( BackendState(..)
  , RuntimeBackend(..)
  , createRuntimeBackend
  , isHealthy
  , trackConnection
  , getConnectionCount
  , getCurrentWeight
  , transitionToUnhealthy
  , transitionToRecovering
  , transitionToHealthy
  , recordFailure
  , recordSuccess
  ) where

import Aenebris.Config (Server(..))
import Control.Concurrent.STM
import Control.Exception (bracket_)
import Control.Monad (when)
import Data.Text (Text)
import Data.Time.Clock (UTCTime)

data BackendState
  = Healthy
  | Unhealthy
  | Recovering
  deriving (Eq, Show)

-- | Runtime backend state wrapping config Server
data RuntimeBackend = RuntimeBackend
  { rbServerId :: Int  -- Unique identifier
  , rbHost :: Text
  , rbWeight :: Int
  -- Runtime state (STM)
  , rbActiveConnections :: TVar Int
  , rbCurrentWeight :: TVar Int
  , rbHealthState :: TVar BackendState
  , rbConsecutiveFailures :: TVar Int
  , rbConsecutiveSuccesses :: TVar Int
  , rbLastHealthCheck :: TVar (Maybe UTCTime)
  , rbTotalRequests :: TVar Int      -- For metrics
  , rbTotalFailures :: TVar Int      -- For metrics
  }

instance Show RuntimeBackend where
  show rb = "RuntimeBackend {id=" ++ show (rbServerId rb) ++
            ", host=" ++ show (rbHost rb) ++ "}"

instance Eq RuntimeBackend where
  rb1 == rb2 = rbServerId rb1 == rbServerId rb2

-- | Runtime backend from config Server
createRuntimeBackend :: Int -> Server -> IO RuntimeBackend
createRuntimeBackend serverId Server{..} = do
  atomically $ RuntimeBackend serverId serverHost serverWeight
    <$> newTVar 0                    -- activeConnections
    <*> newTVar 0                    -- currentWeight (for smooth WRR)
    <*> newTVar Healthy              -- healthState
    <*> newTVar 0                    -- consecutiveFailures
    <*> newTVar 0                    -- consecutiveSuccesses
    <*> newTVar Nothing              -- lastHealthCheck
    <*> newTVar 0                    -- totalRequests
    <*> newTVar 0                    -- totalFailures

-- | Check if backend is healthy
isHealthy :: RuntimeBackend -> STM Bool
isHealthy rb = (== Healthy) <$> readTVar (rbHealthState rb)

-- | Track a connection (increment on start, decrement on end)
trackConnection :: RuntimeBackend -> IO a -> IO a
trackConnection rb action =
  bracket_
    (atomically $ do
      modifyTVar' (rbActiveConnections rb) (+1)
      modifyTVar' (rbTotalRequests rb) (+1))
    (atomically $ modifyTVar' (rbActiveConnections rb) (subtract 1))
    action

-- | Get current connection count
getConnectionCount :: RuntimeBackend -> STM Int
getConnectionCount rb = readTVar (rbActiveConnections rb)

-- | Get current weight (for smooth weighted RR)
getCurrentWeight :: RuntimeBackend -> STM Int
getCurrentWeight rb = readTVar (rbCurrentWeight rb)

-- | State transition: mark as unhealthy
transitionToUnhealthy :: RuntimeBackend -> STM ()
transitionToUnhealthy rb = do
  writeTVar (rbHealthState rb) Unhealthy
  writeTVar (rbConsecutiveFailures rb) 0
  writeTVar (rbConsecutiveSuccesses rb) 0

-- | State transition: start recovering
transitionToRecovering :: RuntimeBackend -> STM ()
transitionToRecovering rb = do
  writeTVar (rbHealthState rb) Recovering
  writeTVar (rbConsecutiveSuccesses rb) 1

-- | State transition: mark as healthy
transitionToHealthy :: RuntimeBackend -> STM ()
transitionToHealthy rb = do
  writeTVar (rbHealthState rb) Healthy
  writeTVar (rbConsecutiveFailures rb) 0
  writeTVar (rbConsecutiveSuccesses rb) 0

-- | Record a health check failure
recordFailure :: RuntimeBackend -> Int -> STM ()
recordFailure rb maxFailures = do
  state <- readTVar (rbHealthState rb)
  failures <- readTVar (rbConsecutiveFailures rb)

  case state of
    Healthy -> do
      let newFailures = failures + 1
      writeTVar (rbConsecutiveFailures rb) newFailures
      when (newFailures >= maxFailures) $
        transitionToUnhealthy rb

    Recovering -> do
      -- Failed during recovery, back to unhealthy
      transitionToUnhealthy rb

    Unhealthy ->
      -- Already unhealthy, just record it
      modifyTVar' (rbTotalFailures rb) (+1)

-- | Record a health check success
recordSuccess :: RuntimeBackend -> Int -> STM ()
recordSuccess rb recoveryAttempts = do
  state <- readTVar (rbHealthState rb)
  successes <- readTVar (rbConsecutiveSuccesses rb)

  case state of
    Healthy ->
      -- Reset failure counter
      writeTVar (rbConsecutiveFailures rb) 0

    Unhealthy ->
      -- First success, transition to recovering
      transitionToRecovering rb

    Recovering -> do
      let newSuccesses = successes + 1
      writeTVar (rbConsecutiveSuccesses rb) newSuccesses
      when (newSuccesses >= recoveryAttempts) $
        transitionToHealthy rb
