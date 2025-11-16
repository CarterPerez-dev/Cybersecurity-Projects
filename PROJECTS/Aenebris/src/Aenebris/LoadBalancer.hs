{-# LANGUAGE RecordWildCards #-}

module Aenebris.LoadBalancer
  ( LoadBalancerStrategy(..)
  , LoadBalancer(..)
  , createLoadBalancer
  , selectBackend
  ) where

import Aenebris.Backend
import Control.Concurrent.STM
import Data.IORef
import Data.List (minimumBy, find)
import Data.Ord (comparing)
import qualified Data.Vector as V
import Data.Vector (Vector, (!))

-- | Load balancing strategy
data LoadBalancerStrategy
  = RoundRobin
  | LeastConnections
  | WeightedRoundRobin
  deriving (Eq, Show)

-- | Load balancer state
data LoadBalancer = LoadBalancer
  { lbBackends :: Vector RuntimeBackend
  , lbStrategy :: LoadBalancerStrategy
  , lbRRCounter :: IORef Int  -- For round robin
  }

-- | Create a load balancer for given backends
createLoadBalancer :: LoadBalancerStrategy -> [RuntimeBackend] -> IO LoadBalancer
createLoadBalancer strategy backends = do
  counter <- newIORef 0
  return LoadBalancer
    { lbBackends = V.fromList backends
    , lbStrategy = strategy
    , lbRRCounter = counter
    }

-- | Select a backend using the configured strategy
selectBackend :: LoadBalancer -> IO (Maybe RuntimeBackend)
selectBackend lb =
  case lbStrategy lb of
    RoundRobin -> selectRoundRobin lb
    LeastConnections -> selectLeastConnections lb
    WeightedRoundRobin -> selectWeightedRR lb

-- Round-Robin Implementation (IORef-based, fastest)
selectRoundRobin :: LoadBalancer -> IO (Maybe RuntimeBackend)
selectRoundRobin LoadBalancer{..} = do
  let backends = lbBackends
      len = V.length backends

  if len == 0
    then return Nothing
    else do
      -- Get next index
      idx <- atomicModifyIORef' lbRRCounter $ \i ->
        let next = (i + 1) `mod` len
        in (next, i)

      -- Find next healthy backend (try all, wrapping around)
      findHealthyBackend backends idx len

-- | Find next healthy backend starting from index
findHealthyBackend :: Vector RuntimeBackend -> Int -> Int -> IO (Maybe RuntimeBackend)
findHealthyBackend backends startIdx totalBackends =
  go startIdx totalBackends
  where
    len = V.length backends

    go currentIdx remaining
      | remaining <= 0 = return Nothing  -- Tried all, none healthy
      | otherwise = do
          let backend = backends ! currentIdx
          healthy <- atomically $ isHealthy backend

          if healthy
            then return (Just backend)
            else go ((currentIdx + 1) `mod` len) (remaining - 1)


-- Least Connections Implementation (STM-based)
selectLeastConnections :: LoadBalancer -> IO (Maybe RuntimeBackend)
selectLeastConnections LoadBalancer{..} = atomically $ do
  let backends = V.toList lbBackends

  -- Filter to only healthy backends
  healthy <- filterM isHealthy backends

  case healthy of
    [] -> return Nothing
    backends' -> do
      -- Get connection counts for all healthy backends
      counts <- mapM getConnectionCount backends'

      -- Find backend with minimum connections
      let (_, minBackend) = minimumBy (comparing fst) (zip counts backends')

      return (Just minBackend)


-- Smooth Weighted Round-Robin (nginx algorithm, STM-based)
selectWeightedRR :: LoadBalancer -> IO (Maybe RuntimeBackend)
selectWeightedRR LoadBalancer{..} = atomically $ do
  let backends = V.toList lbBackends

  -- Filter to only healthy backends
  healthy <- filterM isHealthy backends

  case healthy of
    [] -> return Nothing
    backends' -> do
      -- Step 1: Increase each backend's current weight by its base weight
      forM_ backends' $ \rb -> do
        currentW <- readTVar (rbCurrentWeight rb)
        let newWeight = currentW + rbWeight rb
        writeTVar (rbCurrentWeight rb) newWeight

      -- Step 2: Select backend with maximum current weight
      weights <- mapM getCurrentWeight backends'
      let maxWeight = maximum weights
          selectedIdx = find (\i -> weights !! i == maxWeight) [0..length weights - 1]
          selected = backends' !! (fromMaybe 0 selectedIdx)

      -- Step 3: Reduce selected backend's current weight by total weight
      let totalWeight = sum (map rbWeight backends')
      currentW <- readTVar (rbCurrentWeight selected)
      writeTVar (rbCurrentWeight selected) (currentW - totalWeight)

      return (Just selected)

-- Helper: STM filter
filterM :: Monad m => (a -> m Bool) -> [a] -> m [a]
filterM _ [] = return []
filterM p (x:xs) = do
  b <- p x
  rest <- filterM p xs
  return $ if b then x : rest else rest

-- Helper: fromMaybe
fromMaybe :: a -> Maybe a -> a
fromMaybe def Nothing = def
fromMaybe _ (Just x) = x

-- Helper: forM_
forM_ :: Monad m => [a] -> (a -> m b) -> m ()
forM_ xs f = sequence_ (map f xs)
