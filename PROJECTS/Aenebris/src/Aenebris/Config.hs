{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Aenebris.Config
  ( Config(..)
  , ListenConfig(..)
  , TLSConfig(..)
  , SNIDomain(..)
  , Upstream(..)
  , Server(..)
  , HealthCheck(..)
  , Route(..)
  , PathRoute(..)
  , loadConfig
  , validateConfig
  ) where

import Control.Monad (when, forM_)
import Data.Aeson
import Data.Text (Text)
import qualified Data.Text as T
import Data.Yaml (decodeFileEither)
import GHC.Generics

-- | Main config structure
data Config = Config
  { configVersion :: Int
  , configListen :: [ListenConfig]
  , configUpstreams :: [Upstream]
  , configRoutes :: [Route]
  } deriving (Show, Eq, Generic)

instance FromJSON Config where
  parseJSON = withObject "Config" $ \v -> Config
    <$> v .: "version"
    <*> v .: "listen"
    <*> v .: "upstreams"
    <*> v .: "routes"

-- | Listen port configuration
data ListenConfig = ListenConfig
  { listenPort :: Int
  , listenTLS :: Maybe TLSConfig
  , listenRedirectHTTPS :: Maybe Bool  -- Redirect HTTP to HTTPS?
  } deriving (Show, Eq, Generic)

instance FromJSON ListenConfig where
  parseJSON = withObject "ListenConfig" $ \v -> ListenConfig
    <$> v .: "port"
    <*> v .:? "tls"
    <*> v .:? "redirect_https"

-- | TLS/SSL configuration (supports both single cert and SNI)
data TLSConfig = TLSConfig
  { tlsCert :: Maybe FilePath           -- Single cert (if not using SNI)
  , tlsKey :: Maybe FilePath            -- Single key (if not using SNI)
  , tlsSNI :: Maybe [SNIDomain]         -- SNI domains (multiple certs)
  , tlsDefaultCert :: Maybe FilePath    -- Default cert for SNI
  , tlsDefaultKey :: Maybe FilePath     -- Default key for SNI
  } deriving (Show, Eq, Generic)

instance FromJSON TLSConfig where
  parseJSON = withObject "TLSConfig" $ \v -> TLSConfig
    <$> v .:? "cert"
    <*> v .:? "key"
    <*> v .:? "sni"
    <*> v .:? "default_cert"
    <*> v .:? "default_key"

-- | SNI domain configuration
data SNIDomain = SNIDomain
  { sniDomain :: Text
  , sniCert :: FilePath
  , sniKey :: FilePath
  } deriving (Show, Eq, Generic)

instance FromJSON SNIDomain where
  parseJSON = withObject "SNIDomain" $ \v -> SNIDomain
    <$> v .: "domain"
    <*> v .: "cert"
    <*> v .: "key"

-- | Upstream backend definition
data Upstream = Upstream
  { upstreamName :: Text
  , upstreamServers :: [Server]
  , upstreamHealthCheck :: Maybe HealthCheck
  } deriving (Show, Eq, Generic)

instance FromJSON Upstream where
  parseJSON = withObject "Upstream" $ \v -> Upstream
    <$> v .: "name"
    <*> v .: "servers"
    <*> v .:? "health_check"

-- | Backend server with weight for load balancing
data Server = Server
  { serverHost :: Text
  , serverWeight :: Int
  } deriving (Show, Eq, Generic)

instance FromJSON Server where
  parseJSON = withObject "Server" $ \v -> Server
    <$> v .: "host"
    <*> v .: "weight"

-- | Health check configuration
data HealthCheck = HealthCheck
  { healthCheckPath :: Text
  , healthCheckInterval :: Text  -- e.g., "10s"
  } deriving (Show, Eq, Generic)

instance FromJSON HealthCheck where
  parseJSON = withObject "HealthCheck" $ \v -> HealthCheck
    <$> v .: "path"
    <*> v .: "interval"

-- | Route definition (virtual host + paths)
data Route = Route
  { routeHost :: Text
  , routePaths :: [PathRoute]
  } deriving (Show, Eq, Generic)

instance FromJSON Route where
  parseJSON = withObject "Route" $ \v -> Route
    <$> v .: "host"
    <*> v .: "paths"

-- | Path-based routing rule
data PathRoute = PathRoute
  { pathRoutePath :: Text
  , pathRouteUpstream :: Text
  , pathRouteRateLimit :: Maybe Text  -- e.g., "100/minute"
  } deriving (Show, Eq, Generic)

instance FromJSON PathRoute where
  parseJSON = withObject "PathRoute" $ \v -> PathRoute
    <$> v .: "path"
    <*> v .: "upstream"
    <*> v .:? "rate_limit"

-- | Load configuration from YAML file
loadConfig :: FilePath -> IO (Either String Config)
loadConfig path = do
  result <- decodeFileEither path
  return $ case result of
    Left err -> Left (show err)
    Right config -> Right config

-- | Validate configuration for correctness
validateConfig :: Config -> Either String ()
validateConfig config = do
  -- Check version
  when (configVersion config /= 1) $
    Left "Unsupported config version (expected: 1)"

  -- Check at least one listen port
  when (null $ configListen config) $
    Left "At least one listen port must be specified"

  -- Check port numbers are valid
  forM_ (configListen config) $ \listen -> do
    let port = listenPort listen
    when (port < 1 || port > 65535) $
      Left $ "Invalid port number: " ++ show port

    -- Validate TLS configuration if present
    case listenTLS listen of
      Nothing -> return ()
      Just tlsConf -> validateTLS tlsConf

  -- Check at least one upstream
  when (null $ configUpstreams config) $
    Left "At least one upstream must be specified"

  -- Check upstream names are unique
  let upstreamNames = map upstreamName (configUpstreams config)
  when (length upstreamNames /= length (nubText upstreamNames)) $
    Left "Upstream names must be unique"

  -- Check each upstream has at least one server
  forM_ (configUpstreams config) $ \upstream -> do
    when (null $ upstreamServers upstream) $
      Left $ "Upstream '" ++ T.unpack (upstreamName upstream) ++ "' has no servers"

    -- Check server weights are positive
    forM_ (upstreamServers upstream) $ \server -> do
      when (serverWeight server < 1) $
        Left $ "Server weight must be positive: " ++ T.unpack (serverHost server)

  -- Check at least one route
  when (null $ configRoutes config) $
    Left "At least one route must be specified"

  -- Validate upstream references in routes
  forM_ (configRoutes config) $ \route -> do
    when (null $ routePaths route) $
      Left $ "Route for host '" ++ T.unpack (routeHost route) ++ "' has no paths"

    forM_ (routePaths route) $ \pathRoute -> do
      let upstreamRef = pathRouteUpstream pathRoute
      when (upstreamRef `notElem` upstreamNames) $
        Left $ "Unknown upstream referenced: '" ++ T.unpack upstreamRef ++ "'"

  return ()
  where
    -- Helper to remove duplicates from Text list
    nubText :: [Text] -> [Text]
    nubText [] = []
    nubText (x:xs) = x : nubText (filter (/= x) xs)

    -- Validate TLS configuration
    validateTLS :: TLSConfig -> Either String ()
    validateTLS tlsConf = do
      let hasSingleCert = case (tlsCert tlsConf, tlsKey tlsConf) of
            (Just _, Just _) -> True
            (Nothing, Nothing) -> False
            _ -> False  -- One is set but not the other

          hasSNI = case (tlsSNI tlsConf, tlsDefaultCert tlsConf, tlsDefaultKey tlsConf) of
            (Just sniDomains, Just _, Just _) -> not (null sniDomains)
            _ -> False

      -- Must have either single cert or SNI configuration
      when (not hasSingleCert && not hasSNI) $
        Left "TLS configuration must specify either (cert + key) or (sni + default_cert + default_key)"

      -- Can't have both single cert and SNI
      when (hasSingleCert && hasSNI) $
        Left "TLS configuration cannot have both single cert and SNI configuration"

      -- If single cert, ensure both cert and key are present
      when (hasSingleCert) $ do
        case (tlsCert tlsConf, tlsKey tlsConf) of
          (Just _, Nothing) -> Left "TLS cert specified but key missing"
          (Nothing, Just _) -> Left "TLS key specified but cert missing"
          _ -> return ()

      -- If SNI, ensure default cert/key are present
      when (hasSNI) $ do
        case (tlsDefaultCert tlsConf, tlsDefaultKey tlsConf) of
          (Just _, Nothing) -> Left "SNI default_cert specified but default_key missing"
          (Nothing, Just _) -> Left "SNI default_key specified but default_cert missing"
          (Nothing, Nothing) -> Left "SNI configuration requires default_cert and default_key"
          _ -> return ()

      return ()
