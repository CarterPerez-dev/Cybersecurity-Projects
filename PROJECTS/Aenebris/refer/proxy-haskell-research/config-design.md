# Configuration Language Design for Haskell Applications

**Haskell's strong type system and functional programming paradigm demand configuration approaches that balance safety, flexibility, and developer experience.** This research reveals that while traditional formats like YAML and TOML remain popular, Dhall's type-safe approach and modern hot-reload patterns offer compelling advantages for production systems. The choice depends critically on project scale, team expertise, and operational requirements.

## Configuration format comparison reveals distinct trade-offs

The Haskell ecosystem supports four primary approaches to configuration, each with unique characteristics suited to different use cases. **YAML dominates adoption due to mature tooling and ecosystem compatibility, yet introduces runtime risks absent from type-safe alternatives.** TOML offers explicit typing and bidirectional safety through innovative libraries like tomland. Dhall provides compile-time guarantees at the cost of verbosity. Custom DSLs enable domain-specific optimization but demand significant maintenance investment.

### YAML: Mature but type-unsafe

The yaml library (built on libyaml C bindings) integrates seamlessly with aeson for JSON-compatible types, making it the default choice for Stack, Cabal, and most Haskell infrastructure tools. **With ~1000 lines of parser code, it parses medium files in 300-850 μs**, providing excellent performance for most applications. HsYAML offers a pure Haskell alternative with YAML 1.2 compliance, crucial for GHCJS/Eta compatibility.

**Critical pitfall: the Norway Problem.** YAML's implicit typing causes `NO` to parse as boolean `False`, `010` as octal `8`, and `12:34:56` as seconds (45296). These silent failures have caused production incidents. Additional concerns include indentation sensitivity leading to subtle bugs, security vulnerabilities from complex anchor processing, and complete absence of schema validation until runtime.

```haskell
{-# LANGUAGE DeriveGeneric #-}
import Data.Yaml
import Data.Aeson (FromJSON, ToJSON)

data DatabaseConfig = DatabaseConfig
  { host :: String
  , port :: Int
  , maxConnections :: Int
  , sslMode :: Bool
  } deriving (Show, Generic, FromJSON, ToJSON)

-- Type checking only at runtime
loadConfig :: IO (Either ParseException DatabaseConfig)
loadConfig = decodeFileEither "database.yaml"
```

**Recommended for:** Existing projects with established YAML infrastructure, simple applications where quick setup outweighs safety concerns, configurations under 100 lines where complexity remains manageable.

### TOML: Explicit and bidirectional

The tomland library revolutionizes TOML handling through bidirectional codecs using advanced Haskell techniques (GADTs, Category theory, Monadic profunctors). **This architecture ensures encode/decode logic stays synchronized, eliminating an entire class of serialization bugs.** Benchmarks show tomland parses in 305.5 μs with transformation taking just 1.280 μs—faster than alternatives while providing stronger guarantees.

```haskell
import Toml (TomlCodec, (.=))
import qualified Toml

data ServerConfig = ServerConfig
  { serverHost :: Text
  , serverPort :: Natural
  , serverTimeout :: Maybe Natural
  } deriving (Show, Generic)

-- Single definition for both directions
serverCodec :: TomlCodec ServerConfig
serverCodec = ServerConfig
  <$> Toml.text "host" .= serverHost
  <*> Toml.int "port" .= serverPort
  <*> Toml.dioptional (Toml.int "timeout") .= serverTimeout

main = do
  config <- Toml.decodeFileEither serverCodec "server.toml"
  -- Encoding uses same codec - guaranteed consistency
  Toml.encodeToFile serverCodec "output.toml" myConfig
```

**Advantages:** No indentation issues, explicit string quoting eliminates ambiguity, easier version control diffs, compile-time codec verification. **Limitations:** Verbose for nested structures, smaller ecosystem than YAML, steeper learning curve due to advanced Haskell concepts, arrays-of-arrays-of-objects unsupported (tomland issue #373).

**Recommended for:** New CLI tools, configurations under ~100 lines, teams prioritizing explicitness, projects requiring guaranteed encode/decode consistency.

### Dhall: Type safety as foundational principle

Dhall represents a paradigm shift—a non-Turing-complete functional language specifically designed for configuration. **As the only option providing both compile-time type checking and guaranteed termination, Dhall eliminates entire categories of configuration errors before deployment.** The Haskell implementation serves as the reference, ensuring seamless integration via Generic deriving.

```dhall
-- types.dhall
let DatabaseConfig = 
  { Type = 
    { host : Text
    , port : Natural
    , maxConnections : Natural
    , replica : Optional DatabaseConfig.Type
    }
  , default = 
    { host = "localhost"
    , port = 5432
    , maxConnections = 20
    , replica = None DatabaseConfig.Type
    }
  }

-- production.dhall
let DB = ./types.dhall
let staging = ./staging.dhall

in DB::{ 
  , host = "prod-db.internal"
  , port = 5432
  , maxConnections = 100
  , replica = Some staging
  } : DB.Type
```

**Production validation:** meshcloud reports **50% reduction in configuration files** and **measurably reduced deployment defects** after adopting Dhall for their multi-cloud platform. They now compile and type-check all customer configs before rollout, generating Terraform, Ansible, Kubernetes, Spring configs, and Concourse CI definitions from a single source of truth.

The type system provides genuine safety:

```haskell
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}
import Dhall

data Config = Config
  { database :: DatabaseConfig
  , apiKeys :: [APIKey]
  , features :: Features
  } deriving (Generic, FromDhall, ToDhall)

-- Type errors caught at config-load time, not runtime
main = do
  config <- input auto "./config.dhall" :: IO Config
  -- Guaranteed valid if this succeeds
```

**Critical limitations:** Performance overhead makes it unsuitable for hot-path loading (1-3 orders of magnitude slower than YAML), verbose syntax with required type annotations and `Some` for optionals, smaller ecosystem requiring manual schema creation, steep learning curve for non-functional programmers. **The Dhall team acknowledges it's overkill for ~10 line configs.**

**Recommended for:** Large-scale infrastructure (Kubernetes, Terraform, CloudFormation), multi-environment deployments sharing base configuration, CI/CD pipelines where correctness is paramount, configurations with repetitive patterns benefiting from functions.

### Custom DSLs: Maximum control, maximum cost

Building custom DSLs offers complete syntax control and domain-specific validation but demands substantial investment. Three approaches exist: embedded DSLs using Haskell syntax directly, parser combinators (Megaparsec, Parsec, Attoparsec) for custom grammars, or Template Haskell QuasiQuoters for compile-time parsing.

```haskell
-- Embedded DSL approach
data ServiceConfig = ServiceConfig
  { routes :: [Route]
  , middleware :: [Middleware]
  }

-- Type-safe DSL in Haskell
myService :: ServiceConfig
myService = ServiceConfig
  { routes = 
    [ route "/api" GET apiHandler
    , route "/health" GET healthCheck
    ]
  , middleware = 
    [ cors allowAll
    , logging Verbose
    , auth jwtValidator
    ]
  }
```

```haskell
-- Parser combinator approach with Megaparsec
import Text.Megaparsec

type Parser = Parsec Void Text

configItem :: Parser ConfigItem
configItem = choice
  [ serverItem
  , databaseItem
  , featureFlag
  ]

serverItem :: Parser ConfigItem
serverItem = do
  symbol "server"
  host <- lexeme identifier
  port <- lexeme L.decimal
  pure $ ServerItem host port
```

**Real-world success:** Servant's type-level DSL for APIs demonstrates embedded DSL power—single specification generates client, server, and documentation. Dhall itself proves custom parsers can succeed at scale (~4000 LOC before error messages).

**Recommended for:** Domain-specific needs unmet by general formats, compile-time guarantees beyond type safety, embedding configuration in code, projects with dedicated tooling resources. **Not recommended for:** Simple applications, teams without DSL expertise, rapid prototyping, standard configuration needs.

## Comprehensive format comparison

| Criterion | YAML | TOML | Dhall | Custom DSL |
|-----------|------|------|-------|------------|
| **Type Safety** | Runtime only | Runtime + codec verification | Compile-time | Compile-time (if embedded) |
| **Learning Curve** | Easiest | Easy | Moderate-Hard | Hard |
| **Ecosystem Maturity** | Excellent (largest) | Good | Growing | N/A (build yourself) |
| **Performance** | 300-850 μs (C bindings) | 305 μs | Slower (type checking) | Varies |
| **DRY Support** | None | None | Functions + imports | Full control |
| **Error Messages** | Basic | Good | Excellent (verbose) | Depends on implementation |
| **Indentation Sensitive** | Yes (error-prone) | No | No | Configurable |
| **Schema Validation** | External (yamllint) | Codec definition | Built-in types | Custom |
| **Multi-language** | Yes | Yes | Yes | Usually no |
| **Maintenance Burden** | Low | Low | Low-Medium | High |
| **Best For** | Existing projects | New CLI tools | Large infrastructure | Specific domains |

## Type-safe configuration through Dhall

Dhall's type system fundamentally differs from runtime validation—**it prevents invalid configurations from existing rather than detecting them after creation.** Built on simply-typed lambda calculus, Dhall guarantees termination (non-Turing-complete), type soundness (well-typed programs cannot crash), and sandboxing (only permitted side effect is imports).

### Type system mechanics

Dhall's primitives include `Bool`, `Natural`, `Integer`, `Double`, `Text`, with composite types including records, lists, optionals, and unions. **Functions are first-class with explicit type abstraction**, enabling polymorphism while maintaining simplicity:

```dhall
-- Type annotation enforced
let makeEndpoint : Text → Natural → { url : Text, port : Natural } =
  λ(host : Text) → λ(port : Natural) →
    { url = "https://" ++ host, port = port }

-- Polymorphic function
let identity : ∀(a : Type) → a → a =
  λ(a : Type) → λ(x : a) → x

-- Type-safe record construction
let Config : Type = 
  { apiKey : Text
  , endpoints : List { url : Text, port : Natural }
  , retries : Optional Natural
  }
```

**Integration pattern showing automatic marshaling:**

```haskell
{-# LANGUAGE DeriveGeneric, DeriveAnyClass, DerivingVia #-}
import Dhall
import Dhall.Deriving

-- Automatic Generic deriving
data Config = Config
  { apiKey :: Text
  , endpoints :: [Endpoint]
  , retries :: Maybe Natural
  } deriving (Generic, Show, FromDhall, ToDhall)

-- Custom field mapping with DerivingVia
data APIConfig = APIConfig
  { apiConfigKey :: Text
  , apiConfigSecret :: Text
  } deriving stock (Generic, Show)
    deriving (FromDhall, ToDhall)
    via Codec (Field (CamelCase <<< DropPrefix "apiConfig")) APIConfig
```

### Real-world adoption validates approach

**Bellroy** uses Dhall for AWS CloudFormation (dhall-aws-cloudformation), GitHub Actions (github-actions-dhall), and Backstage configuration. **Earnest Research** open-sourced dhall-packages library for Kubernetes infrastructure. **Formation.ai** built custom DSL with additional Dhall built-ins for their multi-cloud platform.

**Critical insight:** Christine Dodrill (Tailscale) states "Dhall is probably the most viable replacement for Helm and other Kubernetes templating tools." This validates Dhall's sweet spot—large-scale infrastructure where configuration complexity and error costs justify the learning investment.

### Limitations require awareness

**Recursive types hit termination guarantees.** Using Generic-derived FromDhall on mutually recursive types causes non-termination. Workaround requires dhall-recursive-adt package with recursion-schemes—added complexity for advanced use cases.

**Performance characteristics matter.** Initial load of large schemas (Kubernetes types) can take hours without caching. Semantic integrity checks enable caching but require manual hash verification on first import. This makes Dhall **unsuitable for hot-path runtime config loading** but excellent for build-time generation.

**Verbosity trades against safety.** Type annotations everywhere, `Some` wrapping all optional values, explicit types for empty lists (`[] : List Natural`)—all increase noise compared to YAML's terseness. Teams must decide if this overhead pays for itself through prevented errors.

## Hot reload implementation strategies

Modern applications require configuration updates without restarts for high availability and rapid iteration. **Haskell's concurrency primitives (IORef, MVar, TVar) combined with file watching libraries enable robust hot reload with atomic guarantees.** The key challenge lies in preventing partial config loads and race conditions.

### File watching approaches

**fsnotify** provides unified cross-platform file system notifications, using native OS mechanisms (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) with automatic polling fallback. With 21 dependencies and active maintenance, it's the ecosystem standard:

```haskell
import System.FSNotify
import Control.Concurrent (threadDelay)
import Control.Monad (forever)

-- Basic file watching
watchConfigFile :: IO ()
watchConfigFile = withManager $ \mgr -> do
  watchDir
    mgr
    "."
    (\event -> "config.yaml" `isSuffixOf` eventPath event)
    handleConfigChange
  
  forever $ threadDelay 1000000

handleConfigChange :: Event -> IO ()
handleConfigChange event = do
  putStrLn $ "Config changed: " ++ show event
  reloadConfig
```

**Configuration options** enable platform-specific tuning:

```haskell
data WatchConfig = WatchConfig
  { confWatchMode :: WatchMode          -- OS native or polling
  , confThreadingMode :: ThreadingMode   -- Single or pool
  , confOnHandlerException :: SomeException -> IO ()
  }

-- Use polling on BSD, native elsewhere
customConfig :: WatchConfig
customConfig = defaultConfig
  { confWatchMode = WatchModeOS
  , confThreadingMode = ThreadPool 4
  , confOnHandlerException = logError
  }

withManagerConf customConfig $ \mgr -> ...
```

**hinotify** offers Linux-specific inotify bindings with lower overhead but platform lock-in. **rapid** enables hot reload with reload-surviving values in GHCi for development. **twitch** provides a monadic DSL wrapping fsnotify for declarative file watching.

### Atomic swap techniques eliminate race conditions

**IORef provides single-pointer atomicity** through hardware compare-and-swap instructions. The `atomicModifyIORef` function guarantees no interference between read and write:

```haskell
import Data.IORef
import Data.Aeson

data AppConfig = AppConfig
  { database :: DatabaseConfig
  , features :: FeatureFlags
  , apiKeys :: [APIKey]
  } deriving (Generic, FromJSON)

-- Config stored in IORef for atomic updates
type ConfigRef = IORef AppConfig

-- Atomic config reload
reloadConfig :: ConfigRef -> FilePath -> IO (Either String ())
reloadConfig configRef path = do
  result <- eitherDecodeFileStrict path
  case result of
    Left err -> return $ Left $ "Parse error: " ++ err
    Right newConfig -> do
      -- Atomic swap - no partial updates visible
      atomicModifyIORef' configRef $ \oldConfig ->
        (newConfig, ())
      return $ Right ()

-- Thread-safe read
getConfig :: ConfigRef -> IO AppConfig
getConfig = readIORef  -- Always sees complete config
```

**Critical detail:** `atomicModifyIORef'` (strict version) prevents thunk buildup. The lazy `atomicModifyIORef` can cause stack overflow if many modifications occur without reads.

**MVar adds blocking semantics** useful for coordination but susceptible to deadlocks. Documentation warns: "Do not use them if you need to perform larger atomic operations such as reading from multiple variables: use STM instead."

```haskell
import Control.Concurrent.MVar

-- MVar can be empty (useful for initialization)
type ConfigMVar = MVar AppConfig

reloadWithMVar :: ConfigMVar -> FilePath -> IO (Either String ())
reloadWithMVar configVar path = do
  result <- eitherDecodeFileStrict path
  case result of
    Left err -> return $ Left err
    Right newConfig -> do
      -- Take old config, put new one
      -- Blocks readers during update
      _ <- tryTakeMVar configVar
      putMVar configVar newConfig
      return $ Right ()
```

**TVar enables composable transactions** through Software Transactional Memory:

```haskell
import Control.Concurrent.STM

type ConfigTVar = TVar AppConfig

-- Compose multiple config updates atomically
updateConfigs :: TVar AppConfig -> TVar CacheConfig -> IO ()
updateConfigs appVar cacheVar = atomically $ do
  app <- readTVar appVar
  cache <- readTVar cacheVar
  
  -- Both updates happen atomically or retry
  writeTVar appVar (app { maxConnections = 100 })
  writeTVar cacheVar (cache { ttl = 3600 })

-- STM automatically retries on conflicts
reloadWithSTM :: ConfigTVar -> FilePath -> IO (Either String ())
reloadWithSTM configVar path = do
  result <- eitherDecodeFileStrict path
  case result of
    Left err -> return $ Left err
    Right newConfig -> do
      atomically $ writeTVar configVar newConfig
      return $ Right ()
```

### Complete hot reload implementation

```haskell
{-# LANGUAGE DeriveGeneric #-}
import System.FSNotify
import Data.IORef
import Data.Aeson
import Control.Exception
import Control.Concurrent

data AppConfig = AppConfig
  { database :: DatabaseConfig
  , apiKeys :: [Text]
  , features :: Map Text Bool
  } deriving (Generic, FromJSON, ToJSON)

data ConfigManager = ConfigManager
  { currentConfig :: IORef AppConfig
  , lastValidConfig :: IORef AppConfig  -- Rollback target
  , configPath :: FilePath
  , watchManager :: WatchManager
  }

-- Initialize config manager with hot reload
initConfigManager :: FilePath -> IO (Either String ConfigManager)
initConfigManager path = do
  result <- eitherDecodeFileStrict path
  case result of
    Left err -> return $ Left $ "Initial load failed: " ++ err
    Right config -> do
      currentRef <- newIORef config
      lastValidRef <- newIORef config
      
      mgr <- startManager
      
      let manager = ConfigManager currentRef lastValidRef path mgr
      
      -- Start watching
      _ <- watchDir mgr (takeDirectory path) 
           (matchesFile path) 
           (handleReload manager)
      
      return $ Right manager
  where
    matchesFile target event = target == eventPath event

-- Handle reload with validation and rollback
handleReload :: ConfigManager -> Event -> IO ()
handleReload manager event = do
  result <- tryReload (configPath manager)
  case result of
    Right newConfig -> do
      -- Validate before applying
      if validateConfig newConfig
        then do
          -- Save current as last valid
          current <- readIORef (currentConfig manager)
          writeIORef (lastValidConfig manager) current
          
          -- Atomic swap to new config
          atomicWriteIORef (currentConfig manager) newConfig
          
          logInfo "Config reloaded successfully"
        else
          logError "Validation failed, keeping old config"
    
    Left err -> do
      logError $ "Reload failed: " ++ err
      -- Keep running with old config
  where
    tryReload :: FilePath -> IO (Either String AppConfig)
    tryReload path = 
      catch (eitherDecodeFileStrict path)
            (\(e :: SomeException) -> return $ Left $ show e)
    
    validateConfig :: AppConfig -> Bool
    validateConfig cfg = 
      -- Custom validation logic
      not (null $ apiKeys cfg) 
      && all isValidEndpoint (databaseEndpoints $ database cfg)

-- Access config safely from multiple threads
withConfig :: ConfigManager -> (AppConfig -> IO a) -> IO a
withConfig manager action = do
  config <- readIORef (currentConfig manager)
  action config
```

### Performance considerations

**File watching overhead** is negligible—fsnotify uses efficient OS mechanisms. Debouncing prevents rapid-fire reloads:

```haskell
-- Debounce rapid changes
debounceReload :: IORef UTCTime -> NominalDiffTime -> IO () -> IO ()
debounceReload lastReloadRef minInterval action = do
  now <- getCurrentTime
  lastReload <- readIORef lastReloadRef
  
  when (diffUTCTime now lastReload > minInterval) $ do
    writeIORef lastReloadRef now
    action
```

**Config reload frequency** should match operational needs. Database configs might reload hourly, feature flags every few seconds. **Connection pools require special handling**—drain gracefully when credentials change:

```haskell
-- Coordinate pool and config updates
data DatabasePool = DatabasePool
  { pool :: Pool Connection
  , credentials :: IORef Credentials
  }

rotatePoolCredentials :: DatabasePool -> Credentials -> IO ()
rotatePoolCredentials dbPool newCreds = do
  atomicWriteIORef (credentials dbPool) newCreds
  
  -- Drain old connections gradually
  -- New connections use new credentials from IORef
  drainPool (pool dbPool) gracefulDrainSeconds
```

## Validation strategies balance safety and availability

Configuration validation represents a critical decision point—**fail fast to prevent invalid states or degrade gracefully to maintain availability.** The optimal strategy depends on service criticality, failure costs, and operational context.

### Fail-fast: Immediate termination on invalid config

Fail-fast prevents application startup or config reload with invalid data, ensuring consistency. **This approach suits security-sensitive applications, financial systems, and development environments where errors should surface immediately:**

```haskell
import Refined
import Refined.Unsafe

-- Type-level validation with refined
type Port = Refined (FromTo 1 65535) Int
type NonEmptyText = Refined (SizeGreaterThan 0) Text

data ServerConfig = ServerConfig
  { port :: Port
  , host :: NonEmptyText
  , workers :: Refined Positive Int
  } deriving (Show, Generic)

-- Smart constructor pattern
newtype DatabasePassword = DatabasePassword Text

mkDatabasePassword :: Text -> Maybe DatabasePassword
mkDatabasePassword pwd
  | T.length pwd >= 8 = Just $ DatabasePassword pwd
  | otherwise = Nothing

-- Fails at construction if invalid
loadConfigFailFast :: FilePath -> IO ServerConfig
loadConfigFailFast path = do
  result <- eitherDecodeFileStrict path
  case result of
    Left err -> error $ "Config invalid: " ++ err
    Right config -> do
      -- Additional semantic validation
      when (workers config > 1000) $
        error "Worker count exceeds limit"
      return config
```

**Validation library** enables error accumulation:

```haskell
import Data.Validation

data ValidationError = 
    InvalidPort Int
  | MissingField Text
  | InvalidFormat Text Text
  deriving Show

validateConfig :: RawConfig -> Validation [ValidationError] Config
validateConfig raw = Config
  <$> validatePort (rawPort raw)
  <*> validateHost (rawHost raw)
  <*> validateWorkers (rawWorkers raw)
  where
    validatePort p
      | p > 0 && p < 65536 = Success p
      | otherwise = Failure [InvalidPort p]
    
    validateHost h
      | not (T.null h) = Success h
      | otherwise = Failure [MissingField "host"]
```

### Graceful degradation: Availability over consistency

Graceful degradation uses defaults and partial configs to keep services running despite invalid configuration. **High-availability services, optional features, and non-critical settings benefit from this approach:**

```haskell
data ConfigWithDefaults = ConfigWithDefaults
  { coreSettings :: CoreConfig      -- Required, fail if invalid
  , optionalFeatures :: Features    -- Use defaults on error
  , experimentalFlags :: Map Text Bool  -- Ignore invalid entries
  }

loadConfigGraceful :: FilePath -> IO ConfigWithDefaults
loadConfigGraceful path = do
  result <- eitherDecodeFileStrict path
  case result of
    Left err -> do
      logWarning $ "Config parse error, using defaults: " ++ err
      return defaultConfig
    
    Right rawConfig -> do
      -- Core settings must be valid
      core <- case validateCore rawConfig of
        Left errors -> error $ "Core config invalid: " ++ show errors
        Right validated -> return validated
      
      -- Optional features use defaults on error
      features <- case validateFeatures rawConfig of
        Left errors -> do
          logWarning $ "Feature config invalid, using defaults: " ++ show errors
          return defaultFeatures
        Right validated -> return validated
      
      -- Experimental flags filter out invalid entries
      let flags = filterValidFlags (rawExperimental rawConfig)
      
      return $ ConfigWithDefaults core features flags
```

**Environment variable handling** demonstrates graceful fallbacks:

```haskell
import System.Envy

data EnvConfig = EnvConfig
  { databaseUrl :: String
  , redisUrl :: String
  , logLevel :: LogLevel
  } deriving (Generic, Show)

instance FromEnv EnvConfig

instance DefConfig EnvConfig where
  defConfig = EnvConfig
    { databaseUrl = "postgresql://localhost/dev"
    , redisUrl = "redis://localhost:6379"
    , logLevel = Info
    }

-- Combines env vars with defaults
loadWithDefaults :: IO EnvConfig
loadWithDefaults = do
  result <- decodeWithDefaults
  case result of
    Left err -> do
      logWarning $ "Env var error, using defaults: " ++ err
      return defConfig
    Right config -> return config
```

### Parser-based validation with aeson

**Aeson's FromJSON typeclass** enables validation during parsing:

```haskell
instance FromJSON ServerConfig where
  parseJSON = withObject "ServerConfig" $ \o -> do
    rawPort <- o .: "port"
    when (rawPort < 1 || rawPort > 65535) $
      fail $ "Invalid port: " ++ show rawPort
    
    host <- o .: "host"
    when (T.null host) $
      fail "Host cannot be empty"
    
    workers <- o .:? "workers" .!= 4  -- Default to 4
    when (workers < 1 || workers > 1000) $
      fail $ "Invalid worker count: " ++ show workers
    
    return $ ServerConfig rawPort host workers
```

### Runtime vs compile-time validation trade-offs

| Aspect | Compile-Time | Runtime |
|--------|-------------|---------|
| **Error Detection** | Before execution | During execution |
| **Performance** | Zero overhead | Validation cost |
| **Flexibility** | Static only | Handles dynamic input |
| **Implementation** | Refined + TH, Dependent types | Smart constructors, parsers |
| **Use Cases** | Constants, known values | File loading, user input |
| **Guarantees** | Type system enforced | Must validate explicitly |

**Hybrid approach** leverages both:

```haskell
data Config = Config
  { staticPort :: Refined (FromTo 1 65535) Int  -- Compile-time
  , dynamicEndpoints :: [Endpoint]              -- Runtime validated
  }

-- Compile-time validated constant
defaultPort :: Refined (FromTo 1 65535) Int
defaultPort = $$(refineTH 8080)  -- Fails at compile if invalid

-- Runtime validation
loadConfig :: FilePath -> IO (Either String Config)
loadConfig path = do
  result <- eitherDecodeFileStrict path
  case result of
    Left err -> return $ Left err
    Right raw -> do
      validated <- validateEndpoints (rawEndpoints raw)
      case validated of
        Left errors -> return $ Left $ show errors
        Right endpoints -> return $ Right $ Config defaultPort endpoints
```

## Environment variable interpolation and precedence

Modern applications require flexible configuration sourcing with **clear precedence hierarchies and secure interpolation.** The 12-factor app methodology advocates storing config in environment variables for language/OS-agnostic configuration and strict separation from code.

### Interpolation syntax and implementation

Common patterns include `${VAR}` (explicit), `${VAR:-default}` (with fallback), and `$VAR` (shell-style). **Security demands validating after interpolation and preventing injection attacks:**

```haskell
import System.Environment
import Text.Regex.TDFA
import qualified Data.Text as T

-- Safe interpolation
interpolateEnvVars :: Text -> IO (Either String Text)
interpolateEnvVars template = do
  let matches = getAllTextMatches $ template =~ ("\\$\\{[A-Z_][A-Z0-9_]*\\}" :: String)
  foldM replaceVar (Right template) matches
  where
    replaceVar :: Either String Text -> Text -> IO (Either String Text)
    replaceVar (Left err) _ = return $ Left err
    replaceVar (Right txt) match = do
      let varName = T.drop 2 $ T.dropEnd 1 match  -- Strip ${ }
      maybeValue <- lookupEnv (T.unpack varName)
      case maybeValue of
        Just value -> 
          return $ Right $ T.replace match (T.pack value) txt
        Nothing -> 
          return $ Left $ "Undefined variable: " ++ T.unpack varName

-- With defaults
interpolateWithDefaults :: Text -> IO Text
interpolateWithDefaults template = do
  let pattern = "\\$\\{([A-Z_][A-Z0-9_]*):-([^}]*)\\}"
      matches = getAllTextMatches $ template =~ (pattern :: String)
  foldM replaceWithDefault template matches
  where
    replaceWithDefault txt match = do
      let (varName, defaultVal) = parseMatch match
      value <- fromMaybe defaultVal <$> lookupEnv varName
      return $ T.replace match (T.pack value) txt
```

### Type-safe environment parsing with envy

```haskell
{-# LANGUAGE DeriveGeneric #-}
import System.Envy

data AppConfig = AppConfig
  { appDatabaseUrl :: String      -- DATABASE_URL
  , appRedisHost :: String        -- REDIS_HOST  
  , appPort :: Int                -- PORT
  , appDebug :: Bool              -- DEBUG
  , appLogLevel :: Maybe LogLevel -- LOG_LEVEL (optional)
  } deriving (Generic, Show)

instance FromEnv AppConfig

-- With custom defaults
instance DefConfig AppConfig where
  defConfig = AppConfig
    { appDatabaseUrl = "postgresql://localhost/dev"
    , appRedisHost = "localhost"
    , appPort = 8080
    , appDebug = False
    , appLogLevel = Nothing
    }

main :: IO ()
main = do
  config <- decodeWithDefaults :: IO AppConfig
  print config
```

### Precedence hierarchy implementation

**Standard precedence** (highest to lowest): Command-line arguments > Environment variables > Local config file > Project config > System config > Built-in defaults.

```haskell
import Options.Applicative
import qualified Data.Yaml as Y

data ConfigSource = 
    CLIConfig Config
  | EnvConfig Config  
  | FileConfig Config
  | DefaultConfig Config

-- Merge with precedence
mergeConfigs :: [ConfigSource] -> Config
mergeConfigs sources = foldl merge defaultConfig sources
  where
    merge :: Config -> ConfigSource -> Config
    merge base (CLIConfig cli) = base { port = port cli `orDefault` port base
                                       , host = host cli `orDefault` host base
                                       }
    merge base (EnvConfig env) = base { port = port env `orDefault` port base }
    merge base (FileConfig file) = base { port = port file `orDefault` port base }
    merge base (DefaultConfig _) = base
    
    orDefault :: Maybe a -> a -> a
    orDefault = fromMaybe

-- Complete loading strategy
loadLayeredConfig :: IO Config
loadLayeredConfig = do
  -- 1. Load defaults
  let defaults = defaultConfig
  
  -- 2. Load system config
  systemCfg <- loadSystemConfig `catch` \(_ :: IOException) -> return Nothing
  
  -- 3. Load project config  
  projectCfg <- loadProjectConfig `catch` \(_ :: IOException) -> return Nothing
  
  -- 4. Load local config
  localCfg <- Y.decodeFileEither "config.yaml" >>= \case
    Left _ -> return Nothing
    Right cfg -> return $ Just cfg
  
  -- 5. Load environment variables
  envCfg <- decodeEnv :: IO (Either String EnvConfig)
  let env = either (const Nothing) Just envCfg
  
  -- 6. Parse CLI args
  cliCfg <- execParser cliParser
  
  -- Merge with precedence
  return $ mergeConfigs 
    [ maybe DefaultConfig FileConfig systemCfg
    , maybe DefaultConfig FileConfig projectCfg  
    , maybe DefaultConfig FileConfig localCfg
    , maybe DefaultConfig EnvConfig env
    , CLIConfig cliCfg
    ]
```

### Security considerations for environment variables

```haskell
-- Prevent injection attacks
newtype SafeEnvValue = SafeEnvValue Text

-- Validate after interpolation
validateEnvValue :: Text -> Either String SafeEnvValue
validateEnvValue value
  | T.any isControlChar value = Left "Control characters not allowed"
  | T.any (== ';') value = Left "Semicolons not allowed"  
  | T.any (== '|') value = Left "Pipes not allowed"
  | otherwise = Right $ SafeEnvValue value
  where
    isControlChar c = c < ' ' && c /= '\t'

-- Redact secrets in logs
newtype Secret a = Secret { unSecret :: a }

instance Show (Secret a) where
  show _ = "<REDACTED>"

data SecureConfig = SecureConfig
  { dbPassword :: Secret Text
  , apiKey :: Secret Text
  , publicEndpoint :: Text  -- Not secret
  } deriving Show

-- Safe to log this config - secrets hidden
```

## Secrets management integration patterns

**Proper secrets management demands specialized solutions beyond configuration files.** HashiCorp Vault, AWS Secrets Manager, and cloud-native options provide encryption, rotation, auditing, and access control that flat files cannot match.

### HashiCorp Vault with gothic library

The gothic library (version 0.1.8.3) implements the complete KVv2 engine API with connection management, secret versioning, and metadata support:

```haskell
import Database.Vault.KVv2.Client

data AppSecrets = AppSecrets
  { databaseCredentials :: Credentials
  , apiKeys :: Map Text Text
  , certificates :: Map Text ByteString
  }

-- Connect with token authentication
connectVault :: IO (Either String VaultConnection)
connectVault = vaultConnect
  (Just "https://vault.internal:8200/")
  (KVEnginePath "/secret")
  Nothing  -- Uses ~/.vault-token or VAULT_TOKEN
  False    -- Enable TLS cert validation

-- Retrieve secrets
loadSecrets :: VaultConnection -> IO (Either String AppSecrets)
loadSecrets conn = do
  -- Get database credentials
  dbResult <- getSecret conn (SecretPath "myapp/database") Nothing
  
  -- Get API keys
  apiResult <- getSecret conn (SecretPath "myapp/api-keys") Nothing
  
  case (dbResult, apiResult) of
    (Right dbData, Right apiData) -> do
      let dbCreds = parseCredentials $ fromSecretData dbData
          keys = fromSecretData apiData
      return $ Right $ AppSecrets dbCreds keys mempty
    (Left err, _) -> return $ Left $ "Database secret error: " ++ err
    (_, Left err) -> return $ Left $ "API key error: " ++ err

-- Update secrets with versioning
updateSecret :: VaultConnection -> IO ()
updateSecret conn = do
  result <- putSecret
    conn
    NoCheckAndSet
    (SecretPath "myapp/database")
    (toSecretData [("password", newPassword), ("username", "admin")])
  
  case result of
    Right version -> putStrLn $ "Updated to version " ++ show version
    Left err -> putStrLn $ "Update failed: " ++ err
```

**AppRole authentication** (recommended for applications):

```haskell
-- vault-tool library approach
connectWithAppRole :: IO VaultConnection
connectWithAppRole = do
  let addr = VaultAddress "https://vault.internal:8200"
  conn <- connectToVaultAppRole
    addr
    (VaultAppRoleId "role-id-from-env")
    (VaultAppRoleSecretId "secret-id-from-env")
  return conn
```

### AWS Secrets Manager with amazonka

The amazonka-secretsmanager library (version 2.0) provides full AWS integration with IAM authentication:

```haskell
import Amazonka
import Amazonka.SecretsManager
import Amazonka.SecretsManager.GetSecretValue
import Control.Lens
import qualified Data.Aeson as A

data DatabaseConfig = DatabaseConfig
  { dbHost :: Text
  , dbPort :: Int
  , dbUsername :: Text
  , dbPassword :: Text
  } deriving (Generic, FromJSON)

-- Load secret from AWS Secrets Manager
loadDatabaseConfig :: IO (Either String DatabaseConfig)
loadDatabaseConfig = do
  -- Discover credentials (IAM role, env vars, etc.)
  env <- newEnv discover
  
  -- Request secret
  let req = newGetSecretValue "production/database"
  resp <- runResourceT $ send env req
  
  -- Extract and parse
  case resp ^. getSecretValueResponse_secretString of
    Just jsonString -> 
      case A.eitherDecode (encodeUtf8 jsonString) of
        Right config -> return $ Right config
        Left err -> return $ Left $ "Parse error: " ++ err
    Nothing -> return $ Left "No secret string found"

-- Trigger rotation
rotateSecret :: Text -> IO ()
rotateSecret secretId = do
  env <- newEnv discover
  
  let req = newRotateSecret secretId
        & rotateSecret_rotationLambdaARN ?~ lambdaArn
        & rotateSecret_rotationRules ?~ 
            newRotationRulesType
              & rotationRulesType_automaticallyAfterDays ?~ 30
  
  _ <- runResourceT $ send env req
  putStrLn "Rotation initiated"
```

**Required IAM permissions:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:*:*:key/*"
    }
  ]
}
```

### Rotation and zero-downtime patterns

**Dual-credential pattern** enables zero-downtime rotation:

```haskell
data RotatingCredentials = RotatingCredentials
  { currentCreds :: Credentials
  , previousCreds :: Maybe Credentials
  , rotationTime :: UTCTime
  }

-- Try current, fallback to previous
withRotatingCreds :: RotatingCredentials -> (Credentials -> IO a) -> IO a
withRotatingCreds rc action = do
  result <- tryAction (currentCreds rc)
  case result of
    Right r -> return r
    Left _ -> case previousCreds rc of
      Just prev -> action prev  -- Fallback during rotation window
      Nothing -> throwIO RotationError
  where
    tryAction creds = 
      catch (Right <$> action creds)
            (\(e :: SomeException) -> return $ Left e)

-- Automatic rotation loop
rotationLoop :: IORef RotatingCredentials -> VaultConnection -> IO ()
rotationLoop credsRef vault = forever $ do
  currentTime <- getCurrentTime
  creds <- readIORef credsRef
  
  when (shouldRotate currentTime (rotationTime creds)) $ do
    -- Fetch new credentials
    newCreds <- fetchDynamicCreds vault
    
    -- Update with both old and new
    atomicModifyIORef' credsRef $ \old ->
      (RotatingCredentials newCreds (Just $ currentCreds old) currentTime, ())
  
  threadDelay (5 * 60 * 1000000)  -- Check every 5 minutes

-- Vault dynamic secrets with lease renewal
requestDynamicCredentials :: VaultConnection -> IO DynamicDBCredentials
requestDynamicCredentials conn = do
  result <- vaultRead conn (VaultSecretPath "database/creds/readonly")
  
  case result of
    (metadata, Right creds) -> do
      -- Schedule renewal before expiration
      forkIO $ renewLeaseLoop conn (leaseId creds) (leaseDuration creds)
      return creds
    _ -> throwIO CredentialRequestFailed

renewLeaseLoop :: VaultConnection -> Text -> Int -> IO ()
renewLeaseLoop conn leaseId duration = do
  let renewInterval = duration `div` 2  -- Renew at halfway point
  threadDelay (renewInterval * 1000000)
  
  success <- renewLease conn leaseId
  if success
    then renewLeaseLoop conn leaseId duration  -- Continue renewing
    else logWarning "Lease renewal failed"
```

### Security best practices

```haskell
-- Never store secrets in code or config files
-- ❌ DON'T DO THIS
apiKey = "sk_live_abc123xyz"  

-- ✅ Load from secure source
loadSecrets :: IO Secrets

-- Use type system to prevent leakage
newtype DatabasePassword = DatabasePassword Text
  deriving Eq

instance Show DatabasePassword where
  show _ = "DatabasePassword <redacted>"

-- Prevents accidentally logging secrets
logConfig :: Config -> IO ()
logConfig cfg = logger $ show cfg  -- Passwords show as <redacted>

-- Scrubbed memory for sensitive data
import Data.ByteString.Scrub

withSecureString :: ByteString -> (ByteString -> IO a) -> IO a
withSecureString secret action = do
  scrubbed <- newScrubbedBytes secret
  result <- action scrubbed
  -- Memory automatically zeroed when GC'd
  return result
```

### Comparison of secrets management solutions

| Feature | Vault | AWS SM | GCP SM | K8s Secrets | Env Vars |
|---------|-------|--------|---------|-------------|----------|
| **Dynamic Secrets** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| **Automatic Rotation** | ✅ Yes | ✅ Yes | ✅ Yes | ❌ Manual | ❌ No |
| **Versioning** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| **Audit Logs** | ✅ Complete | ✅ CloudTrail | ✅ Cloud Logging | ✅ K8s logs | ❌ None |
| **Multi-cloud** | ✅ Yes | ❌ AWS only | ❌ GCP only | ✅ Yes | ✅ Yes |
| **Haskell Support** | ✅ gothic | ✅ amazonka | ⚠️ REST API | ✅ haskell-kubernetes | ✅ envy |
| **Encryption at Rest** | ✅ Yes | ✅ KMS | ✅ Yes | ⚠️ Optional | ❌ No |
| **Lease Management** | ✅ Built-in | ⚠️ Manual | ⚠️ Manual | N/A | N/A |
| **Cost** | Self-hosted | AWS pricing | GCP pricing | Cluster cost | Free |

## Example schemas and code patterns

### Database configuration with all patterns

**YAML approach:**

```yaml
# database.yaml
database:
  host: ${DB_HOST:-localhost}
  port: 5432
  name: production_db
  pool:
    min_connections: 10
    max_connections: 100
    idle_timeout: 60
  ssl:
    enabled: true
    mode: require
    ca_cert: /etc/ssl/ca.crt
  replicas:
    - host: replica1.internal
      port: 5432
    - host: replica2.internal
      port: 5432
```

```haskell
{-# LANGUAGE DeriveGeneric #-}
import Data.Yaml

data DatabaseConfig = DatabaseConfig
  { database :: DatabaseSettings
  } deriving (Generic, FromJSON)

data DatabaseSettings = DatabaseSettings
  { host :: String
  , port :: Int
  , name :: String
  , pool :: PoolConfig
  , ssl :: SSLConfig
  , replicas :: [ReplicaConfig]
  } deriving (Generic, FromJSON)
```

**TOML approach:**

```toml
# database.toml
[database]
host = "localhost"
port = 5432
name = "production_db"

[database.pool]
min_connections = 10
max_connections = 100
idle_timeout = 60

[database.ssl]
enabled = true
mode = "require"
ca_cert = "/etc/ssl/ca.crt"

[[database.replicas]]
host = "replica1.internal"
port = 5432

[[database.replicas]]
host = "replica2.internal"
port = 5432
```

```haskell
import Toml

data DatabaseConfig = DatabaseConfig
  { host :: Text
  , port :: Natural
  , pool :: PoolConfig
  , replicas :: [ReplicaConfig]
  } deriving (Show, Generic)

databaseCodec :: TomlCodec DatabaseConfig
databaseCodec = DatabaseConfig
  <$> Toml.text "database.host" .= host
  <*> Toml.int "database.port" .= port
  <*> poolCodec .= pool
  <*> Toml.list replicaCodec "database.replicas" .= replicas
```

**Dhall approach:**

```dhall
-- types/Database.dhall
let PoolConfig = { Type = 
  { minConnections : Natural
  , maxConnections : Natural
  , idleTimeout : Natural
  }
, default = 
  { minConnections = 5
  , maxConnections = 20
  , idleTimeout = 30
  }
}

let ReplicaConfig = { Type =
  { host : Text, port : Natural }
}

let DatabaseConfig = { Type =
  { host : Text
  , port : Natural
  , name : Text
  , pool : PoolConfig.Type
  , replicas : List ReplicaConfig.Type
  }
, default =
  { host = "localhost"
  , port = 5432
  , name = "app"
  , pool = PoolConfig.default
  , replicas = [] : List ReplicaConfig.Type
  }
}

in DatabaseConfig

-- config/production.dhall
let DB = ../types/Database.dhall

in DB::{ 
  , host = "prod-db.internal"
  , name = "production_db"
  , pool = DB.default.pool // { maxConnections = 100 }
  , replicas = 
    [ { host = "replica1.internal", port = 5432 }
    , { host = "replica2.internal", port = 5432 }
    ]
  }
```

### Feature flags with hot reload

```haskell
{-# LANGUAGE DeriveGeneric #-}
import Data.IORef
import Data.Aeson
import qualified Data.Map.Strict as Map

data FeatureFlags = FeatureFlags
  { enableNewUI :: Bool
  , maxUploadSize :: Int
  , allowedRegions :: [Text]
  , experimentalFeatures :: Map Text Bool
  } deriving (Generic, FromJSON, ToJSON, Show)

data FeatureFlagManager = FeatureFlagManager
  { flags :: IORef FeatureFlags
  , configPath :: FilePath
  }

-- Initialize with hot reload
initFeatureFlags :: FilePath -> IO FeatureFlagManager
initFeatureFlags path = do
  initial <- loadFeatureFlags path
  flagsRef <- newIORef initial
  
  let manager = FeatureFlagManager flagsRef path
  
  -- Watch for changes
  _ <- forkIO $ watchAndReload manager
  
  return manager
  where
    loadFeatureFlags :: FilePath -> IO FeatureFlags
    loadFeatureFlags p = do
      result <- eitherDecodeFileStrict p
      case result of
        Left err -> error $ "Failed to load feature flags: " ++ err
        Right flags -> return flags

-- Check feature flag (thread-safe)
isFeatureEnabled :: FeatureFlagManager -> Text -> IO Bool
isFeatureEnabled manager featureName = do
  currentFlags <- readIORef (flags manager)
  return $ Map.findWithDefault False featureName (experimentalFeatures currentFlags)

-- Use feature flag
withFeature :: FeatureFlagManager -> Text -> IO a -> IO a -> IO a
withFeature manager featureName enabledAction disabledAction = do
  enabled <- isFeatureEnabled manager featureName
  if enabled
    then enabledAction
    else disabledAction
```

### Multi-environment configuration

```haskell
data Environment = Development | Staging | Production
  deriving (Show, Eq, Generic, FromJSON)

data MultiEnvConfig = MultiEnvConfig
  { shared :: SharedConfig
  , environment :: Environment
  , envSpecific :: EnvironmentConfig
  } deriving (Show, Generic)

data SharedConfig = SharedConfig
  { appName :: Text
  , version :: Text
  , features :: [Text]
  } deriving (Show, Generic, FromJSON)

data EnvironmentConfig = EnvironmentConfig
  { database :: DatabaseConfig
  , cache :: CacheConfig
  , logLevel :: LogLevel
  , apiKeys :: Map Text Text
  } deriving (Show, Generic, FromJSON)

-- Load based on environment
loadConfig :: IO MultiEnvConfig
loadConfig = do
  -- Determine environment
  envVar <- lookupEnv "APP_ENV"
  let env = case envVar of
        Just "production" -> Production
        Just "staging" -> Staging
        _ -> Development
  
  -- Load shared config
  shared <- decodeFileThrow "config/shared.yaml"
  
  -- Load environment-specific config
  let envFile = case env of
        Development -> "config/development.yaml"
        Staging -> "config/staging.yaml"  
        Production -> "config/production.yaml"
  
  envSpecific <- decodeFileThrow envFile
  
  -- Merge with env vars (highest precedence)
  envOverrides <- decodeEnv :: IO (Either String EnvOverrides)
  
  let finalConfig = case envOverrides of
        Right overrides -> applyOverrides envSpecific overrides
        Left _ -> envSpecific
  
  return $ MultiEnvConfig shared env finalConfig
```

## Anti-patterns to avoid

**Storing secrets in version control** remains the most common mistake:

```haskell
-- ❌ NEVER do this
apiKey = "sk_live_real_key_here"
dbPassword = "supersecret123"

-- ✅ Load from secure source
loadSecrets :: IO Config
```

**Blocking main thread during config load:**

```haskell
-- ❌ Blocks application startup
main = do
  config <- loadConfigWithRetries 100  -- Could take forever
  runApp config

-- ✅ Timeout config loading
main = do
  result <- timeout (10 * 1000000) loadConfig
  config <- case result of
    Just cfg -> return cfg
    Nothing -> error "Config load timeout"
  runApp config
```

**Insufficient error handling in hot reload:**

```haskell
-- ❌ Crashes on reload error
handleReload event = do
  newConfig <- decodeFile path
  writeIORef configRef newConfig

-- ✅ Keeps running with old config
handleReload event = do
  result <- try $ decodeFile path
  case result of
    Right newConfig -> atomicWriteIORef configRef newConfig
    Left (err :: SomeException) -> 
      logError $ "Reload failed, keeping old config: " ++ show err
```

**Validating before interpolation:**

```haskell
-- ❌ Validates template, not final values
config <- parseYAML rawText
validate config  -- Still has ${VAR} in strings

-- ✅ Interpolate then validate
interpolated <- interpolateEnvVars rawText
config <- parseYAML interpolated
validate config  -- Actual values validated
```

## Recommendations by project context

### Small CLI tools (< 500 LOC)

**Recommended:** TOML with tomland

**Rationale:** Explicit syntax prevents errors, bidirectional codecs guarantee consistency, minimal boilerplate for simple needs.

```haskell
-- Single codec definition
import Toml

data Config = Config
  { output :: FilePath
  , verbose :: Bool
  } deriving (Show, Generic)

configCodec :: TomlCodec Config
configCodec = Config
  <$> Toml.string "output" .= output
  <*> Toml.bool "verbose" .= verbose
```

### Medium services (500-10K LOC)

**Recommended:** YAML with refined types + envy for env vars

**Rationale:** Mature ecosystem, team familiarity, runtime validation sufficient for this scale.

```haskell
import Data.Yaml
import Refined
import System.Envy

data Config = Config
  { port :: Refined (FromTo 1 65535) Int
  , database :: DatabaseURL
  , features :: FeatureFlags
  }
```

### Large-scale infrastructure (10K+ LOC, multiple services)

**Recommended:** Dhall with compilation to YAML/JSON

**Rationale:** Type safety prevents costly production errors, functions eliminate repetition across services, semantic hashing enables safe refactoring.

```dhall
-- Shared base configuration
let baseService = ./types/Service.dhall

-- Generate configs for 50 microservices
let makeServiceConfig = λ(name : Text) → λ(port : Natural) →
  baseService::{ name = name, port = port }

in { services = 
  [ makeServiceConfig "api" 8080
  , makeServiceConfig "auth" 8081
  -- ... 48 more services with consistent structure
  ]
}
```

### High-security applications

**Recommended:** Dhall + Vault + refined types

**Rationale:** Multiple layers of validation, secrets never in files, audit trail of all access.

```haskell
import Dhall
import Refined
import Database.Vault.KVv2.Client

-- Types guarantee valid values
type SecurePort = Refined (FromTo 1 65535) Int
newtype APIKey = APIKey Text deriving (Eq)
instance Show APIKey where show _ = "<redacted>"

data Config = Config
  { listenPort :: SecurePort
  , vaultSecrets :: VaultConnection
  }
```

### Rapid prototyping

**Recommended:** YAML with defaults + environment variables

**Rationale:** Fastest to set up, supports quick iteration, can migrate to stronger typing later.

```haskell
import Data.Yaml
import System.Envy

-- Quick and dirty
data Config = Config
  { setting1 :: Maybe Text
  , setting2 :: Maybe Int
  } deriving (Generic, FromJSON)

instance DefConfig Config where
  defConfig = Config Nothing Nothing
```

## Conclusion: Choose validation depth matching failure costs

**The optimal configuration approach balances type safety, developer experience, and operational requirements.** For small projects, TOML's bidirectional codecs provide adequate safety with minimal overhead. Medium-scale services benefit from YAML's ecosystem maturity combined with runtime validation through refined types and smart constructors. Large-scale infrastructure demands Dhall's compile-time guarantees to prevent costly production failures across many services.

**Hot reload capabilities and secrets management represent non-negotiable requirements for modern production systems.** fsnotify enables efficient file watching, IORef provides atomic config swaps, and HashiCorp Vault or AWS Secrets Manager deliver security beyond flat files. The dual-credential pattern ensures zero-downtime rotation.

**Key takeaway: invest in stronger validation as configuration complexity and failure costs increase.** Start simple with YAML or TOML, add refinement types as needed, migrate to Dhall when type safety justifies the learning curve. Never store secrets in files—use dedicated secrets management from day one. Implement hot reload for services requiring high availability. Your choice ultimately depends on team expertise, project scale, and how much a configuration error costs your organization.
