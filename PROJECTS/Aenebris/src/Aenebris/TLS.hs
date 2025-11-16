{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Aenebris.TLS
  ( TLSSettings
  , createTLSSettings
  , createSNISettings
  , validateCertificate
  , CertificateError(..)
  ) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Map.Strict as Map
import Network.Wai.Handler.WarpTLS
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra.Cipher as Cipher
import Data.Default.Class (def)
import Data.X509 (SignedCertificate)
import Data.X509.File (readSignedObject)
import System.Directory (doesFileExist)
import Control.Exception (try, SomeException)

-- | Certificate loading errors
data CertificateError
  = CertFileNotFound FilePath
  | KeyFileNotFound FilePath
  | InvalidCertificate FilePath String
  | InvalidKey FilePath String
  deriving (Show, Eq)

-- | Create TLS settings for a single certificate (non-SNI)
createTLSSettings :: FilePath -> FilePath -> IO (Either CertificateError TLSSettings)
createTLSSettings certFile keyFile = do
  -- Validate files exist
  certExists <- doesFileExist certFile
  keyExists <- doesFileExist keyFile

  if not certExists
    then return $ Left (CertFileNotFound certFile)
    else if not keyExists
      then return $ Left (KeyFileNotFound keyFile)
      else do
        -- Try to load the credential to validate it
        result <- try $ TLS.credentialLoadX509 certFile keyFile
        case result of
          Left (err :: SomeException) ->
            return $ Left (InvalidCertificate certFile (show err))

          Right (Left err) ->
            return $ Left (InvalidCertificate certFile err)

          Right (Right _credential) -> do
            -- Create TLS settings with strong security
            let tlsConfig = (tlsSettings certFile keyFile)
                  { tlsAllowedVersions = [TLS.TLS13, TLS.TLS12]
                  , tlsCiphers = strongCipherSuites
                  , onInsecure = DenyInsecure "This server requires HTTPS"
                  }

            return $ Right tlsConfig

-- | Create TLS settings with SNI support for multiple domains
createSNISettings :: [(Text, FilePath, FilePath)] -> FilePath -> FilePath -> IO (Either CertificateError TLSSettings)
createSNISettings domains defaultCert defaultKey = do
  -- Validate default certificate
  defaultExists <- doesFileExist defaultCert
  defaultKeyExists <- doesFileExist defaultKey

  if not defaultExists
    then return $ Left (CertFileNotFound defaultCert)
    else if not defaultKeyExists
      then return $ Left (KeyFileNotFound defaultKey)
      else do
        -- Validate all domain certificates exist
        validationResults <- mapM validateDomainCert domains
        case sequence validationResults of
          Left err -> return $ Left err
          Right _ -> do
            -- Create SNI-enabled TLS settings using the default cert first
            let baseTLS = tlsSettings defaultCert defaultKey
                tlsConfig = baseTLS
                  { tlsAllowedVersions = [TLS.TLS13, TLS.TLS12]
                  , tlsCiphers = strongCipherSuites
                  , onInsecure = DenyInsecure "This server requires HTTPS"
                  , tlsServerHooks = def
                      { TLS.onServerNameIndication = \mHostname -> case mHostname of
                          Nothing -> loadCredentials defaultCert defaultKey
                          Just hostname -> sniCallback domains defaultCert defaultKey hostname
                      }
                  }

            return $ Right tlsConfig
  where
    validateDomainCert :: (Text, FilePath, FilePath) -> IO (Either CertificateError ())
    validateDomainCert (domain, certFile, keyFile) = do
      certExists <- doesFileExist certFile
      keyExists <- doesFileExist keyFile

      if not certExists
        then return $ Left (CertFileNotFound certFile)
        else if not keyExists
          then return $ Left (KeyFileNotFound keyFile)
          else return $ Right ()

-- | SNI callback function - returns credentials based on hostname
sniCallback :: [(Text, FilePath, FilePath)] -> FilePath -> FilePath -> String -> IO TLS.Credentials
sniCallback domains defaultCert defaultKey hostname = do
  let hostnameText = T.pack hostname
      -- Look up domain in map
      domainMap = Map.fromList [(d, (c, k)) | (d, c, k) <- domains]

  case Map.lookup hostnameText domainMap of
    Nothing -> do
      -- No match, use default certificate
      loadCredentials defaultCert defaultKey

    Just (certFile, keyFile) -> do
      -- Found matching domain, load its certificate
      loadCredentials certFile keyFile

-- | Load TLS credentials from certificate and key files
loadCredentials :: FilePath -> FilePath -> IO TLS.Credentials
loadCredentials certFile keyFile = do
  result <- TLS.credentialLoadX509 certFile keyFile
  case result of
    Left err ->
      error $ "Failed to load certificate: " ++ err
    Right credential ->
      return $ TLS.Credentials [credential]

-- | Validate a certificate file (check if it's readable and valid)
validateCertificate :: FilePath -> IO (Either CertificateError [SignedCertificate])
validateCertificate certFile = do
  exists <- doesFileExist certFile
  if not exists
    then return $ Left (CertFileNotFound certFile)
    else do
      result <- try $ readSignedObject certFile
      case result of
        Left (err :: SomeException) ->
          return $ Left (InvalidCertificate certFile (show err))
        Right certs ->
          return $ Right certs

-- | Strong cipher suites for production (TLS 1.2 + TLS 1.3)
strongCipherSuites :: [TLS.Cipher]
strongCipherSuites =
  -- TLS 1.3 cipher suites (preferred)
  [ Cipher.cipher_TLS13_AES128GCM_SHA256
  , Cipher.cipher_TLS13_AES256GCM_SHA384
  , Cipher.cipher_TLS13_CHACHA20POLY1305_SHA256
  ] ++
  -- TLS 1.2 cipher suites (fallback, only ECDHE + AEAD)
  [ Cipher.cipher_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  , Cipher.cipher_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  , Cipher.cipher_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  , Cipher.cipher_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  , Cipher.cipher_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  , Cipher.cipher_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  ]
