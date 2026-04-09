# ©AngelaMos | 2026
# config.nim
#
# Application constants and default configuration
#
# Central repository for every configurable value in the tool. Defines
# the module category list with human-readable names and descriptions,
# filesystem paths for each collector target (Firefox/Chromium browser
# dirs, SSH paths and key headers/encryption markers, AWS/GCP/Azure/
# Kubernetes config paths, shell history files, secret regex patterns,
# sensitive command patterns, .env file patterns, keyring/wallet/
# password store dirs, Git credential files and token prefixes, and
# 20+ application token paths from Docker to Terraform to rclone).
# Also defines permission constants, ANSI color codes, severity color/
# label mappings, box-drawing characters for terminal output, the
# ASCII banner, and the defaultConfig factory proc.
#
# Connects to:
#   types.nim               - Category, Severity, HarvestConfig, OutputFormat
#   collectors/*.nim         - all collectors reference path/pattern constants
#   output/terminal.nim     - banner, colors, box characters, severity labels
#   harvester.nim           - defaultConfig, ModuleNames, ModuleDescriptions

{.push raises: [].}

import std/os
import types

const
  AppVersion* = "0.1.0"
  BinaryName* = "credenum"

  AllModules*: seq[Category] =
    @[catBrowser, catSsh, catCloud, catHistory, catKeyring, catGit, catApptoken]

  ModuleNames*: array[Category, string] = [
    catBrowser: "browser",
    catSsh: "ssh",
    catCloud: "cloud",
    catHistory: "history",
    catKeyring: "keyring",
    catGit: "git",
    catApptoken: "apptoken",
  ]

  ModuleDescriptions*: array[Category, string] = [
    catBrowser: "Browser credential stores",
    catSsh: "SSH keys and configuration",
    catCloud: "Cloud provider configurations",
    catHistory: "Shell history and environment files",
    catKeyring: "Keyrings and password stores",
    catGit: "Git credential stores",
    catApptoken: "Application tokens and database configs",
  ]

const
  FirefoxDir* = ".mozilla/firefox"
  FirefoxProfilesIni* = "profiles.ini"
  FirefoxLoginsFile* = "logins.json"
  FirefoxCookiesDb* = "cookies.sqlite"
  FirefoxKeyDb* = "key4.db"

  ChromiumDirs* =
    [".config/google-chrome", ".config/chromium", ".config/brave", ".config/vivaldi"]
  ChromiumLoginData* = "Login Data"
  ChromiumCookies* = "Cookies"
  ChromiumWebData* = "Web Data"

const
  SshDir* = ".ssh"
  SshConfig* = "config"
  SshAuthorizedKeys* = "authorized_keys"
  SshKnownHosts* = "known_hosts"

  SshKeyHeaders* = [
    "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
  ]

  SshEncryptedMarkers* =
    ["ENCRYPTED", "Proc-Type: 4,ENCRYPTED", "aes256-ctr", "aes128-ctr", "bcrypt"]

  SshSafeKeyPerms* = "0600"
  SshSafeDirPerms* = "0700"

const
  AwsCredentials* = ".aws/credentials"
  AwsConfig* = ".aws/config"
  AwsStaticKeyPrefix* = "AKIA"
  AwsSessionKeyPrefix* = "ASIA"

  GcpConfigDir* = ".config/gcloud"
  GcpAppDefaultCreds* = ".config/gcloud/application_default_credentials.json"
  GcpServiceAccountPattern* = "service_account"

  AzureDir* = ".azure"
  AzureAccessTokens* = ".azure/accessTokens.json"
  AzureMsalTokenCache* = ".azure/msal_token_cache.json"

  KubeConfig* = ".kube/config"
  KubeContextMarker* = "contexts:"
  KubeUserMarker* = "users:"

const
  HistoryFiles* =
    [".bash_history", ".zsh_history", ".fish_history", ".sh_history", ".python_history"]

  SecretPatterns* = [
    "KEY=", "SECRET=", "TOKEN=", "PASSWORD=", "PASSWD=", "API_KEY=", "ACCESS_KEY=",
    "PRIVATE_KEY=", "AUTH_TOKEN=", "CREDENTIALS=",
  ]

  HistoryCommandPatterns* = [
    "curl.*-h.*authoriz", "curl.*-u ", "wget.*--header.*authoriz", "wget.*--password",
    "mysql.*-p", "psql.*password", "sshpass",
  ]

  EnvFileName* = ".env"
  EnvFilePatterns* = [".env", ".env.local", ".env.production", ".env.staging"]

const
  GnomeKeyringDir* = ".local/share/keyrings"
  KdeWalletDir* = ".local/share/kwalletd"
  KeePassExtension* = ".kdbx"
  PassStoreDir* = ".password-store"
  BitwardenDir* = ".config/Bitwarden"
  BitwardenCliDir* = ".config/Bitwarden CLI"

const
  GitCredentials* = ".git-credentials"
  GitConfig* = ".gitconfig"
  GitConfigLocal* = ".config/git/config"
  GitCredentialHelperKey* = "credential"
  GitHubTokenPatterns* = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
  GitLabTokenPatterns* = ["glpat-"]

const
  SlackDir* = ".config/Slack"
  DiscordDir* = ".config/discord"
  VsCodeDir* = ".config/Code"
  VsCodeUserSettings* = ".config/Code/User/settings.json"
  PgPass* = ".pgpass"
  MyCnf* = ".my.cnf"
  RedisConf* = ".rediscli_auth"
  MongoRc* = ".mongorc.js"
  DockerConfig* = ".docker/config.json"

const
  NetrcFile* = ".netrc"
  NpmrcFile* = ".npmrc"
  PypircFile* = ".pypirc"
  GhCliHosts* = ".config/gh/hosts.yml"
  TerraformCreds* = ".terraform.d/credentials.tfrc.json"
  VaultTokenFile* = ".vault-token"
  HelmRepos* = ".config/helm/repositories.yaml"
  RcloneConf* = ".config/rclone/rclone.conf"

const
  OwnerOnlyFilePerms* = 0o600
  OwnerOnlyDirPerms* = 0o700
  GroupReadBit* = 0o040
  WorldReadBit* = 0o004

const
  Banner* = """
   ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗██╗   ██╗███╗   ███╗
  ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║██║   ██║████╗ ████║
  ██║     ██████╔╝█████╗  ██║  ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
  ██║     ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
  ╚██████╗██║  ██║███████╗██████╔╝███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
   ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝"""

  BannerTagline* = "Post-access credential exposure detection"

const
  ColorReset* = "\e[0m"
  ColorBold* = "\e[1m"
  ColorDim* = "\e[2m"
  ColorRed* = "\e[31m"
  ColorGreen* = "\e[32m"
  ColorYellow* = "\e[33m"
  ColorBlue* = "\e[34m"
  ColorMagenta* = "\e[35m"
  ColorCyan* = "\e[36m"
  ColorWhite* = "\e[37m"
  ColorBoldRed* = "\e[1;31m"
  ColorBoldGreen* = "\e[1;32m"
  ColorBoldYellow* = "\e[1;33m"
  ColorBoldMagenta* = "\e[1;35m"
  ColorBoldCyan* = "\e[1;36m"

  SeverityColors*: array[Severity, string] = [
    svInfo: ColorDim,
    svLow: ColorCyan,
    svMedium: ColorYellow,
    svHigh: ColorBoldMagenta,
    svCritical: ColorBoldRed,
  ]

  SeverityLabels*: array[Severity, string] = [
    svInfo: "INFO",
    svLow: "LOW",
    svMedium: "MEDIUM",
    svHigh: "HIGH",
    svCritical: "CRITICAL",
  ]

const
  BoxTopLeft* = "┌"
  BoxTopRight* = "┐"
  BoxBottomLeft* = "└"
  BoxBottomRight* = "┘"
  BoxHorizontal* = "─"
  BoxVertical* = "│"
  BoxTeeRight* = "├"
  BoxTeeLeft* = "┤"
  BoxCross* = "┼"
  Bullet* = "●"
  Arrow* = "▸"
  CheckMark* = "✓"
  CrossMark* = "✗"

proc defaultConfig*(): HarvestConfig =
  HarvestConfig(
    targetDir: getHomeDir(),
    enabledModules: AllModules,
    excludePatterns: @[],
    outputFormat: fmtTerminal,
    outputPath: "",
    dryRun: false,
    quiet: false,
    verbose: false,
  )
