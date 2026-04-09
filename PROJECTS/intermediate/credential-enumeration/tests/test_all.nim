# ©AngelaMos | 2026
# test_all.nim
#
# Unit tests for core utility and parsing functions
#
# Exercises exported helpers from four modules across eight test
# suites. redactValue covers short, long, exact-length, and empty
# strings. isPrivateKey validates detection of five PEM header
# formats (OpenSSH, RSA, ECDSA, DSA, PKCS8) and rejection of
# public keys and non-key content. isEncrypted checks for
# ENCRYPTED, bcrypt, and aes256-ctr markers versus unencrypted
# keys. matchesSecretPattern verifies detection of export-prefixed
# and bare KEY=/SECRET=/TOKEN=/PASSWORD= assignments while
# rejecting PATH exports and ordinary commands.
# matchesCommandPattern tests curl with auth headers and -u flag,
# wget with authorization header and password, mysql -p, psql
# password, and sshpass detection, rejecting safe commands.
# matchesExclude validates exact filename and directory segment
# matching without false positives on partial or embedded
# substrings. permissionSeverity confirms svInfo for nonexistent
# paths. parseModules tests single, multiple, whitespace-padded,
# full-set, empty, and unknown module string parsing. redactLine
# checks export-prefixed quoted, unquoted, and single-quoted value
# redaction plus passthrough for lines without an equals sign.
#
# Connects to:
#   types.nim              - Category enum values for parseModules
#   collectors/base.nim    - redactValue, matchesExclude,
#                             permissionSeverity
#   collectors/ssh.nim     - isPrivateKey, isEncrypted
#   collectors/history.nim - matchesSecretPattern,
#                             matchesCommandPattern, redactLine
#   harvester.nim          - parseModules

import std/[unittest, strutils]
import types
import collectors/base
import collectors/ssh
import collectors/history
import harvester

suite "redactValue":
  test "short value fully redacted":
    check redactValue("abc", 4) == "***"

  test "value longer than showChars":
    check redactValue("mysecret", 4) == "myse****"

  test "exact showChars length":
    check redactValue("abcd", 4) == "****"

  test "empty string":
    check redactValue("", 4) == ""

suite "isPrivateKey":
  test "OpenSSH key":
    check isPrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----\ndata")

  test "RSA key":
    check isPrivateKey("-----BEGIN RSA PRIVATE KEY-----\ndata")

  test "ECDSA key":
    check isPrivateKey("-----BEGIN EC PRIVATE KEY-----\ndata")

  test "DSA key":
    check isPrivateKey("-----BEGIN DSA PRIVATE KEY-----\ndata")

  test "generic PKCS8 key":
    check isPrivateKey("-----BEGIN PRIVATE KEY-----\ndata")

  test "public key rejected":
    check isPrivateKey("-----BEGIN PUBLIC KEY-----\ndata") == false

  test "random text rejected":
    check isPrivateKey("this is not a key") == false

  test "empty string rejected":
    check isPrivateKey("") == false

suite "isEncrypted":
  test "ENCRYPTED marker":
    check isEncrypted(
      "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\ndata"
    )

  test "bcrypt marker":
    check isEncrypted(
      "-----BEGIN OPENSSH PRIVATE KEY-----\nbcrypt\ndata"
    )

  test "aes256-ctr marker":
    check isEncrypted("data with aes256-ctr in it")

  test "unencrypted key":
    check isEncrypted(
      "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1\ndata"
    ) == false

suite "matchesSecretPattern":
  test "export with KEY=":
    check matchesSecretPattern("export API_KEY=some_value")

  test "export with SECRET=":
    check matchesSecretPattern(
      "export AWS_SECRET_ACCESS_KEY=abc123"
    )

  test "bare TOKEN= at start":
    check matchesSecretPattern("TOKEN=abcdef12345")

  test "bare PASSWORD=":
    check matchesSecretPattern("PASSWORD=hunter2")

  test "non-secret assignment":
    check matchesSecretPattern("export PATH=/usr/bin") == false

  test "ordinary command":
    check matchesSecretPattern("ls -la /tmp") == false

  test "empty string":
    check matchesSecretPattern("") == false

suite "matchesCommandPattern":
  test "curl with auth header":
    check matchesCommandPattern(
      "curl -H \"Authorization: Bearer token\" https://api.example.com"
    )

  test "curl with lowercase -h auth":
    check matchesCommandPattern(
      "curl -h \"authorization: bearer token\" https://api.example.com"
    )

  test "curl with -u flag":
    check matchesCommandPattern(
      "curl -u user:pass https://api.example.com"
    )

  test "wget with authorization header":
    check matchesCommandPattern(
      "wget --header=\"Authorization: Basic abc\" https://example.com"
    )

  test "wget with password":
    check matchesCommandPattern(
      "wget --password=secret https://files.example.com/data.zip"
    )

  test "mysql with -p flag":
    check matchesCommandPattern("mysql -u root -psecret mydb")

  test "psql with password":
    check matchesCommandPattern(
      "psql password=secret host=db.example.com"
    )

  test "sshpass command":
    check matchesCommandPattern("sshpass -p 'mypass' ssh user@host")

  test "safe curl rejected":
    check matchesCommandPattern("curl https://example.com") == false

  test "safe git command rejected":
    check matchesCommandPattern("git push origin main") == false

  test "empty string rejected":
    check matchesCommandPattern("") == false

suite "matchesExclude":
  test "exact filename match":
    check matchesExclude("/home/user/.env", @[".env"])

  test "directory segment match":
    check matchesExclude("/home/user/.git/config", @[".git"])

  test "no false positive on partial name":
    check matchesExclude(
      "/home/user/.venv/lib/site.py", @[".env"]
    ) == false

  test "no match on embedded substring":
    check matchesExclude(
      "/home/user/environment/data", @[".env"]
    ) == false

  test "empty patterns":
    check matchesExclude("/home/user/.env", @[]) == false

suite "permissionSeverity":
  test "returns svInfo for unreadable path":
    check permissionSeverity("/nonexistent/path/abc123") == svInfo

suite "parseModules":
  test "single module":
    check parseModules("ssh") == @[catSsh]

  test "multiple modules":
    let mods = parseModules("ssh,git,cloud")
    check mods.len == 3
    check mods.contains(catSsh)
    check mods.contains(catGit)
    check mods.contains(catCloud)

  test "with whitespace":
    let mods = parseModules(" browser , keyring ")
    check mods.len == 2
    check mods.contains(catBrowser)
    check mods.contains(catKeyring)

  test "all modules":
    let mods = parseModules(
      "browser,ssh,cloud,history,keyring,git,apptoken"
    )
    check mods.len == 7

  test "empty string":
    check parseModules("").len == 0

  test "unknown module ignored":
    check parseModules("fake,nonexistent").len == 0

suite "redactLine":
  test "export with quoted value":
    let got = redactLine("export KEY=\"secret\"")
    check got.contains("KEY=")
    check got.contains("\"") == false

  test "export with unquoted value":
    let got = redactLine("export API_KEY=mysecretvalue")
    check got.contains("API_KEY=")
    check got.contains("myse")
    check got.contains("cretvalue") == false

  test "no equals sign":
    check redactLine("no assignment here") == "no assignment here"

  test "single-quoted value":
    let got = redactLine("export TOKEN='abcdefgh'")
    check got.contains("TOKEN=")
    check got.contains("'") == false
