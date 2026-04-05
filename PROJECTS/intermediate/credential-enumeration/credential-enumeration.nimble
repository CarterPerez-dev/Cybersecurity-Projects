# ©AngelaMos | 2026
# credential-enumeration.nimble

version       = "0.1.0"
author        = "AngelaMos"
description   = "Post-access credential exposure detection for Linux systems"
license       = "AGPL-3.0"
srcDir        = "src"
binDir        = "bin"
bin           = @["credenum"]
namedBin      = {"harvester": "credenum"}.toTable

requires "nim >= 2.2.0"
