# ©AngelaMos | 2026
# config.nims

switch("mm", "orc")

when defined(musl):
  var muslGcc = findExe("musl-gcc")
  if muslGcc.len > 0:
    switch("gcc.exe", muslGcc)
    switch("gcc.linkerexe", muslGcc)
  switch("passL", "-static")

when defined(zigcc):
  switch("cc", "clang")
  switch("clang.exe", "zigcc")
  switch("clang.linkerexe", "zigcc")

when defined(release):
  switch("opt", "size")
  switch("passC", "-flto")
  switch("passL", "-flto")

when defined(strip):
  switch("passL", "-s")

when defined(crossX86):
  switch("passC", "-target x86_64-linux-musl")
  switch("passL", "-target x86_64-linux-musl")
  switch("os", "linux")
  switch("cpu", "amd64")

when defined(crossArm64):
  switch("passC", "-target aarch64-linux-musl")
  switch("passL", "-target aarch64-linux-musl")
  switch("os", "linux")
  switch("cpu", "arm64")
