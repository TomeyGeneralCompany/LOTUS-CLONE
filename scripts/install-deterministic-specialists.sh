#!/usr/bin/env bash
# Deterministic specialist provisioning for the self-hosted LOTUS laptop.
# Isolated from system Python, project node_modules, and the installed LOTUS instance.
set -Eeuo pipefail
ROOT="${LOTUS_SPECIALIST_ROOT:-$HOME/.lotus-tools}"
mkdir -p "$ROOT/bin" "$ROOT/downloads" "$ROOT/logs"
LOG="$ROOT/logs/install.log"
exec > >(tee -a "$LOG") 2>&1
echo "[SPECIALIST_INSTALL] root=$ROOT"
export PATH="$ROOT/bin:$ROOT/python/bin:$HOME/.foundry/bin:$PATH"
FAILURES=()
fetch() { curl -fL --retry 4 --retry-delay 4 --connect-timeout 20 "$1" -o "$2"; }
attempt() {
  local name="$1"; shift
  if "$@"; then echo "[SPECIALIST_READY] $name"; else
    echo "[SPECIALIST_FAILED] $name"; FAILURES+=("$name")
  fi
}
setup_python() {
  python3 -m venv "$ROOT/python"
  "$ROOT/python/bin/python" -m pip install --upgrade pip wheel
  "$ROOT/python/bin/python" -m pip install \
    "libcst==1.9.0" "z3-solver==5.4.1.0" "tree-sitter==0.26.1" \
    "tree-sitter-python==0.25.0" "tree-sitter-javascript==0.25.0" \
    "tree-sitter-java==0.23.5"
  "$ROOT/python/bin/python3" - <<'PY'
import libcst, z3, tree_sitter, tree_sitter_python, tree_sitter_java, tree_sitter_javascript
assert z3.Solver().check() == z3.sat
solver=z3.Solver(); x=z3.Int("x"); solver.add(x>1,x<0)
assert solver.check() == z3.unsat
assert libcst.parse_module("x = 1\n")
assert tree_sitter.Language(tree_sitter_python.language())
assert tree_sitter.Language(tree_sitter_java.language())
assert tree_sitter.Language(tree_sitter_javascript.language())
PY
  ln -sf "$ROOT/python/bin/python3" "$ROOT/bin/python3"
}
setup_javaparser() {
  local jar="$ROOT/javaparser-core-3.26.3.jar" url="https://repo.maven.apache.org/maven2/com/github/javaparser/javaparser-core/3.26.3/javaparser-core-3.26.3.jar"
  fetch "$url" "$jar"
  local expected
  expected="$(curl -fsSL "$url.sha1" | tr -d '\r\n ')"
  [[ "$expected" =~ ^[0-9a-fA-F]{40}$ ]]
  echo "$expected  $jar" | sha1sum -c -
  java -version
  export JAVAPARSER_JAR="$jar"
  echo "$jar" > "$ROOT/javaparser-path.txt"
}
setup_foundry() {
  local version="v1.10.0" base="https://github.com/foundry-rs/foundry/releases/download/v1.10.0"
  local file="$ROOT/downloads/foundry_${version}_linux_amd64.tar.gz"
  fetch "$base/foundry_${version}_linux_amd64.tar.gz" "$file"
  local expected
  expected="$(curl -fsSL "$base/foundry_${version}_linux_amd64.sha256" | awk '{print $1}')"
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]]
  echo "$expected  $file" | sha256sum -c -
  tar -xzf "$file" -C "$ROOT/bin" forge cast anvil chisel
  "$ROOT/bin/forge" --version
}
setup_mythril() {
  local py=python3.10
  command -v "$py" >/dev/null 2>&1 || py=python3
  "$py" -m venv "$ROOT/mythril"
  "$ROOT/mythril/bin/python" -m pip install --upgrade pip "setuptools<70" wheel
  "$ROOT/mythril/bin/python" -m pip install "mythril==0.24.8"
  "$ROOT/mythril/bin/myth" version
  echo "$ROOT/mythril/bin/myth" > "$ROOT/mythril-path.txt"
}
setup_joern() {
  local version="v4.0.687" base="https://github.com/joernio/joern/releases/download/v4.0.687"
  local zip="$ROOT/downloads/joern-cli-linux-x86_64.zip"
  fetch "$base/joern-cli-linux-x86_64.zip" "$zip"
  local expected
  expected="$(curl -fsSL "$base/joern-cli-linux-x86_64.zip.sha512" | awk '{print $1}')"
  [[ "$expected" =~ ^[0-9a-fA-F]{128}$ ]]
  echo "$expected  $zip" | sha512sum -c -
  mkdir -p "$ROOT/joern"
  unzip -qo "$zip" -d "$ROOT/joern"
  local parser
  parser="$(find "$ROOT/joern" -maxdepth 5 -type f -name joern-parse | head -1)"
  [[ -n "$parser" ]]
  chmod +x "$parser"
  ln -sf "$parser" "$ROOT/bin/joern-parse"
  "$ROOT/bin/joern-parse" --help >/dev/null
  echo "$(dirname "$parser")" > "$ROOT/joern-path.txt"
}
attempt python-specialists setup_python
attempt javaparser setup_javaparser
attempt foundry setup_foundry
attempt mythril setup_mythril
attempt joern setup_joern
export MYTHRIL_BIN="$ROOT/mythril/bin/myth"
export JOERN_HOME="$(cat "$ROOT/joern-path.txt" 2>/dev/null || echo "$ROOT/joern")"
export JAVAPARSER_JAR="$(cat "$ROOT/javaparser-path.txt" 2>/dev/null || echo "$ROOT/javaparser-core-3.26.3.jar")"
{
  printf 'export PATH=%q\n' "$ROOT/bin:$ROOT/python/bin:$HOME/.foundry/bin:$PATH"
  printf 'export MYTHRIL_BIN=%q\n' "$MYTHRIL_BIN"
  printf 'export JOERN_HOME=%q\n' "$JOERN_HOME"
  printf 'export JAVAPARSER_JAR=%q\n' "$JAVAPARSER_JAR"
} > "$ROOT/env.sh"
echo "[SPECIALIST_VERSIONS]"
python3 -m pip freeze 2>/dev/null | grep -E '^(libcst|z3-solver|tree-sitter)' || true
"$ROOT/bin/forge" --version 2>/dev/null || true
"$MYTHRIL_BIN" version 2>/dev/null || true
printf '[SPECIALIST_INSTALL_RESULT] failed=%s\n' "${FAILURES[*]-}"
if (("${#FAILURES[@]}" > 0)); then exit 1; fi
