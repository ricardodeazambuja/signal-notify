#!/usr/bin/env bash
# Reproducibly build + install the spqr_py binding into the active Python env.
#
# Reproducibility contract (see rust/spqr_py/PROVENANCE.md):
#   - spqr git dep is pinned to an immutable commit in Cargo.toml
#   - Cargo.lock (committed) freezes every transitive dep
#   - rust-toolchain.toml pins the compiler
# Running this from a clean checkout rebuilds the identical binding.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Each binding is a self-contained crate under rust/ with its own pinned
# Cargo.lock + rust-toolchain.toml.
CRATES="spqr_py kyber1024_py"

# Bring cargo/rustc onto PATH if the rustup env script exists.
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

# Prefer the project's local conda env python if the caller hasn't picked one.
PYTHON="${PYTHON:-$HOME/miniforge3/envs/local/bin/python}"

echo ">> rustc:   $(rustc --version)"
echo ">> cargo:   $(cargo --version)"
echo ">> python:  $("$PYTHON" --version)"
echo ">> maturin: $("$PYTHON" -m maturin --version)"

for crate in $CRATES; do
    echo ">> building $crate"
    cd "$HERE/$crate"
    # --locked: fail instead of silently updating Cargo.lock. This is what
    # enforces reproducibility — a drifted lockfile is an error, not an auto-fix.
    "$PYTHON" -m maturin develop --release --locked
done

echo ">> ok: $CRATES installed into $("$PYTHON" -c 'import sys; print(sys.prefix)')"
