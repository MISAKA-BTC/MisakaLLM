#!/bin/bash
set -euo pipefail

UPSTREAM_REPO="kaspanet/rusty-kaspa"
# Immutable, versioned release tag to consume (audit H-4). Keep this in sync
# with the tag published by .github/workflows/musl-toolchain.yaml. When a new
# toolchain is published under a new tag, bump this value (and the pinned
# EXPECTED_XTOOLS_SHA256 below) together.
TOOLCHAIN_TAG="musl-toolchain-v1"

# Supply-chain hardening (audit H-4):
# The x-tools.tar.zst archive is downloaded from a GitHub release before any of
# its contents are trusted. We MUST verify the archive's integrity/authenticity
# BEFORE extracting it; verifying the extracted preset_hash afterwards is not
# sufficient (a tampered archive could carry a matching preset_hash).
#
# EXPECTED_XTOOLS_SHA256: pin the known-good SHA-256 of x-tools.tar.zst here.
# The release publisher MUST fill this in whenever the toolchain release is
# (re)built. Leave it empty only if you intend to rely solely on the committed
# sidecar fetched from the same release (x-tools.tar.zst.sha256); note that a
# sidecar fetched from the same release is weaker than a pinned-in-repo value
# because an attacker who can rewrite the release can rewrite both. When set,
# the downloaded archive's sha256sum MUST equal this value or the build fails.
EXPECTED_XTOOLS_SHA256=""

# Calculate the hash of the preset file
CURRENT_PRESET_HASH=$(sha256sum $GITHUB_WORKSPACE/musl-toolchain/preset.sh | awk '{print $1}')
PRESET_HASH_FILE="$HOME/x-tools/preset_hash"

echo "Current preset hash: $CURRENT_PRESET_HASH"

# Traverse to working directory
cd $GITHUB_WORKSPACE/musl-toolchain

# Set the preset
source preset.sh

# Check if the toolchain is already installed and up-to-date
if [ -d "$HOME/x-tools" ] && [ -f "$PRESET_HASH_FILE" ] && [ "$(cat $PRESET_HASH_FILE)" = "$CURRENT_PRESET_HASH" ]; then
  echo "Toolchain already installed and up-to-date, skipping"
else
  rm -rf "$HOME/x-tools"
  TOOLCHAIN_INSTALLED=false

  # Try downloading and verifying from a repo. Cleans up on any verification
  # failure. The archive's SHA-256 is verified BEFORE extraction (audit H-4).
  try_download_toolchain() {
    local repo="$1"
    echo "Trying to download toolchain from $repo..."

    local archive="/tmp/x-tools.tar.zst"
    local sidecar="/tmp/x-tools.tar.zst.sha256"
    local extract_dir="/tmp/x-tools-extract.$$"
    local download_url="https://github.com/$repo/releases/download/$TOOLCHAIN_TAG/x-tools.tar.zst"

    rm -f "$archive" "$sidecar"
    if ! curl -fsSL -o "$archive" "$download_url"; then
      echo "  No release found in $repo"
      rm -f "$archive"
      return 1
    fi

    # Compute the actual SHA-256 of the downloaded archive.
    local actual_sha
    actual_sha=$(sha256sum "$archive" | awk '{print $1}')
    echo "  Downloaded archive sha256: $actual_sha"

    # (1) Verify against the in-repo pinned value when provided. This is the
    # strongest check: it does not trust anything fetched from the release.
    if [ -n "$EXPECTED_XTOOLS_SHA256" ]; then
      if [ "$actual_sha" != "$EXPECTED_XTOOLS_SHA256" ]; then
        echo "  ERROR: archive sha256 mismatch vs pinned EXPECTED_XTOOLS_SHA256"
        echo "         expected: $EXPECTED_XTOOLS_SHA256"
        echo "         actual:   $actual_sha"
        rm -f "$archive"
        return 1
      fi
      echo "  Archive sha256 matches pinned EXPECTED_XTOOLS_SHA256"
    fi

    # (2) Verify against the sidecar published with the release. This catches
    # accidental corruption and, combined with (1), documents the expected hash.
    if curl -fsSL -o "$sidecar" "$download_url.sha256"; then
      # The sidecar may be either a bare hash or "<hash>  <filename>".
      local sidecar_sha
      sidecar_sha=$(awk '{print $1}' "$sidecar")
      if [ -z "$sidecar_sha" ]; then
        echo "  ERROR: sidecar $download_url.sha256 is empty/unparseable"
        rm -f "$archive" "$sidecar"
        return 1
      fi
      if [ "$actual_sha" != "$sidecar_sha" ]; then
        echo "  ERROR: archive sha256 mismatch vs sidecar"
        echo "         sidecar: $sidecar_sha"
        echo "         actual:  $actual_sha"
        rm -f "$archive" "$sidecar"
        return 1
      fi
      echo "  Archive sha256 matches release sidecar"
      rm -f "$sidecar"
    elif [ -z "$EXPECTED_XTOOLS_SHA256" ]; then
      # No pinned value AND no sidecar: we have nothing to verify against.
      echo "  ERROR: no EXPECTED_XTOOLS_SHA256 pinned and no sidecar found at"
      echo "         $download_url.sha256 -- refusing to extract unverified archive"
      rm -f "$archive"
      return 1
    else
      echo "  Note: no sidecar found; relying on pinned EXPECTED_XTOOLS_SHA256"
    fi

    # Only now, after the archive is verified, extract it. Extract into a fresh
    # temp dir and move into place (do not extract-in-place over $HOME).
    echo "  Extracting..."
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    if ! tar --use-compress-program=zstd -xf "$archive" -C "$extract_dir"; then
      echo "  ERROR: extraction failed"
      rm -rf "$extract_dir"
      rm -f "$archive"
      return 1
    fi
    rm -f "$archive"

    if [ ! -d "$extract_dir/x-tools" ]; then
      echo "  ERROR: archive did not contain an x-tools directory"
      rm -rf "$extract_dir"
      return 1
    fi

    rm -rf "$HOME/x-tools"
    mv "$extract_dir/x-tools" "$HOME/x-tools"
    rm -rf "$extract_dir"

    if [ -f "$PRESET_HASH_FILE" ] && [ "$(cat "$PRESET_HASH_FILE")" = "$CURRENT_PRESET_HASH" ]; then
      echo "  Preset hash matches, toolchain ready"
      return 0
    fi

    echo "  Preset hash mismatch (expected: $CURRENT_PRESET_HASH, got: $(cat "$PRESET_HASH_FILE" 2>/dev/null || echo 'missing'))"
    rm -rf "$HOME/x-tools"
    return 1
  }

  # Try upstream first, then fall back to the current repo (for fork-based toolchain testing)
  if try_download_toolchain "$UPSTREAM_REPO"; then
    TOOLCHAIN_INSTALLED=true
  elif [ "$GITHUB_REPOSITORY" != "$UPSTREAM_REPO" ] && try_download_toolchain "$GITHUB_REPOSITORY"; then
    TOOLCHAIN_INSTALLED=true
  fi

  if [ "$TOOLCHAIN_INSTALLED" != "true" ]; then
    echo "ERROR: Could not download a matching toolchain from $UPSTREAM_REPO or $GITHUB_REPOSITORY"
    echo "Run the 'Build musl toolchain' workflow to create/update the release."
    exit 1
  fi
fi

# Update toolchain variables: C compiler, C++ compiler, linker, and archiver
export CC=$HOME/x-tools/$CTNG_PRESET/bin/$CTNG_PRESET-gcc
export CXX=$HOME/x-tools/$CTNG_PRESET/bin/$CTNG_PRESET-g++
export LD=$HOME/x-tools/$CTNG_PRESET/bin/$CTNG_PRESET-ld
export AR=$HOME/x-tools/$CTNG_PRESET/bin/$CTNG_PRESET-ar

# Exports for cc crate
# https://docs.rs/cc/latest/cc/#external-configuration-via-environment-variables
export RANLIB_x86_64_unknown_linux_musl=$HOME/x-tools/$CTNG_PRESET/bin/$CTNG_PRESET-ranlib
export CC_x86_64_unknown_linux_musl=$CC
export CXX_x86_64_unknown_linux_musl=$CXX
export AR_x86_64_unknown_linux_musl=$AR
export LD_x86_64_unknown_linux_musl=$LD

# Set environment variables for static linking
export OPENSSL_STATIC=true
export RUSTFLAGS="-C link-arg=-static"

# We specify the compiler that will invoke linker
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$CC

# Add target
rustup target add x86_64-unknown-linux-musl

# Install missing dependencies
cargo fetch --target x86_64-unknown-linux-musl
