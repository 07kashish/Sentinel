# The image an untrusted skill is detonated inside.
#
# WHAT THIS IMAGE IS FOR
# ----------------------
# It runs one skill package, once, with no network and no capabilities, and
# then it is destroyed. `ContainerDetonator` supplies the isolation flags; this
# file supplies the contents. Both halves have to be minimal, or the flags are
# protecting a filesystem full of tools.
#
# WHY IT IS THIS EMPTY
# --------------------
# Every binary present is a binary an untrusted skill can use. `curl` would be
# useless with --network=none, but `tar`, a compiler, a package manager or a
# shell with job control all widen what a skill can do to its workspace before
# it exits. So this starts from a distroless base rather than a distribution:
# no shell, no package manager, no coreutils to inherit.
#
# WHAT IT DOES NOT PROVIDE
# ------------------------
# Not observation. A container run reports an exit code and two output streams;
# it does not report which files were read or which hosts were contacted. That
# needs syscall tracing and is not here, which is why every recording from this
# boundary sets `observation_incomplete=True`. See the module docstring in
# `sentinel/infrastructure/detonation_container.py`.
#
# Not a virtual machine. It shares the host kernel.

# THE BASE IMAGE MUST BE PINNED BY DIGEST, AND THIS FILE REFUSES TO GUESS ONE.
#
# `ARG` with no default, so `docker build` FAILS unless a digest is supplied:
#
#   docker build --build-arg BASE=gcr.io/distroless/python3-debian12:nonroot@sha256:<digest> \
#                -t sentinel/detonate:<version> deploy/detonation
#
# A mutable tag would mean "we detonated untrusted code inside whatever
# :latest resolved to this morning", which is not a statement anybody can
# audit. A digest written into this file by hand would be worse: it would look
# authoritative while being unverified, and it would fail to pull at the moment
# somebody needed the sandbox. Resolve the digest yourself:
#
#   docker buildx imagetools inspect gcr.io/distroless/python3-debian12:nonroot
#
# and record it in the commit that sets it, so the provenance of the boundary
# is in version control rather than in somebody's shell history.
ARG BASE
FROM ${BASE}

# 65534:65534 is nobody:nogroup. The runtime also passes --user=65534:65534, so
# this is belt and braces: an image defaulting to root would run as root if
# anybody ever invoked it without the flag.
USER 65534:65534

# The only writable location, and the runtime mounts it as a noexec, nosuid
# tmpfs. Nothing written here survives the run.
WORKDIR /workspace

# The package arrives read-only at /skill/package, mounted by the runtime. It
# is deliberately NOT copied in at build time: the image is built once and
# reused for every skill, and baking a package in would mean rebuilding per
# detonation and re-resolving the base digest every time.
#
# -I is isolated mode: no site-packages, no user directory on sys.path, and
# PYTHONPATH ignored. -S skips site initialisation. Together they stop a skill
# reaching anything the image happens to have installed.
ENTRYPOINT ["/usr/bin/python3", "-I", "-S", "/skill/package"]
