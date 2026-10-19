#!/bin/sh
# The container's launch command, with the worker count decided by the same
# rule the application enforces at startup.
#
# `sentinel/composition/topology.py` REFUSES to start when several worker
# processes are observed and no shared rate limiter (`SENTINEL_REDIS_URL`) is
# configured, because a per-process limiter across N workers permits N times
# the configured rate while every check reports healthy. The image used to
# hard-code `--workers 4`, so every deployment without Redis -- the CI smoke
# test, the Helm chart on a kind cluster, a developer's laptop -- was refused by
# its own image before it served a request.
#
# So: one worker unless a shared limiter exists, in which case four. An
# operator who knows better sets GUNICORN_WORKERS explicitly, and if that is
# wrong the application still refuses -- this script chooses a default, it does
# not bypass the check.
set -eu

# `docker run <image> python -m sentinel.interface.cli migrate` runs THAT
# command, exactly as it did when the image had a plain CMD. Only an empty
# command line, or one that starts with a gunicorn option, launches the server.
case "${1:-}" in
    "" | -*) ;;
    *) exec "$@" ;;
esac

if [ -n "${GUNICORN_WORKERS:-}" ]; then
    workers="$GUNICORN_WORKERS"
elif [ -n "${SENTINEL_REDIS_URL:-}" ]; then
    workers=4
else
    workers=1
fi

exec gunicorn "sentinel.interface.asgi:create_application()" \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --workers "$workers" \
    --timeout 120 \
    --access-logfile - \
    "$@"
