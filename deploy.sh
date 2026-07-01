#!/usr/bin/env bash
# Pull + restart on the Pi (compose lives in /home/pi/docker/sonoff).
set -euo pipefail
PI="${PI:-pi@192.168.8.9}"
DIR="/home/pi/docker/sonoff"
ssh "$PI" "cd $DIR && docker compose pull && docker compose up -d && docker compose ps"
