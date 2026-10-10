#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sagar Jadhav
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$ROOT/.dev/pids" ] && xargs -r kill < "$ROOT/.dev/pids" 2>/dev/null; rm -f "$ROOT/.dev/pids"; echo "stack stopped"
