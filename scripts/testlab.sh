#!/usr/bin/env bash
# Runs the insnaps Android instrumentation suite on Firebase Test Lab.
#
# NOT USABLE YET. There is no Android module: the BLE transport, Keystore
# IdentityStore and capture protections are unwritten, and the core suite has no
# device dependencies worth running on a handset (see docs/TESTING.md).
#
# This exists so the device matrix is a reviewed decision rather than something
# improvised the day the Android module lands.
set -euo pipefail

# Firebase project. Not a secret -- a project id is embedded in every client app
# that talks to Firebase -- but no API key or service-account credential belongs
# in this repository.
PROJECT="${FIREBASE_PROJECT:-insnaps-44c85}"

APP_APK="${APP_APK:-androidApp/build/outputs/apk/debug/androidApp-debug.apk}"
TEST_APK="${TEST_APK:-androidApp/build/outputs/apk/androidTest/debug/androidApp-debug-androidTest.apk}"

# Chosen to cover the axes that actually differ for BLE and background execution:
# OEM Bluetooth stack, API level, and manufacturer background policy. Samsung and
# Xiaomi are included specifically because their background restrictions are more
# aggressive than stock Android.
gcloud firebase test android run \
  --project "$PROJECT" \
  --type instrumentation \
  --app "$APP_APK" \
  --test "$TEST_APK" \
  --device model=shiba,version=34,locale=en,orientation=portrait \
  --device model=b0q,version=33,locale=en,orientation=portrait \
  --device model=redfin,version=30,locale=en,orientation=portrait \
  --device model=a51,version=31,locale=en,orientation=portrait \
  --timeout 10m \
  --use-orchestrator \
  --environment-variables clearPackageData=true \
  --results-history-name insnaps-android

# Deliberately absent:
#
#   --network-profile     shapes IP traffic, not BLE radio conditions. Using it
#                         here would produce numbers that look like mesh results
#                         and are not.
#
# Multi-device BLE cannot be expressed here at all: one execution targets one
# device, and devices cannot be placed in radio range of each other. That belongs
# to the physical fleet (docs/TESTING.md, layer 3).
#
# Budget note: the four devices above at --timeout 10m is up to 40 physical-device
# minutes for one invocation, which already exceeds the 30 free minutes/day on
# Blaze. Real runs finish well under the timeout, but a hung suite will bill.
# Keep the matrix small on a per-commit trigger and use the full one on releases.

# ---------------------------------------------------------------------------
# One-time setup, for whoever wires this up at v0.9:
#
#   gcloud auth login
#   gcloud config set project insnaps-44c85
#   gcloud services enable testing.googleapis.com toolresults.googleapis.com
#
# Note: no Firebase app registration and no google-services.json are needed. Test
# Lab takes APKs from the command line; insnaps deliberately links no Firebase SDK
# (see docs/TESTING.md).
#
# For CI, create a service account with roles/cloudtestservice.testAdmin and
# roles/firebase.analyticsViewer, and authenticate with a workload-identity
# federation rather than a downloaded JSON key.
# ---------------------------------------------------------------------------
