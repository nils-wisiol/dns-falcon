#!/usr/bin/env bash
set -o xtrace
set -e

auth() {
  docker-compose exec auth "$@"
}

recursor() {
  docker-compose exec recursor "$@"
}

zone() {
  ZONE=$1
  auth pdnsutil create-zone "$ZONE"
  auth pdnsutil add-record "$ZONE" @ A 127.0.0.1
  auth pdnsutil add-record "$ZONE" @ A 127.0.0.2
  auth pdnsutil add-record "$ZONE" @ AAAA ::1
  auth pdnsutil add-record "$ZONE" @ TXT "\"FALCON DNSSEQ PoC; details: github.com/nils-wisiol/dns-falcon\""
}

zone_classic() {
  ZONE=$1
  zone "$ZONE"
  auth pdnsutil secure-zone "$ZONE"
}

zone_falcon() {
  ZONE=$1
  zone "$ZONE"
  auth pdnsutil add-zone-key "$ZONE" active falcon
}

ds() {
  ZONE=$1
  auth pdnsutil export-zone-ds "$ZONE" | grep SHA256 | grep -oE '([0-9]+\s){3}[0-9a-f]+'
}

trustanchor() {
  ZONE=$1
  recursor rec_control add-ta example. "$(ds "$1")"
}

delegate() {
  SUBNAME=$1
  PARENT=$2
  NSIP4=$3
  ZONE="$SUBNAME.$PARENT"
  NS="ns.$SUBNAME.$PARENT"
  auth pdnsutil add-record "$ZONE" "ns" A "$NSIP4"
  auth pdnsutil add-record "$ZONE" @ NS "$NS"
  auth pdnsutil add-record "$PARENT" "$SUBNAME" NS "$NS"
  auth pdnsutil add-record "$PARENT" "$SUBNAME" DS "$(ds "$ZONE")"
}

# create .example root and set trust anchor
zone_classic "example."
trustanchor "example."

# create test zones
zone_classic "classic.example."
delegate "classic" "example." "172.20.53.101"
zone_falcon "falcon.example."
delegate "falcon" "example." "172.20.53.101"

auth pdnsutil rectify-all-zones
