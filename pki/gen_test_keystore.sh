#!/bin/bash

BPAK=bpak
IMG=internal_keystore.bpak
PKG_UUID=5df103ef-e774-450b-95c5-1fef51ceec28

set -e

$BPAK create $IMG -Y

$BPAK add $IMG --meta bpak-package --from-string $PKG_UUID --encoder uuid

$BPAK add $IMG --part pb-development \
               --from-file secp256r1-pub-key.der \
               --encoder key

$BPAK add $IMG --part pb-development2 \
               --from-file secp384r1-pub-key.der \
               --encoder key

$BPAK add $IMG --part pb-development3 \
               --from-file secp521r1-pub-key.der \
               --encoder key

$BPAK add $IMG --part pb-development4 \
               --from-file dev_rsa_public.der \
               --encoder key

$BPAK add $IMG --meta bpak-key-store --from-string ks-internal --encoder id

$BPAK generate keystore $IMG --name internal

