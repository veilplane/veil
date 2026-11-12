# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# The veil binary and its systemd unit. vendorHash is the hash of the Go dependencies: in a pull
# request that changes go.mod or go.sum, the workflow vendor-hash.yml updates it; by hand:
# nix/update-vendor-hash.sh.
{ lib, buildGoModule, version ? "dev" }:

buildGoModule {
  pname = "veil";
  inherit version;

  src = lib.cleanSourceWith {
    src = ./..;
    filter = path: type: !(lib.hasSuffix ".nix" path) && baseNameOf path != "result";
  };

  vendorHash = "sha256-NI9fBKi3KISK2nn1OwgGijtA36bt7YEFlG8dPsoN0No=";

  subPackages = [ "cmd/veil" ];
  env.CGO_ENABLED = 0;
  ldflags = [ "-s" "-w" "-X main.version=${version}" ];

  # the tests run in CI; some need network namespaces or an etcd binary
  doCheck = false;

  postInstall = ''
    install -Dm644 packaging/veil.service $out/lib/systemd/system/veil.service
    substituteInPlace $out/lib/systemd/system/veil.service --replace-fail /usr/bin/veil $out/bin/veil
  '';

  meta = {
    description = "The Veilplane agent: end-to-end encrypted etcd for Kubernetes and a WireGuard mesh";
    homepage = "https://github.com/veilplane/veil";
    license = {
      shortName = "FSL-1.1-ALv2";
      fullName = "Functional Source License, Version 1.1, ALv2 Future License";
      url = "https://fsl.software";
      free = false;
      redistributable = true;
    };
    platforms = lib.platforms.linux;
    mainProgram = "veil";
  };
}
