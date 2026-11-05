# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# veil for Nix: the package (nix build, nix run) and a NixOS module (services.veil).
#
#   nix run github:veilplane/veil/v1.2.3 -- version
#
#   # NixOS (flake input "veil"):
#   imports = [ veil.nixosModules.default ];
#   services.veil = { enable = true; settings.join = "/run/secrets/veil.invite"; };
{
  description = "veil, the Veilplane agent";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = "0-unstable-" + builtins.substring 0 8 (self.lastModifiedDate or "19700101");
    in
    {
      packages = forAll (pkgs: rec {
        veil = pkgs.callPackage ./nix/package.nix { inherit version; };
        default = veil;
      });

      nixosModules.default = import ./nix/module.nix self;
    };
}
