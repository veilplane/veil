# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# veil for Nix: the packages (nix build, nix run) and a NixOS module (services.veil).
#
#   nix run github:veilplane/veil/v1.2.3 -- version
#   nix run github:veilplane/veil/v1.2.3#veilctl -- login      # also on macOS
#
#   # NixOS (flake input "veil"):
#   imports = [ veil.nixosModules.default ];
#   services.veil = { enable = true; settings.join = "/run/secrets/veil.invite"; };
{
  description = "veil, the Veilplane agent, and veilctl";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      linux = [ "x86_64-linux" "aarch64-linux" ];
      systems = linux ++ [ "x86_64-darwin" "aarch64-darwin" ];
      # source-available (FSL-1.1-ALv2), which nixpkgs counts as unfree: allow these, and only these
      forAll = f: lib.genAttrs systems (system: f system (import nixpkgs {
        inherit system;
        config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "veil" "veilctl" ];
      }));
      version = "0-unstable-" + builtins.substring 0 8 (self.lastModifiedDate or "19700101");
    in
    {
      packages = forAll (system: pkgs:
        let
          veil = pkgs.callPackage ./nix/package.nix { inherit version; };
          # veilctl: the same source and Go dependencies (and vendorHash), another program
          veilctl = veil.overrideAttrs (old: {
            pname = "veilctl";
            subPackages = [ "cmd/veilctl" ];
            nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.installShellFiles ];
            postInstall = ''
              installShellCompletion --cmd veilctl \
                --bash <($out/bin/veilctl completion bash) \
                --zsh <($out/bin/veilctl completion zsh) \
                --fish <($out/bin/veilctl completion fish)
            '';
            meta = old.meta // {
              description = "Veilplane from the terminal: organizations, clusters, nodes, API tokens";
              platforms = lib.platforms.linux ++ lib.platforms.darwin;
              mainProgram = "veilctl";
            };
          });
        in
        if builtins.elem system linux then { inherit veil veilctl; default = veil; }
        else { inherit veilctl; default = veilctl; });

      nixosModules.default = import ./nix/module.nix self;
    };
}
