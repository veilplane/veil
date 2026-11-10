# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# NixOS module: services.veil runs the agent as a systemd service. The default package comes
# from this flake, which allows veil's license itself; the machine needs no allowUnfree. settings becomes
# /etc/veil/agent.json (see the README, section 3). Do not put an invite file or a join code into
# the Nix store, it is readable by everyone on the machine: point settings.join at a file outside
# it (sops-nix, agenix, or copied by hand), e.g. "/run/secrets/veil.invite".
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.veil;
  json = pkgs.formats.json { };
in
{
  options.services.veil = {
    enable = lib.mkEnableOption "the Veilplane agent (veil)";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "veil.packages.\${system}.default";
      description = "The veil package.";
    };

    settings = lib.mkOption {
      type = json.type;
      default = { };
      example = lib.literalExpression ''
        {
          join = "/run/secrets/veil.invite";
          allow = [ "proxy" "mesh" ];
          proxy.listen = "127.0.0.1:2379";
        }
      '';
      description = "Contents of agent.json.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."veil/agent.json".source = json.generate "agent.json" cfg.settings;
    environment.systemPackages = [ cfg.package ];
    # veil manages its WireGuard interface itself
    networking.networkmanager.unmanaged = lib.mkIf config.networking.networkmanager.enable
      [ "interface-name:${cfg.settings.mesh.interface or "veil0"}" ];

    systemd.services.veil = {
      description = "veil (Veilplane agent: end-to-end encrypted etcd, WireGuard mesh)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      before = [ "k3s.service" "kubelet.service" ];
      path = [ pkgs.iproute2 ];
      environment = {
        VEIL_CONFIG = "/etc/veil";
        VEIL_STATE = "/var/lib/veil";
      };
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} agent";
        Restart = "always";
        RestartSec = 2;
        StateDirectory = "veil";
        StateDirectoryMode = "0700";
      };
    };
  };
}
