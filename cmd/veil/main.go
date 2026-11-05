// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// veil: the Veilplane agent and its tools.
//
//	veil agent     run in the background (systemd): the etcd proxy, the mesh, as the backend says
//	veil status    what the agent runs (its status file)
//	veil invite    an invite file for one more node (on a control plane node)
//	veil leave     unenroll this node
//	veil version
//
// Every command takes only the two directories: -config (VEIL_CONFIG, default /etc/veil) with
// agent.json, and -state (VEIL_STATE, default /var/lib/veil) with the agent's own files.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/veilplane/veil/agent"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3"
var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `veil %s, the Veilplane agent

  veil agent                     run the agent (systemd: veil.service)
  veil status [-json]            what the agent runs
  veil invite -o FILE [-node NAME] [-worker] [-ttl 24h]
                                 an invite file for one more node (control plane nodes only)
  veil leave                     unenroll this node
  veil version

Directories (every command): -config DIR (VEIL_CONFIG, default /etc/veil) holds agent.json,
-state DIR (VEIL_STATE, default /var/lib/veil) the agent's own files and its status file.
`, version)
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var p agent.Paths
	fs.StringVar(&p.Config, "config", env("VEIL_CONFIG", "/etc/veil"), "directory with agent.json")
	fs.StringVar(&p.State, "state", env("VEIL_STATE", "/var/lib/veil"), "the agent's directory")
	asJSON := fs.Bool("json", false, "status: print the status file as it is")
	node := fs.String("node", "", "invite: the new node's name (required for a worker)")
	worker := fs.Bool("worker", false, "invite: a worker node (mesh only, no master key)")
	ttl := fs.Duration("ttl", 0, "invite: validity of the code (default: the backend's, 24h)")
	out := fs.String("o", "", "invite: the file to write")
	fs.Usage = usage
	fs.Parse(os.Args[2:])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var err error
	switch cmd {
	case "agent":
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)).With("version", version))
		log.SetFlags(0)
		err = agent.Run(ctx, p, version)
	case "status":
		var s *agent.Status
		if s, err = agent.ReadStatus(p); err == nil {
			if *asJSON {
				raw, _ := json.MarshalIndent(s, "", "  ")
				fmt.Println(string(raw))
			} else {
				fmt.Print(agent.FormatStatus(s))
			}
		}
	case "invite":
		if *out == "" {
			err = fmt.Errorf("invite needs -o FILE")
			break
		}
		tctx, cancel := context.WithTimeout(ctx, time.Minute)
		var inv *agent.Invite
		if inv, err = agent.CreateInvite(tctx, p, version, agent.InviteOptions{Node: *node, Worker: *worker, TTL: *ttl}); err == nil {
			if err = agent.WriteInvite(inv, *out); err == nil {
				fmt.Printf("wrote %s: an invite for one more %s node of cluster %s, valid once, until %s\n", *out, inv.Role, inv.Cluster,
					inv.ExpiresAt.Local().Format(time.DateTime))
				fmt.Printf("copy it to the new node like a password and set there in agent.json:  \"join\": %q\n", *out)
			}
		}
		cancel()
	case "leave":
		tctx, cancel := context.WithTimeout(ctx, time.Minute)
		if err = agent.Leave(tctx, p, version); err == nil {
			fmt.Println("left: the backend refuses this node from now on; the agent stops everything")
		}
		cancel()
	case "version", "-version", "--version":
		fmt.Println("veil", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "veil "+cmd+":", err)
		os.Exit(1)
	}
}
