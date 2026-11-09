// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
)

// InstallCommand is what a node runs with a join code.
const InstallCommand = "curl -fsSL https://get.veilplane.com | sudo sh -s -- join "

var globalFlags = []*Flag{
	{Name: "org", Value: "ORG", Usage: "the organization (default: the one chosen with orgs use, or your only one; env VEILCTL_ORG)", Complete: completeOrgs},
	{Name: "json", Usage: "print the API's answer as JSON (for scripts)"},
	{Name: "yes", Short: "y", Usage: "do not ask before deleting or revoking"},
	{Name: "context", Value: "NAME", Usage: "the context (API and sign-in) to use (env VEILCTL_CONTEXT)", Complete: completeContexts},
	{Name: "api", Value: "URL", Usage: "the management API (env VEILCTL_API, default " + DefaultAPI + ")"},
	{Name: "no-color", Usage: "no colors (also: env NO_COLOR)"},
	{Name: "help", Short: "h", Usage: "help for a command"},
}

// Env is where veilctl reads and writes: the terminal, or buffers in tests.
type Env struct {
	In       io.Reader
	Out, Err io.Writer
	TTY      bool // stdin and stderr are a terminal: a person who can answer questions
	OutColor bool // stdout is a terminal
	ErrColor bool // stderr is a terminal
}

// Main runs veilctl with os.Args[1:] on the terminal and returns the exit code.
func Main(argv []string, version string) int {
	env := Env{In: os.Stdin, Out: os.Stdout, Err: os.Stderr,
		TTY:      isTerminal(os.Stdin) && isTerminal(os.Stderr),
		OutColor: isTerminal(os.Stdout), ErrColor: isTerminal(os.Stderr)}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		env.OutColor, env.ErrColor = false, false
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return Run(ctx, argv, version, env)
}

// Run is Main with its surroundings given.
func Run(ctx context.Context, argv []string, version string, env Env) int {
	root := tree()
	root.link()
	c := &Ctx{Context: ctx, Out: env.Out, Stderr: env.Err, In: env.In, tty: env.TTY, version: version,
		st: style{env.OutColor}, est: style{env.ErrColor}}

	if len(argv) > 0 && argv[0] == "__complete" {
		c.flags = map[string]string{}
		c.cfg, _ = loadConfig()
		if c.cfg == nil {
			c.cfg = &Config{Contexts: map[string]*Context{}}
		}
		c.ctxName = c.contextName()
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		c.Context = cctx
		for _, s := range complete(root, globalFlags, c, argv[1:]) {
			fmt.Fprintln(env.Out, s)
		}
		return 0
	}

	cmd, args, flags, err := parse(root, globalFlags, argv)
	if flags["no-color"] == "true" {
		c.st, c.est = style{}, style{}
	}
	c.cmd = cmd
	if err == nil && flags["help"] == "true" {
		cmd.help(env.Out, globalFlags, c.st)
		return 0
	}
	if err == nil && cmd.Run == nil {
		switch {
		case cmd.Default != "" && (len(args) == 0 || cmd.find(cmd.Default).MaxArgs != 0):
			cmd = cmd.find(cmd.Default)
		case len(args) == 0:
			cmd.help(env.Out, globalFlags, c.st)
			return 0
		default:
			msg := fmt.Sprintf("unknown command %q for %q", args[0], cmd.path())
			var names []string
			byAlias := map[string]string{}
			for _, s := range cmd.Sub {
				names = append(names, s.Name)
				for _, a := range s.Aliases {
					byAlias[a] = s.Name
				}
			}
			s := suggest(args[0], names)
			if s == "" {
				var aliases []string
				for a := range byAlias {
					aliases = append(aliases, a)
				}
				sort.Strings(aliases)
				s = byAlias[suggest(args[0], aliases)]
			}
			if s != "" {
				msg += fmt.Sprintf(" (did you mean %q?)", s)
			}
			err = &UsageError{cmd, msg}
		}
	}
	if err == nil {
		switch {
		case len(args) < cmd.MinArgs:
			err = &UsageError{cmd, fmt.Sprintf("%s needs %s", cmd.path(), cmd.Args)}
		case cmd.MaxArgs >= 0 && len(args) > cmd.MaxArgs:
			if cmd.MaxArgs == 0 {
				err = &UsageError{cmd, fmt.Sprintf("%s takes no arguments (got %q)", cmd.path(), args[0])}
			} else {
				err = &UsageError{cmd, fmt.Sprintf("too many arguments: %s %s", cmd.path(), cmd.Args)}
			}
		}
	}
	if err == nil {
		c.cmd, c.Args, c.flags = cmd, args, flags
		if c.cfg, err = loadConfig(); err == nil {
			c.ctxName = c.contextName()
			err = cmd.Run(c)
		}
	}
	return c.report(err)
}

// report prints an error the way a person can act on it, and returns the exit code.
func (c *Ctx) report(err error) int {
	if err == nil {
		return 0
	}
	st := c.est
	var ue *UsageError
	var p *Problem
	switch {
	case errors.As(err, &ue):
		fmt.Fprintf(c.Stderr, "%s %s\n", st.red("error:"), ue.Msg)
		fmt.Fprintln(c.Stderr, st.dim(fmt.Sprintf("See: %s --help", ue.Cmd.path())))
		return 2
	case errors.Is(err, errCanceled), errors.Is(err, context.Canceled):
		fmt.Fprintln(c.Stderr, "canceled")
		return 1
	case errors.As(err, &p):
		fmt.Fprintf(c.Stderr, "%s %s\n", st.red("error:"), p.Error())
		switch p.Status {
		case http.StatusUnauthorized:
			if c.client != nil && c.client.Token != "" {
				fmt.Fprintln(c.Stderr, st.dim("The API token is not valid (deleted or expired)."))
			} else {
				fmt.Fprintln(c.Stderr, st.dim("Not signed in, or the sign-in expired: veilctl login"))
			}
		case http.StatusServiceUnavailable:
			fmt.Fprintln(c.Stderr, st.dim("The cluster's region does not answer right now; try again in a moment."))
		case http.StatusTooManyRequests:
			fmt.Fprintln(c.Stderr, st.dim("Too many of these from your address; try again later."))
		}
		return 1
	}
	fmt.Fprintf(c.Stderr, "%s %v\n", st.red("error:"), err)
	return 1
}

// ---------------------------------------------------------------- context, client, organization

func (c *Ctx) contextName() string {
	switch {
	case c.flag("context") != "":
		return c.flag("context")
	case os.Getenv("VEILCTL_CONTEXT") != "":
		return os.Getenv("VEILCTL_CONTEXT")
	case c.cfg.Current != "":
		return c.cfg.Current
	}
	return "default"
}

// current returns the current context (an empty one if there is none yet; not saved by this).
func (c *Ctx) current() *Context {
	cx := c.cfg.Contexts[c.ctxName]
	if cx == nil {
		cx = &Context{}
		c.cfg.Contexts[c.ctxName] = cx
	}
	return cx
}

func (c *Ctx) apiURL() string {
	switch {
	case c.flag("api") != "":
		return strings.TrimRight(c.flag("api"), "/")
	case os.Getenv("VEILCTL_API") != "":
		return strings.TrimRight(os.Getenv("VEILCTL_API"), "/")
	case c.current().API != "":
		return c.current().API
	}
	return DefaultAPI
}

// api is the client for the current context: VEILCTL_TOKEN, else its token or session.
func (c *Ctx) api() *Client {
	if c.client == nil {
		cx := c.current()
		c.client = &Client{Base: c.apiURL(), UA: userAgent(c.version), Token: cx.Token, Session: cx.Session}
		if t := os.Getenv("VEILCTL_TOKEN"); t != "" {
			c.client.Token, c.client.Session = t, ""
		}
	}
	return c.client
}

func (c *Ctx) signedIn() bool {
	cl := c.api()
	return cl.Token != "" || cl.Session != ""
}

func (c *Ctx) needSignIn() error {
	if !c.signedIn() {
		return &Problem{Status: http.StatusUnauthorized, Detail: "not signed in"}
	}
	return nil
}

func (c *Ctx) get(path string, out any) error {
	_, err := c.api().Do(c, "GET", path, nil, out)
	return err
}

func (c *Ctx) send(method, path string, body, out any) error {
	_, err := c.api().Do(c, method, path, body, out)
	return err
}

// org is the organization to work in: --org, VEILCTL_ORG, the context's, or the only one.
func (c *Ctx) org() (string, error) {
	if err := c.needSignIn(); err != nil {
		return "", err
	}
	switch {
	case c.flag("org") != "":
		return c.flag("org"), nil
	case os.Getenv("VEILCTL_ORG") != "":
		return os.Getenv("VEILCTL_ORG"), nil
	case c.current().Org != "":
		return c.current().Org, nil
	}
	if c.api().Token != "" {
		return "", errors.New("which organization? pass --org (an API token belongs to one organization)")
	}
	var orgs []myOrg
	if err := c.get("/api/v1/me/orgs", &orgs); err != nil {
		return "", err
	}
	switch len(orgs) {
	case 0:
		return "", errors.New("you have no organization yet: veilctl orgs create \"Company name\" (or accept an invitation: veilctl invitations)")
	case 1:
		c.current().Org = orgs[0].Slug
		_ = c.cfg.save()
		return orgs[0].Slug, nil
	}
	var slugs []string
	for _, o := range orgs {
		slugs = append(slugs, o.Slug)
	}
	return "", fmt.Errorf("which organization? veilctl orgs use ORG (or --org); yours: %s", strings.Join(slugs, ", "))
}

// orgPath is /api/v1/orgs/<org> plus more.
func (c *Ctx) orgPath(more string) (string, error) {
	org, err := c.org()
	if err != nil {
		return "", err
	}
	return "/api/v1/orgs/" + esc(org) + more, nil
}

// cluster finds a cluster by id, or else by its name.
func (c *Ctx) cluster(ref string) (*cluster, error) {
	base, err := c.orgPath("/clusters")
	if err != nil {
		return nil, err
	}
	var cl cluster
	err = c.get(base+"/"+esc(ref), &cl)
	if err == nil {
		return &cl, nil
	}
	if !IsStatus(err, http.StatusNotFound) {
		return nil, err
	}
	var all []cluster
	if err := c.get(base, &all); err != nil {
		return nil, err
	}
	var match []cluster
	var ids []string
	for _, x := range all {
		ids = append(ids, x.ID, x.Name)
		if strings.EqualFold(x.Name, ref) {
			match = append(match, x)
		}
	}
	switch len(match) {
	case 1:
		return &match[0], nil
	case 0:
		msg := fmt.Sprintf("no cluster %q", ref)
		if s := suggest(ref, ids); s != "" {
			msg += fmt.Sprintf(" (did you mean %s?)", s)
		}
		return nil, errors.New(msg)
	}
	return nil, fmt.Errorf("several clusters are named %q; use the id", ref)
}

// byPrefix finds the one id that starts with ref (ids are shown shortened).
func byPrefix(ref string, ids []string, what string) (string, error) {
	var found []string
	for _, id := range ids {
		if id == ref {
			return id, nil
		}
		if strings.HasPrefix(id, ref) {
			found = append(found, id)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("no %s %q", what, ref)
	}
	return "", fmt.Errorf("%q fits several %ss; type more of it", ref, what)
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// ---------------------------------------------------------------- the tree

func tree() *Command {
	return &Command{
		Name:  "veilctl",
		Short: "manage Veilplane: organizations, clusters, nodes",
		Long: `Veilplane runs end-to-end encrypted etcd for Kubernetes, and a WireGuard mesh between the
nodes. veilctl does everything the dashboard does, from the terminal.

Start with "veilctl login" (or "veilctl trial" for a cluster without an account).`,
		Example: []string{
			"veilctl login",
			"veilctl clusters create web --region eu",
			"veilctl join-code web",
			"veilctl clusters devices web --watch",
		},
		Sub: []*Command{
			{Name: "login", Group: "Get started", Short: "sign in (e-mail link) or use an API token", Run: cmdLogin,
				Long: `Sends a sign-in link to your e-mail address. Copy the link from the mail (do not open it:
it works once, and opening it signs in the browser instead) and paste it here.

With --token, an API token of an organization is used instead (for scripts and CI; or set
VEILCTL_TOKEN). Each context (--context) has its own API and sign-in.`,
				Flags: []*Flag{
					{Name: "email", Value: "ADDRESS", Usage: "your e-mail address (asked if missing)"},
					{Name: "link", Value: "URL", Usage: "the link from the mail (asked if missing)"},
					{Name: "token", Value: "TOKEN", Usage: "an API token (vpt_...) instead; needs --org"},
				},
				Example: []string{"veilctl login", "veilctl login --token vpt_... --org acme", "veilctl login --context staging --api https://api.staging.example.com"}},
			{Name: "trial", Group: "Get started", Short: "a trial cluster for 30 minutes, no account needed", Default: "start", Sub: []*Command{
				{Name: "start", Short: "start a trial cluster (or show the one running)", Run: cmdTrialStart},
				{Name: "status", Short: "the trial cluster and its nodes", Run: cmdTrialStatus,
					Flags: []*Flag{{Name: "watch", Short: "w", Usage: "keep showing it, every two seconds"}}},
				{Name: "end", Short: "end the trial cluster now", Run: cmdTrialEnd},
			}},

			clustersCmd(),
			{Name: "join-code", Group: "Clusters", Short: "a join code for a cluster's first node (= clusters join-code)", Args: "CLUSTER",
				MinArgs: 1, MaxArgs: 1, Run: cmdJoinCode, Complete: completeClusters, Flags: joinCodeFlags},

			orgsCmd(),
			membersCmd(),
			invitationsCmd(),
			tokensCmd(),
			{Name: "audit", Group: "Organizations", Short: "the organization's audit log (admins)", Run: cmdAudit,
				Flags: []*Flag{
					{Name: "limit", Short: "n", Value: "N", Usage: "how many entries (default 50, at most 500)"},
					{Name: "before", Value: "ID", Usage: "only entries older than this id (paging)"},
					{Name: "all", Usage: "every entry, page after page"},
				}},

			{Name: "whoami", Group: "Account", Short: "who you are signed in as, where", Run: cmdWhoami},
			meCmd(),
			{Name: "sessions", Group: "Account", Short: "where you are signed in", Default: "list", Sub: []*Command{
				{Name: "list", Aliases: []string{"ls"}, Short: "your sessions (browsers, veilctl)", Run: cmdSessions},
				{Name: "revoke", Aliases: []string{"rm"}, Short: "sign out a session", Args: "ID", MinArgs: 1, MaxArgs: 1, Run: cmdSessionRevoke},
			}},
			{Name: "passkeys", Group: "Account", Short: "your passkeys (new ones: in the dashboard)", Default: "list", Sub: []*Command{
				{Name: "list", Aliases: []string{"ls"}, Short: "your passkeys", Run: cmdPasskeys},
				{Name: "delete", Aliases: []string{"rm"}, Short: "delete a passkey", Args: "ID", MinArgs: 1, MaxArgs: 1, Run: cmdPasskeyDelete},
			}},
			{Name: "logout", Group: "Account", Short: "sign out (and forget the token)", Run: cmdLogout},
			{Name: "context", Group: "Account", Short: "contexts: several APIs or sign-ins", Default: "list", Sub: []*Command{
				{Name: "list", Aliases: []string{"ls"}, Short: "the contexts", Run: cmdContexts},
				{Name: "use", Short: "make a context the current one", Args: "NAME", MinArgs: 1, MaxArgs: 1, Run: cmdContextUse, Complete: completeContextArg},
				{Name: "delete", Aliases: []string{"rm"}, Short: "forget a context (signs it out)", Args: "NAME", MinArgs: 1, MaxArgs: 1, Run: cmdContextDelete, Complete: completeContextArg},
			}},

			{Name: "regions", Group: "More", Short: "the regions clusters can live in", Run: cmdRegions},
			{Name: "completion", Group: "More", Short: "shell completion: bash, zsh or fish", Args: "SHELL", MinArgs: 1, MaxArgs: 1, Run: cmdCompletion,
				Complete: func(*Ctx, int) []string { return []string{"bash", "zsh", "fish"} },
				Long: `Prints a completion script. It completes commands, flags and also your clusters,
organizations and members (it asks the API, briefly).`,
				Example: []string{
					"source <(veilctl completion bash)        # bash, in ~/.bashrc",
					"source <(veilctl completion zsh)         # zsh, in ~/.zshrc",
					"veilctl completion fish | source         # fish, in config.fish",
				}},
			{Name: "version", Group: "More", Short: "veilctl's version", Run: func(c *Ctx) error {
				fmt.Fprintf(c.Out, "veilctl %s\n", c.version)
				return nil
			}},
		},
	}
}

var joinCodeFlags = []*Flag{{Name: "node", Value: "NAME", Usage: "the node's name (default: its host name)"}}

func clustersCmd() *Command {
	return &Command{Name: "clusters", Aliases: []string{"cluster", "cl"}, Group: "Clusters", Short: "create, look at and remove clusters, their nodes and mesh", Default: "list",
		Sub: []*Command{
			{Name: "list", Aliases: []string{"ls"}, Short: "the organization's clusters", Run: cmdClusters},
			{Name: "create", Aliases: []string{"new"}, Short: "create a cluster", Args: "NAME", MinArgs: 1, MaxArgs: 1, Run: cmdClusterCreate,
				Flags: []*Flag{
					{Name: "id", Value: "ID", Usage: "its id (lower case letters, digits, -; default: generated)"},
					{Name: "region", Short: "r", Value: "REGION", Usage: "where its data lives (default: the home region)", Complete: completeRegions},
				},
				Example: []string{"veilctl clusters create production --region eu"}},
			{Name: "show", Aliases: []string{"get"}, Short: "a cluster and its nodes", Args: "CLUSTER", MinArgs: 1, MaxArgs: 1, Run: cmdClusterShow, Complete: completeClusters},
			{Name: "rename", Short: "give a cluster another name", Args: "CLUSTER NAME", MinArgs: 2, MaxArgs: 2, Run: cmdClusterRename, Complete: completeClusters},
			{Name: "delete", Aliases: []string{"rm"}, Short: "delete a cluster (restorable for a while)", Args: "CLUSTER", MinArgs: 1, MaxArgs: 1, Run: cmdClusterDelete, Complete: completeClusters},
			{Name: "restore", Short: "bring back a deleted cluster", Args: "CLUSTER", MinArgs: 1, MaxArgs: 1, Run: cmdClusterRestore, Complete: completeClusters},
			{Name: "features", Short: "what the agents run: the etcd proxy, the mesh", Args: "CLUSTER", MinArgs: 1, MaxArgs: 1, Run: cmdFeatures, Complete: completeClusters,
				Flags: []*Flag{
					{Name: "proxy", Value: "on|off", Usage: "the encrypted etcd for kube-apiserver", Complete: completeOnOff},
					{Name: "mesh", Value: "on|off", Usage: "the WireGuard mesh between the nodes", Complete: completeOnOff},
				},
				Example: []string{"veilctl clusters features web --mesh on"}},
			{Name: "join-code", Short: "a join code for the first node", Args: "CLUSTER", MinArgs: 1, MaxArgs: 1, Run: cmdJoinCode, Complete: completeClusters, Flags: joinCodeFlags,
				Long: `The first node of a cluster joins with a join code; more nodes join with an invite file
made on a node of the cluster ("veil invite"). The code goes to stdout, the rest to stderr:
CODE=$(veilctl join-code web) works in scripts.`},
			{Name: "devices", Aliases: []string{"nodes"}, Short: "the cluster's nodes and what their agents run", Args: "CLUSTER [NODE]", MinArgs: 1, MaxArgs: 2,
				Run: cmdDevices, Complete: completeClusterNode,
				Flags: []*Flag{{Name: "watch", Short: "w", Usage: "keep showing them, every two seconds"}}},
			{Name: "revoke", Short: "revoke a node: it stops at once and cannot come back", Args: "CLUSTER NODE", MinArgs: 2, MaxArgs: 2, Run: cmdRevoke, Complete: completeClusterNode},
			{Name: "mesh", Short: "the mesh: who reaches whom, and how", Args: "CLUSTER", MinArgs: 1, MaxArgs: 1, Run: cmdMesh, Complete: completeClusters},
		}}
}

func orgsCmd() *Command {
	return &Command{Name: "orgs", Aliases: []string{"org", "organizations"}, Group: "Organizations", Short: "your organizations", Default: "list",
		Sub: []*Command{
			{Name: "list", Aliases: []string{"ls"}, Short: "your organizations (* the current one)", Run: cmdOrgs},
			{Name: "use", Aliases: []string{"switch"}, Short: "work in this organization from now on", Args: "ORG", MinArgs: 1, MaxArgs: 1, Run: cmdOrgUse, Complete: completeOrgArg},
			{Name: "create", Aliases: []string{"new"}, Short: "create an organization (you become its admin)", Args: "NAME", MinArgs: 1, MaxArgs: 1, Run: cmdOrgCreate,
				Flags:   []*Flag{{Name: "slug", Value: "SLUG", Usage: "its address (default: from the name)"}},
				Example: []string{`veilctl orgs create "Acme Inc." --slug acme`}},
			{Name: "show", Aliases: []string{"get"}, Short: "an organization", Args: "[ORG]", MaxArgs: 1, Run: cmdOrgShow, Complete: completeOrgArg},
			{Name: "update", Short: "rename an organization or change its address (admins)", Args: "[ORG]", MaxArgs: 1, Run: cmdOrgUpdate, Complete: completeOrgArg,
				Flags: []*Flag{{Name: "name", Value: "NAME", Usage: "its new name"}, {Name: "slug", Value: "SLUG", Usage: "its new address"}}},
			{Name: "delete", Aliases: []string{"rm"}, Short: "delete an organization and all its clusters (admins)", Args: "ORG", MinArgs: 1, MaxArgs: 1, Run: cmdOrgDelete, Complete: completeOrgArg},
		}}
}

func membersCmd() *Command {
	return &Command{Name: "members", Aliases: []string{"member"}, Group: "Organizations", Short: "who belongs to the organization, and invitations", Default: "list",
		Sub: []*Command{
			{Name: "list", Aliases: []string{"ls"}, Short: "the members", Run: cmdMembers},
			{Name: "invite", Short: "invite someone by e-mail (admins)", Args: "EMAIL", MinArgs: 1, MaxArgs: 1, Run: cmdInvite,
				Flags: []*Flag{{Name: "admin", Usage: "as an admin"}}},
			{Name: "invitations", Short: "open invitations of the organization", Run: cmdOrgInvitations},
			{Name: "withdraw", Short: "withdraw an invitation (admins)", Args: "ID|EMAIL", MinArgs: 1, MaxArgs: 1, Run: cmdWithdraw},
			{Name: "promote", Short: "make a member admin (admins)", Args: "MEMBER", MinArgs: 1, MaxArgs: 1, Run: cmdPromote, Complete: completeMembers},
			{Name: "demote", Short: "make an admin a plain member (admins)", Args: "MEMBER", MinArgs: 1, MaxArgs: 1, Run: cmdDemote, Complete: completeMembers},
			{Name: "remove", Aliases: []string{"rm"}, Short: "remove a member (admins)", Args: "MEMBER", MinArgs: 1, MaxArgs: 1, Run: cmdRemoveMember, Complete: completeMembers},
			{Name: "leave", Short: "leave the organization", Run: cmdLeave},
		}}
}

func invitationsCmd() *Command {
	return &Command{Name: "invitations", Aliases: []string{"invitation", "invites"}, Group: "Organizations", Short: "invitations for you", Default: "list",
		Sub: []*Command{
			{Name: "list", Aliases: []string{"ls"}, Short: "open invitations for your address", Run: cmdMyInvitations},
			{Name: "show", Short: "look at an invitation link", Args: "LINK", MinArgs: 1, MaxArgs: 1, Run: cmdInvitationShow},
			{Name: "accept", Short: "accept an invitation (its id, or the link from the mail)", Args: "ID|LINK", MinArgs: 1, MaxArgs: 1, Run: cmdAccept},
			{Name: "decline", Short: "decline an invitation", Args: "ID", MinArgs: 1, MaxArgs: 1, Run: cmdDecline},
		}}
}

func tokensCmd() *Command {
	return &Command{Name: "tokens", Aliases: []string{"token"}, Group: "Organizations", Short: "API tokens for scripts and CI", Default: "list",
		Long: `An API token acts as a member (not an admin) of one organization. Use it with
VEILCTL_TOKEN=... veilctl ..., or veilctl login --token ... --org ORG.`,
		Sub: []*Command{
			{Name: "list", Aliases: []string{"ls"}, Short: "the organization's API tokens", Run: cmdTokens},
			{Name: "create", Aliases: []string{"new"}, Short: "create an API token (shown once)", Args: "NAME", MinArgs: 1, MaxArgs: 1, Run: cmdTokenCreate,
				Flags:   []*Flag{{Name: "expires", Value: "DAYS", Usage: "valid for so long: 90, 90d, 12w, 6m, 1y (default: until deleted)"}},
				Example: []string{"veilctl tokens create ci --expires 90d"}},
			{Name: "delete", Aliases: []string{"rm"}, Short: "delete an API token (it stops working at once)", Args: "TOKEN", MinArgs: 1, MaxArgs: 1, Run: cmdTokenDelete, Complete: completeTokens},
		}}
}

func meCmd() *Command {
	return &Command{Name: "me", Group: "Account", Short: "your account", Default: "show", Sub: []*Command{
		{Name: "show", Short: "your account", Run: cmdWhoami},
		{Name: "update", Short: "change your name or the language of mails", Run: cmdMeUpdate,
			Flags: []*Flag{{Name: "name", Value: "NAME", Usage: "your name"}, {Name: "locale", Value: "de|en", Usage: "language of mails",
				Complete: func(*Ctx) []string { return []string{"de", "en"} }}}},
		{Name: "delete", Short: "delete your account here", Run: cmdMeDelete},
	}}
}

// ---------------------------------------------------------------- sign-in

func locale() string {
	for _, v := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if s := os.Getenv(v); s != "" {
			if strings.HasPrefix(s, "de") {
				return "de"
			}
			return "en"
		}
	}
	return "en"
}

// linkToken takes the token out of a pasted link (or takes the token itself).
func linkToken(s string) (string, error) {
	s = strings.Trim(strings.TrimSpace(s), "<>\"'")
	if strings.Contains(s, "token=") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("that is not the link from the mail: %v", err)
		}
		if t := u.Query().Get("token"); t != "" {
			return t, nil
		}
	}
	if s == "" || strings.ContainsAny(s, " /?&") {
		return "", errors.New("that is not the link from the mail (it contains token=...)")
	}
	return s, nil
}

func cmdLogin(c *Ctx) error {
	cx := c.current()
	api := c.apiURL()
	cl := &Client{Base: api, UA: userAgent(c.version)}

	if tok := c.flag("token"); tok != "" {
		org := c.flag("org")
		if org == "" {
			return &UsageError{c.cmd, "--token needs --org: the organization the token belongs to"}
		}
		cl.Token = tok
		var o organization
		if _, err := cl.Do(c, "GET", "/api/v1/orgs/"+esc(org), nil, &o); err != nil {
			return fmt.Errorf("the token does not work for %s: %w", org, err)
		}
		*cx = Context{API: api, Token: tok, Org: o.Slug}
		c.cfg.Current = c.ctxName
		if err := c.cfg.save(); err != nil {
			return err
		}
		c.done("Signed in with an API token of %s (%s)", c.est.bold(o.Name), o.Slug)
		return nil
	}

	email := c.flag("email")
	if email == "" {
		var err error
		if email, err = c.ask("E-mail address: "); err != nil {
			return err
		}
	}
	if !strings.Contains(email, "@") {
		return fmt.Errorf("%q is not an e-mail address", email)
	}
	if _, err := cl.Do(c, "POST", "/api/v1/auth/link", map[string]string{"email": email, "locale": locale()}, nil); err != nil {
		return err
	}
	link := c.flag("link")
	if link == "" {
		c.say("A sign-in link is on its way to %s (valid for 15 minutes).", c.est.bold(email))
		c.say("Copy the link from the mail %s and paste it here.", c.est.yellow("without opening it"))
		var err error
		if link, err = c.ask("Link: "); err != nil {
			return err
		}
	}
	token, err := linkToken(link)
	if err != nil {
		return err
	}
	var si signedIn
	hdr, err := cl.Do(c, "POST", "/api/v1/auth/link/verify", map[string]string{"token": token}, &si)
	if err != nil {
		if IsStatus(err, http.StatusForbidden) {
			return errors.New("the link is used or expired (opening it in a browser uses it): run veilctl login again")
		}
		return err
	}
	var cookie string
	for _, ck := range (&http.Response{Header: hdr}).Cookies() {
		if ck.Value != "" && (cookie == "" || strings.Contains(ck.Name, "veilplane")) {
			cookie = ck.Name + "=" + ck.Value
		}
	}
	if cookie == "" {
		return errors.New("signed in, but the API sent no session")
	}
	org := ""
	if cx.API == api && cx.Email == si.Email {
		org = cx.Org // the same account again: keep its organization
	}
	*cx = Context{API: api, Email: si.Email, Session: cookie, Org: org}
	c.cfg.Current = c.ctxName
	c.client = nil
	if err := c.cfg.save(); err != nil {
		return err
	}
	if si.NewAccount {
		c.done("Welcome to Veilplane, %s: your account is ready", c.est.bold(si.Email))
	} else {
		c.done("Signed in as %s", c.est.bold(si.Email))
	}
	c.afterSignIn()
	return nil
}

// afterSignIn says where to go next: the organization, open invitations.
func (c *Ctx) afterSignIn() {
	var orgs []myOrg
	if c.get("/api/v1/me/orgs", &orgs) == nil {
		cx := c.current()
		if cx.Org != "" && !slices.ContainsFunc(orgs, func(o myOrg) bool { return o.Slug == cx.Org }) {
			cx.Org = ""
		}
		if cx.Org == "" && len(orgs) == 1 {
			cx.Org = orgs[0].Slug
		}
		_ = c.cfg.save()
		switch {
		case cx.Org != "":
			c.say("Organization: %s%s", c.est.bold(cx.Org), map[bool]string{true: c.est.dim(" (switch: veilctl orgs use ORG)"), false: ""}[len(orgs) > 1])
		case len(orgs) > 1:
			c.hint("Choose an organization: veilctl orgs use ORG (yours: veilctl orgs)")
		default:
			c.hint("Next: veilctl orgs create \"Company name\"")
		}
	}
	var inv []myInvitation
	if c.get("/api/v1/me/invitations", &inv) == nil && len(inv) > 0 {
		c.say("%s waiting for you: veilctl invitations", plural(len(inv), "invitation"))
	}
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

func cmdLogout(c *Ctx) error {
	cx := c.current()
	if cx.Session == "" && cx.Token == "" {
		c.say("Not signed in (context %s).", c.ctxName)
		return nil
	}
	if cx.Session != "" {
		if err := c.send("POST", "/api/v1/auth/logout", nil, nil); err != nil && !IsStatus(err, http.StatusUnauthorized) {
			c.say("The API did not confirm (%v); forgetting the session here anyway.", err)
		}
	}
	cx.Session, cx.Token = "", ""
	if err := c.cfg.save(); err != nil {
		return err
	}
	c.done("Signed out")
	return nil
}

func cmdWhoami(c *Ctx) error {
	if err := c.needSignIn(); err != nil {
		return err
	}
	cx := c.current()
	if c.api().Token != "" {
		org := cx.Org
		if c.flag("org") != "" {
			org = c.flag("org")
		}
		if c.json() {
			return c.printJSON(map[string]string{"kind": "token", "org": org, "api": c.apiURL()})
		}
		fields(c.Out, c.st, [][2]string{{"signed in", "with an API token"}, {"organization", org}, {"api", c.apiURL()}, {"context", c.ctxName}})
		return nil
	}
	var raw json.RawMessage
	if err := c.get("/api/v1/me", &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var m me
	_ = json.Unmarshal(raw, &m)
	org := cx.Org
	if org == "" {
		org = c.st.dim("(none chosen)")
	}
	fields(c.Out, c.st, [][2]string{
		{"e-mail", m.Email + map[bool]string{true: "", false: c.st.yellow(" (not confirmed)")}[m.EmailVerified]},
		{"name", m.Name}, {"language", m.Locale}, {"organization", org}, {"api", c.apiURL()}, {"context", c.ctxName},
	})
	return nil
}

func cmdMeUpdate(c *Ctx) error {
	body := map[string]string{}
	if c.has("name") {
		body["name"] = c.flag("name")
	}
	if c.has("locale") {
		body["locale"] = c.flag("locale")
	}
	if len(body) == 0 {
		return &UsageError{c.cmd, "nothing to change: --name or --locale"}
	}
	var raw json.RawMessage
	if err := c.send("PATCH", "/api/v1/me", body, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	c.done("Saved")
	return nil
}

func cmdMeDelete(c *Ctx) error {
	var m me
	if err := c.get("/api/v1/me", &m); err != nil {
		return err
	}
	if err := c.confirm("This deletes your account (organizations where you are the last admin go first).", m.Email); err != nil {
		return err
	}
	if err := c.send("DELETE", "/api/v1/me", nil, nil); err != nil {
		return err
	}
	cx := c.current()
	cx.Session, cx.Org = "", ""
	_ = c.cfg.save()
	c.done("Your account is deleted")
	return nil
}

func cmdSessions(c *Ctx) error {
	var raw json.RawMessage
	if err := c.get("/api/v1/auth/sessions", &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var ss []session
	_ = json.Unmarshal(raw, &ss)
	var rows [][]string
	for _, s := range ss {
		id := short(s.ID)
		if s.Current {
			id += c.st.green(" (this)")
		}
		rows = append(rows, []string{id, client(s.UserAgent), s.IP, ago(s.LastSeenAt), ago(s.CreatedAt)})
	}
	table(c.Out, c.st, []string{"ID", "CLIENT", "IP", "LAST SEEN", "SIGNED IN"}, rows)
	return nil
}

// client shortens a user agent to what people recognise.
func client(ua string) string {
	switch {
	case strings.HasPrefix(ua, "veilctl/"):
		return strings.SplitN(ua, " ", 2)[0]
	case strings.Contains(ua, "Firefox/"):
		return "Firefox" + osOf(ua)
	case strings.Contains(ua, "Edg/"):
		return "Edge" + osOf(ua)
	case strings.Contains(ua, "Chrome/"):
		return "Chrome" + osOf(ua)
	case strings.Contains(ua, "Safari/"):
		return "Safari" + osOf(ua)
	case ua == "":
		return "-"
	}
	if len(ua) > 40 {
		return ua[:40] + "…"
	}
	return ua
}

func osOf(ua string) string {
	for _, p := range [][2]string{{"Android", "Android"}, {"iPhone", "iOS"}, {"iPad", "iPadOS"}, {"Mac OS X", "macOS"}, {"Windows", "Windows"}, {"Linux", "Linux"}} {
		if strings.Contains(ua, p[0]) {
			return " on " + p[1]
		}
	}
	return ""
}

func cmdSessionRevoke(c *Ctx) error {
	var ss []session
	if err := c.get("/api/v1/auth/sessions", &ss); err != nil {
		return err
	}
	var ids []string
	for _, s := range ss {
		ids = append(ids, s.ID)
	}
	id, err := byPrefix(c.Args[0], ids, "session")
	if err != nil {
		return err
	}
	if err := c.send("DELETE", "/api/v1/auth/sessions/"+esc(id), nil, nil); err != nil {
		return err
	}
	c.done("Session %s signed out", short(id))
	return nil
}

func cmdPasskeys(c *Ctx) error {
	var raw json.RawMessage
	if err := c.get("/api/v1/auth/passkeys", &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var ps []passkey
	_ = json.Unmarshal(raw, &ps)
	if len(ps) == 0 {
		c.say("No passkeys yet. Create one in the dashboard: it signs you in without a mail.")
		return nil
	}
	var rows [][]string
	for _, p := range ps {
		rows = append(rows, []string{short(p.ID), p.Name, ago(p.CreatedAt), agoPtr(p.LastUsedAt)})
	}
	table(c.Out, c.st, []string{"ID", "NAME", "CREATED", "LAST USED"}, rows)
	return nil
}

func cmdPasskeyDelete(c *Ctx) error {
	var ps []passkey
	if err := c.get("/api/v1/auth/passkeys", &ps); err != nil {
		return err
	}
	var ids []string
	name := map[string]string{}
	for _, p := range ps {
		ids = append(ids, p.ID)
		name[p.ID] = p.Name
	}
	id, err := byPrefix(c.Args[0], ids, "passkey")
	if err != nil {
		return err
	}
	if err := c.confirm(fmt.Sprintf("This deletes the passkey %q.", name[id]), short(id)); err != nil {
		return err
	}
	if err := c.send("DELETE", "/api/v1/auth/passkeys/"+esc(id), nil, nil); err != nil {
		return err
	}
	c.done("Passkey %q deleted", name[id])
	return nil
}

// ---------------------------------------------------------------- contexts

func cmdContexts(c *Ctx) error {
	if c.json() {
		out := map[string]any{"current": c.ctxName}
		list := map[string]any{}
		for n, cx := range c.cfg.Contexts {
			list[n] = map[string]any{"api": cx.API, "email": cx.Email, "org": cx.Org, "token": cx.Token != "", "signedIn": cx.Session != "" || cx.Token != ""}
		}
		out["contexts"] = list
		return c.printJSON(out)
	}
	if len(c.cfg.Contexts) == 0 {
		c.say("No contexts yet: veilctl login creates one.")
		return nil
	}
	names := make([]string, 0, len(c.cfg.Contexts))
	for n := range c.cfg.Contexts {
		names = append(names, n)
	}
	sort.Strings(names)
	var rows [][]string
	for _, n := range names {
		cx := c.cfg.Contexts[n]
		who := c.st.dim("signed out")
		switch {
		case cx.Token != "":
			who = "API token"
		case cx.Session != "":
			who = cx.Email
		}
		mark := " "
		if n == c.ctxName {
			mark = c.st.green("*")
		}
		api := cx.API
		if api == "" {
			api = DefaultAPI
		}
		rows = append(rows, []string{mark + " " + n, who, cx.Org, api})
	}
	table(c.Out, c.st, []string{"  NAME", "SIGNED IN", "ORG", "API"}, rows)
	return nil
}

func cmdContextUse(c *Ctx) error {
	name := c.Args[0]
	if _, ok := c.cfg.Contexts[name]; !ok {
		return fmt.Errorf("no context %q (veilctl login --context %s creates it)", name, name)
	}
	c.cfg.Current = name
	if err := c.cfg.save(); err != nil {
		return err
	}
	c.done("Context %s", name)
	return nil
}

func cmdContextDelete(c *Ctx) error {
	name := c.Args[0]
	cx, ok := c.cfg.Contexts[name]
	if !ok {
		return fmt.Errorf("no context %q", name)
	}
	if cx.Session != "" {
		cl := &Client{Base: cx.API, Session: cx.Session, UA: userAgent(c.version)}
		if cl.Base == "" {
			cl.Base = DefaultAPI
		}
		_, _ = cl.Do(c, "POST", "/api/v1/auth/logout", nil, nil)
	}
	delete(c.cfg.Contexts, name)
	if c.cfg.Current == name {
		c.cfg.Current = ""
	}
	if err := c.cfg.save(); err != nil {
		return err
	}
	c.done("Context %s forgotten", name)
	return nil
}

// ---------------------------------------------------------------- organizations

func cmdOrgs(c *Ctx) error {
	if err := c.needSignIn(); err != nil {
		return err
	}
	if c.api().Token != "" {
		return errors.New("an API token belongs to one organization; veilctl orgs show")
	}
	var raw json.RawMessage
	if err := c.get("/api/v1/me/orgs", &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var orgs []myOrg
	_ = json.Unmarshal(raw, &orgs)
	if len(orgs) == 0 {
		c.say("No organizations yet: veilctl orgs create \"Company name\"")
		return nil
	}
	cur := c.current().Org
	if c.flag("org") != "" {
		cur = c.flag("org")
	}
	var rows [][]string
	for _, o := range orgs {
		mark := " "
		if o.Slug == cur {
			mark = c.st.green("*")
		}
		role := "member"
		if o.Admin {
			role = "admin"
		}
		rows = append(rows, []string{mark + " " + o.Slug, o.Name, role, o.Plan})
	}
	table(c.Out, c.st, []string{"  ORG", "NAME", "ROLE", "PLAN"}, rows)
	if cur == "" && len(orgs) > 1 {
		c.hint("\nChoose one: veilctl orgs use ORG")
	}
	return nil
}

func cmdOrgUse(c *Ctx) error {
	if err := c.needSignIn(); err != nil {
		return err
	}
	var o organization
	if err := c.get("/api/v1/orgs/"+esc(c.Args[0]), &o); err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return fmt.Errorf("no organization %q of yours (veilctl orgs lists them)", c.Args[0])
		}
		return err
	}
	c.current().Org = o.Slug
	if err := c.cfg.save(); err != nil {
		return err
	}
	c.done("Working in %s (%s)", c.est.bold(o.Name), o.Slug)
	return nil
}

func cmdOrgCreate(c *Ctx) error {
	if err := c.needSignIn(); err != nil {
		return err
	}
	body := map[string]string{"name": c.Args[0]}
	if c.has("slug") {
		body["slug"] = c.flag("slug")
	}
	var raw json.RawMessage
	if err := c.send("POST", "/api/v1/orgs", body, &raw); err != nil {
		return err
	}
	var o organization
	_ = json.Unmarshal(raw, &o)
	if c.current().Org == "" {
		c.current().Org = o.Slug
		_ = c.cfg.save()
	}
	if c.json() {
		return c.printJSON(raw)
	}
	c.done("Created %s (%s)", c.est.bold(o.Name), o.Slug)
	if c.current().Org == o.Slug {
		c.hint("Next: veilctl clusters create NAME")
	} else {
		c.hint("Work in it: veilctl orgs use %s", o.Slug)
	}
	return nil
}

func (c *Ctx) orgArg() (string, error) {
	if len(c.Args) > 0 {
		return c.Args[0], nil
	}
	return c.org()
}

func cmdOrgShow(c *Ctx) error {
	slug, err := c.orgArg()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get("/api/v1/orgs/"+esc(slug), &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var o organization
	_ = json.Unmarshal(raw, &o)
	role := "member"
	if o.Admin {
		role = "admin"
	}
	fields(c.Out, c.st, [][2]string{{"org", o.Slug}, {"name", o.Name}, {"plan", o.Plan}, {"status", c.st.state(o.Status)},
		{"your role", role}, {"created", o.CreatedAt.Local().Format("2006-01-02") + " (" + ago(o.CreatedAt) + ")"}})
	return nil
}

func cmdOrgUpdate(c *Ctx) error {
	slug, err := c.orgArg()
	if err != nil {
		return err
	}
	body := map[string]string{}
	if c.has("name") {
		body["name"] = c.flag("name")
	}
	if c.has("slug") {
		body["slug"] = c.flag("slug")
	}
	if len(body) == 0 {
		return &UsageError{c.cmd, "nothing to change: --name or --slug"}
	}
	var raw json.RawMessage
	if err := c.send("PATCH", "/api/v1/orgs/"+esc(slug), body, &raw); err != nil {
		return err
	}
	var o organization
	_ = json.Unmarshal(raw, &o)
	if c.current().Org == slug && o.Slug != slug {
		c.current().Org = o.Slug
		_ = c.cfg.save()
	}
	if c.json() {
		return c.printJSON(raw)
	}
	c.done("Saved: %s (%s)", o.Name, o.Slug)
	return nil
}

func cmdOrgDelete(c *Ctx) error {
	slug := c.Args[0]
	var o organization
	if err := c.get("/api/v1/orgs/"+esc(slug), &o); err != nil {
		return err
	}
	if err := c.confirm(fmt.Sprintf("This deletes the organization %s with all its clusters and their data.", o.Name), o.Slug); err != nil {
		return err
	}
	if err := c.send("DELETE", "/api/v1/orgs/"+esc(o.Slug), nil, nil); err != nil {
		return err
	}
	if c.current().Org == o.Slug {
		c.current().Org = ""
		_ = c.cfg.save()
	}
	c.done("Organization %s deleted", o.Slug)
	return nil
}

// ---------------------------------------------------------------- members and invitations

func (c *Ctx) members() (string, []member, error) {
	base, err := c.orgPath("/members")
	if err != nil {
		return "", nil, err
	}
	var ms []member
	if err := c.get(base, &ms); err != nil {
		return "", nil, err
	}
	return base, ms, nil
}

// member finds a member by e-mail address, name or id.
func (c *Ctx) member(ref string) (string, *member, error) {
	base, err := c.orgPath("/members")
	if err != nil {
		return "", nil, err
	}
	var ms []member
	if err := c.get(base, &ms); err != nil {
		return "", nil, err
	}
	var found []member
	for _, m := range ms {
		local, _, _ := strings.Cut(m.Email, "@")
		if strings.EqualFold(m.Email, ref) || m.UserID == ref || strings.EqualFold(m.Name, ref) || strings.EqualFold(local, ref) ||
			(len(ref) >= 4 && strings.HasPrefix(m.UserID, ref)) {
			found = append(found, m)
		}
	}
	switch len(found) {
	case 1:
		return base, &found[0], nil
	case 0:
		return "", nil, fmt.Errorf("no member %q (veilctl members lists them)", ref)
	}
	return "", nil, fmt.Errorf("%q fits several members; use the e-mail address", ref)
}

func cmdMembers(c *Ctx) error {
	base, err := c.orgPath("/members")
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(base, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var ms []member
	_ = json.Unmarshal(raw, &ms)
	myEmail := c.current().Email
	var rows [][]string
	for _, m := range ms {
		role := "member"
		if m.Admin {
			role = c.st.cyan("admin")
		}
		email := m.Email
		if strings.EqualFold(email, myEmail) {
			email += c.st.dim(" (you)")
		}
		rows = append(rows, []string{email, m.Name, role, ago(m.Since)})
	}
	table(c.Out, c.st, []string{"MEMBER", "NAME", "ROLE", "SINCE"}, rows)
	return nil
}

func cmdInvite(c *Ctx) error {
	base, err := c.orgPath("/invitations")
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.send("POST", base, map[string]any{"email": c.Args[0], "admin": c.on("admin")}, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var inv invitation
	_ = json.Unmarshal(raw, &inv)
	c.done("Invited %s%s; the mail is on its way (valid %s)", c.est.bold(inv.Email), map[bool]string{true: " as admin", false: ""}[inv.Admin], ago(inv.ExpiresAt))
	if inv.Link != "" {
		c.say("Or send the link yourself (it only works for %s):", inv.Email)
		fmt.Fprintln(c.Out, inv.Link)
	}
	return nil
}

func cmdOrgInvitations(c *Ctx) error {
	base, err := c.orgPath("/invitations")
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(base, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var invs []invitation
	_ = json.Unmarshal(raw, &invs)
	if len(invs) == 0 {
		c.say("No open invitations.")
		return nil
	}
	var rows [][]string
	for _, i := range invs {
		role := "member"
		if i.Admin {
			role = "admin"
		}
		rows = append(rows, []string{short(i.ID), i.Email, role, i.InvitedBy, ago(i.ExpiresAt)})
	}
	table(c.Out, c.st, []string{"ID", "E-MAIL", "AS", "INVITED BY", "EXPIRES"}, rows)
	return nil
}

func cmdWithdraw(c *Ctx) error {
	base, err := c.orgPath("/invitations")
	if err != nil {
		return err
	}
	var invs []invitation
	if err := c.get(base, &invs); err != nil {
		return err
	}
	var ids []string
	for _, i := range invs {
		if strings.EqualFold(i.Email, c.Args[0]) {
			ids = []string{i.ID}
			c.Args[0] = i.ID
			break
		}
		ids = append(ids, i.ID)
	}
	id, err := byPrefix(c.Args[0], ids, "invitation")
	if err != nil {
		return err
	}
	if err := c.send("DELETE", base+"/"+esc(id), nil, nil); err != nil {
		return err
	}
	c.done("Invitation withdrawn")
	return nil
}

func (c *Ctx) setAdmin(admin bool) error {
	base, m, err := c.member(c.Args[0])
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.send("PATCH", base+"/"+esc(m.UserID), map[string]bool{"admin": admin}, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	if admin {
		c.done("%s is an admin now", m.Email)
	} else {
		c.done("%s is a member now (not an admin)", m.Email)
	}
	return nil
}

func cmdPromote(c *Ctx) error { return c.setAdmin(true) }
func cmdDemote(c *Ctx) error  { return c.setAdmin(false) }

func cmdRemoveMember(c *Ctx) error {
	base, m, err := c.member(c.Args[0])
	if err != nil {
		return err
	}
	if err := c.confirm(fmt.Sprintf("This removes %s from the organization.", m.Email), m.Email); err != nil {
		return err
	}
	if err := c.send("DELETE", base+"/"+esc(m.UserID), nil, nil); err != nil {
		return err
	}
	c.done("%s removed", m.Email)
	return nil
}

func cmdLeave(c *Ctx) error {
	if c.api().Token != "" {
		return errors.New("an API token cannot leave; delete it instead")
	}
	var my me
	if err := c.get("/api/v1/me", &my); err != nil {
		return err
	}
	org, err := c.org()
	if err != nil {
		return err
	}
	if err := c.confirm(fmt.Sprintf("You leave the organization %s.", org), org); err != nil {
		return err
	}
	if err := c.send("DELETE", "/api/v1/orgs/"+esc(org)+"/members/"+esc(my.ID), nil, nil); err != nil {
		return err
	}
	if c.current().Org == org {
		c.current().Org = ""
		_ = c.cfg.save()
	}
	c.done("You left %s", org)
	return nil
}

func cmdMyInvitations(c *Ctx) error {
	var raw json.RawMessage
	if err := c.get("/api/v1/me/invitations", &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var invs []myInvitation
	_ = json.Unmarshal(raw, &invs)
	if len(invs) == 0 {
		c.say("No invitations for you.")
		return nil
	}
	var rows [][]string
	for _, i := range invs {
		role := "member"
		if i.Admin {
			role = "admin"
		}
		rows = append(rows, []string{short(i.ID), i.OrgName + c.st.dim(" ("+i.OrgSlug+")"), role, i.InvitedBy, ago(i.ExpiresAt)})
	}
	table(c.Out, c.st, []string{"ID", "ORGANIZATION", "AS", "INVITED BY", "EXPIRES"}, rows)
	c.hint("\nAccept: veilctl invitations accept ID")
	return nil
}

// invitationToken takes the token out of an invitation link (.../invite/<token>), or the token.
func invitationToken(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "<>\"'")
	if i := strings.LastIndex(s, "/invite/"); i >= 0 {
		s = s[i+len("/invite/"):]
	}
	return strings.SplitN(strings.SplitN(s, "?", 2)[0], "#", 2)[0]
}

func cmdInvitationShow(c *Ctx) error {
	var raw json.RawMessage
	if err := c.get("/api/v1/invitations/"+esc(invitationToken(c.Args[0])), &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var p invitationPreview
	_ = json.Unmarshal(raw, &p)
	role := "member"
	if p.Admin {
		role = "admin"
	}
	fields(c.Out, c.st, [][2]string{{"organization", p.OrgName + " (" + p.OrgSlug + ")"}, {"for", p.Email}, {"as", role},
		{"invited by", p.InvitedBy}, {"expires", ago(p.ExpiresAt)}})
	if !p.ForMe {
		c.say("%s", c.est.yellow("This invitation is for "+p.Email+", not for the address you are signed in with."))
	}
	return nil
}

func cmdAccept(c *Ctx) error {
	ref := c.Args[0]
	var raw json.RawMessage
	if strings.Contains(ref, "/") || len(ref) > 36 {
		if err := c.send("POST", "/api/v1/invitations/"+esc(invitationToken(ref))+"/accept", nil, &raw); err != nil {
			return err
		}
	} else {
		var invs []myInvitation
		if err := c.get("/api/v1/me/invitations", &invs); err != nil {
			return err
		}
		var ids []string
		for _, i := range invs {
			ids = append(ids, i.ID)
		}
		id, err := byPrefix(ref, ids, "invitation")
		if err != nil {
			return err
		}
		if err := c.send("POST", "/api/v1/me/invitations/"+esc(id)+"/accept", nil, &raw); err != nil {
			return err
		}
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var o myOrg
	_ = json.Unmarshal(raw, &o)
	if o.Slug != "" {
		c.done("You are a member of %s (%s) now", c.est.bold(o.Name), o.Slug)
		if c.current().Org == "" {
			c.current().Org = o.Slug
			_ = c.cfg.save()
		} else if c.current().Org != o.Slug {
			c.hint("Work in it: veilctl orgs use %s", o.Slug)
		}
	} else {
		c.done("Invitation accepted")
	}
	return nil
}

func cmdDecline(c *Ctx) error {
	var invs []myInvitation
	if err := c.get("/api/v1/me/invitations", &invs); err != nil {
		return err
	}
	var ids []string
	for _, i := range invs {
		ids = append(ids, i.ID)
	}
	id, err := byPrefix(c.Args[0], ids, "invitation")
	if err != nil {
		return err
	}
	if err := c.send("DELETE", "/api/v1/me/invitations/"+esc(id), nil, nil); err != nil {
		return err
	}
	c.done("Invitation declined")
	return nil
}

// ---------------------------------------------------------------- clusters

func (c *Ctx) clusterStatus(cl *cluster) string {
	switch {
	case cl.DeletedAt != nil:
		return c.st.red("deleted") + c.st.dim(", gone "+agoPtr(cl.PurgeAt))
	case cl.RegionUnavailable:
		return c.st.red("region unavailable")
	}
	return c.st.green("active")
}

func (c *Ctx) featureList(f features) string {
	var on []string
	if f.Proxy {
		on = append(on, "proxy")
	}
	if f.Mesh {
		on = append(on, "mesh")
	}
	if len(on) == 0 {
		return c.st.dim("none")
	}
	return strings.Join(on, ", ")
}

func storage(cl *cluster) string {
	if cl.QuotaBytes <= 0 {
		return size(cl.SizeBytes)
	}
	return fmt.Sprintf("%s / %s", size(cl.SizeBytes), size(cl.QuotaBytes))
}

func cmdClusters(c *Ctx) error {
	base, err := c.orgPath("/clusters")
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(base, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var cls []cluster
	_ = json.Unmarshal(raw, &cls)
	if len(cls) == 0 {
		c.say("No clusters yet: veilctl clusters create NAME")
		return nil
	}
	var rows [][]string
	for i := range cls {
		cl := &cls[i]
		rows = append(rows, []string{c.st.bold(cl.ID), cl.Name, cl.Region, c.clusterStatus(cl), fmt.Sprint(cl.Devices),
			fmt.Sprint(cl.Revision), storage(cl), c.featureList(cl.Features), ago(cl.CreatedAt)})
	}
	table(c.Out, c.st, []string{"ID", "NAME", "REGION", "STATUS", "NODES", "REVISION", "STORAGE", "FEATURES", "CREATED"}, rows)
	return nil
}

func cmdClusterCreate(c *Ctx) error {
	base, err := c.orgPath("/clusters")
	if err != nil {
		return err
	}
	body := map[string]string{"name": c.Args[0]}
	if c.has("id") {
		body["id"] = c.flag("id")
	}
	if c.has("region") {
		body["region"] = c.flag("region")
	}
	var raw json.RawMessage
	if err := c.send("POST", base, body, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var cl cluster
	_ = json.Unmarshal(raw, &cl)
	c.done("Created cluster %s (%s) in %s", c.est.bold(cl.Name), cl.ID, cl.Region)
	fmt.Fprintln(c.Out, cl.ID)
	c.hint("Next: veilctl join-code %s   (a code for the first node)", cl.ID)
	return nil
}

func cmdClusterShow(c *Ctx) error {
	cl, err := c.cluster(c.Args[0])
	if err != nil {
		return err
	}
	base, _ := c.orgPath("/clusters/" + esc(cl.ID))
	var devs []device
	var devRaw json.RawMessage
	devErr := error(nil)
	if cl.DeletedAt == nil && !cl.RegionUnavailable {
		devErr = c.get(base+"/devices", &devRaw)
		_ = json.Unmarshal(devRaw, &devs)
	}
	if c.json() {
		var clRaw json.RawMessage
		if err := c.get(base, &clRaw); err != nil {
			return err
		}
		if devRaw == nil {
			devRaw = json.RawMessage("[]")
		}
		return c.printJSON(json.RawMessage(fmt.Sprintf(`{"cluster":%s,"devices":%s}`, clRaw, devRaw)))
	}
	rev := fmt.Sprint(cl.Revision)
	if cl.CompactRevision > 0 {
		rev += c.st.dim(fmt.Sprintf(" (compacted up to %d)", cl.CompactRevision))
	}
	fields(c.Out, c.st, [][2]string{{"id", c.st.bold(cl.ID)}, {"name", cl.Name}, {"region", cl.Region}, {"status", c.clusterStatus(cl)},
		{"features", "proxy " + c.st.state(onoff(cl.Features.Proxy)) + ", mesh " + c.st.state(onoff(cl.Features.Mesh))},
		{"revision", rev}, {"storage", storage(cl)}, {"created", ago(cl.CreatedAt)}})
	if cl.DeletedAt != nil {
		c.hint("\nDeleted; restore it until it is gone: veilctl clusters restore %s", cl.ID)
		return nil
	}
	fmt.Fprintln(c.Out)
	if devErr != nil {
		return devErr
	}
	if len(devs) == 0 {
		c.say("No nodes yet.")
		c.hint("Next: veilctl join-code %s", cl.ID)
		return nil
	}
	c.deviceTable(devs)
	return nil
}

func cmdClusterRename(c *Ctx) error {
	cl, err := c.cluster(c.Args[0])
	if err != nil {
		return err
	}
	base, _ := c.orgPath("/clusters/" + esc(cl.ID))
	var raw json.RawMessage
	if err := c.send("PATCH", base, map[string]string{"name": c.Args[1]}, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	c.done("Cluster %s is called %s now", cl.ID, c.est.bold(c.Args[1]))
	return nil
}

func cmdClusterDelete(c *Ctx) error {
	cl, err := c.cluster(c.Args[0])
	if err != nil {
		return err
	}
	if err := c.confirm(fmt.Sprintf("This deletes the cluster %s (%s): its nodes are refused at once.", cl.Name, cl.ID), cl.ID); err != nil {
		return err
	}
	base, _ := c.orgPath("/clusters/" + esc(cl.ID))
	var raw json.RawMessage
	if err := c.send("DELETE", base, nil, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var after cluster
	_ = json.Unmarshal(raw, &after)
	c.done("Cluster %s deleted", cl.ID)
	if after.PurgeAt != nil {
		c.hint("Its data is kept until %s: veilctl clusters restore %s", after.PurgeAt.Local().Format("2006-01-02 15:04"), cl.ID)
	}
	return nil
}

func cmdClusterRestore(c *Ctx) error {
	base, err := c.orgPath("/clusters/" + esc(c.Args[0]))
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.send("POST", base+"/restore", nil, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	c.done("Cluster %s restored", c.Args[0])
	return nil
}

func cmdFeatures(c *Ctx) error {
	cl, err := c.cluster(c.Args[0])
	if err != nil {
		return err
	}
	f := cl.Features
	changed := false
	for _, name := range []string{"proxy", "mesh"} {
		if !c.has(name) {
			continue
		}
		v, err := parseOnOff(c.flag(name))
		if err != nil {
			return &UsageError{c.cmd, "--" + name + " " + err.Error()}
		}
		if name == "proxy" {
			f.Proxy = v
		} else {
			f.Mesh = v
		}
		changed = true
	}
	if changed {
		base, _ := c.orgPath("/clusters/" + esc(cl.ID))
		var raw json.RawMessage
		if err := c.send("PUT", base+"/features", f, &raw); err != nil {
			return err
		}
		if c.json() {
			return c.printJSON(raw)
		}
		_ = json.Unmarshal(raw, cl)
		c.done("Saved; the agents switch within seconds (each node's agent.json has the last word)")
	} else if c.json() {
		return c.printJSON(cl.Features)
	}
	fields(c.Out, c.st, [][2]string{{"proxy", c.st.state(onoff(cl.Features.Proxy))}, {"mesh", c.st.state(onoff(cl.Features.Mesh))}})
	return nil
}

func cmdJoinCode(c *Ctx) error {
	cl, err := c.cluster(c.Args[0])
	if err != nil {
		return err
	}
	base, _ := c.orgPath("/clusters/" + esc(cl.ID))
	body := map[string]string{}
	if c.has("node") {
		body["node"] = c.flag("node")
	}
	var raw json.RawMessage
	if err := c.send("POST", base+"/join-codes", body, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var jc joinCode
	_ = json.Unmarshal(raw, &jc)
	c.say("Join code for %s, valid until %s (%s):", c.est.bold(cl.Name), jc.ExpiresAt.Local().Format("Jan 2 15:04"), ago(jc.ExpiresAt))
	if c.st.on { // the code on the terminal between the lines; piped, only the code goes to stdout
		c.say("")
		fmt.Fprintln(c.Out, "  "+c.st.bold(jc.Code))
		c.say("")
	} else {
		fmt.Fprintln(c.Out, jc.Code)
	}
	c.say("On the first node:")
	c.say("  %s", c.est.cyan(InstallCommand+jc.Code))
	return nil
}

// deviceState is what a node is doing, from its agent's last report.
func (c *Ctx) deviceState(d *device) string {
	switch {
	case d.RevokedAt != nil:
		return "revoked"
	case d.Agent == nil:
		return "waiting"
	case time.Since(d.Agent.ReportedAt) > 10*time.Minute:
		return "offline"
	case d.Agent.Status.State == "running" && !d.Agent.Status.Backend.Connected:
		return "disconnected"
	case d.Agent.Status.State != "":
		return d.Agent.Status.State
	}
	return "unknown"
}

func (c *Ctx) featureState(d *device, name string) string {
	if d.Agent == nil || d.RevokedAt != nil {
		return "-"
	}
	f := d.Agent.Status.Features[name]
	if f == nil {
		return "-"
	}
	s := c.st.state(f.State)
	if name == "proxy" && f.State == "running" && f.Revision > 0 {
		s += c.st.dim(fmt.Sprintf(" @%d", f.Revision))
	}
	return s
}

func (c *Ctx) deviceTable(devs []device) {
	var rows [][]string
	for i := range devs {
		d := &devs[i]
		version := "-"
		if d.Agent != nil && d.Agent.Status.Version != "" {
			version = d.Agent.Status.Version
		}
		role := d.Role
		if role == "" {
			role = "-"
		}
		rows = append(rows, []string{c.st.bold(d.Node), role, c.st.state(c.deviceState(d)), c.featureState(d, "proxy"), c.featureState(d, "mesh"),
			version, agoPtr(d.LastSeen)})
	}
	table(c.Out, c.st, []string{"NODE", "ROLE", "STATE", "PROXY", "MESH", "VERSION", "LAST SEEN"}, rows)
	for i := range devs {
		d := &devs[i]
		if d.Agent != nil && d.RevokedAt == nil {
			if e := d.Agent.Status.Error; e != "" {
				fmt.Fprintf(c.Out, "%s %s\n", c.st.red(d.Node+":"), e)
			}
			names := make([]string, 0, len(d.Agent.Status.Features))
			for name := range d.Agent.Status.Features {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				switch f := d.Agent.Status.Features[name]; {
				case f.State == "refused":
					fmt.Fprintln(c.Out, c.st.dim(fmt.Sprintf("%s: %s wanted, but its agent.json does not allow it", d.Node, name)))
				case f.Error != "":
					fmt.Fprintf(c.Out, "%s %s\n", c.st.red(d.Node+" "+name+":"), f.Error)
				}
			}
		}
	}
}

func cmdDevices(c *Ctx) error {
	cl, err := c.cluster(c.Args[0])
	if err != nil {
		return err
	}
	base, _ := c.orgPath("/clusters/" + esc(cl.ID) + "/devices")
	show := func() error {
		var raw json.RawMessage
		if err := c.get(base, &raw); err != nil {
			return err
		}
		var devs []device
		_ = json.Unmarshal(raw, &devs)
		if len(c.Args) == 2 {
			i := slices.IndexFunc(devs, func(d device) bool { return d.Node == c.Args[1] })
			if i < 0 {
				return fmt.Errorf("no node %q in %s", c.Args[1], cl.ID)
			}
			if c.json() {
				var all []json.RawMessage
				_ = json.Unmarshal(raw, &all)
				return c.printJSON(all[i])
			}
			c.deviceDetail(&devs[i])
			return nil
		}
		if c.json() {
			return c.printJSON(raw)
		}
		if len(devs) == 0 {
			c.say("No nodes in %s yet.", cl.ID)
			c.hint("Next: veilctl join-code %s", cl.ID)
			return nil
		}
		c.deviceTable(devs)
		return nil
	}
	return c.watch(show)
}

// watch runs show once, or with --watch every two seconds until Ctrl-C.
func (c *Ctx) watch(show func() error) error {
	if !c.on("watch") {
		return show()
	}
	for {
		if c.st.on {
			fmt.Fprint(c.Out, "\x1b[H\x1b[2J")
		}
		fmt.Fprintln(c.Out, c.st.dim(time.Now().Format("15:04:05")+"  (Ctrl-C ends)"))
		if err := show(); err != nil {
			fmt.Fprintln(c.Out, c.st.red("error: ")+err.Error())
		}
		select {
		case <-c.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *Ctx) deviceDetail(d *device) {
	kv := [][2]string{{"node", c.st.bold(d.Node)}, {"role", d.Role}, {"state", c.st.state(c.deviceState(d))},
		{"joined", ago(d.FirstSeen)}, {"last seen", agoPtr(d.LastSeen)}}
	if d.RevokedAt != nil {
		kv = append(kv, [2]string{"revoked", agoPtr(d.RevokedAt)})
	}
	if a := d.Agent; a != nil {
		kv = append(kv, [2]string{"agent", a.Status.Version}, [2]string{"reported", ago(a.ReportedAt)},
			[2]string{"backend", c.st.state(map[bool]string{true: "connected", false: "disconnected"}[a.Status.Backend.Connected])})
		if a.Status.Error != "" {
			kv = append(kv, [2]string{"error", c.st.red(a.Status.Error)})
		}
		names := make([]string, 0, len(a.Status.Features))
		for n := range a.Status.Features {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			f := a.Status.Features[n]
			v := c.st.state(f.State)
			switch {
			case f.State == "refused":
				v += c.st.dim(" (wanted, but agent.json does not allow it)")
			case f.State == "off" && f.Wanted:
				v += c.st.dim(" (wanted)")
			}
			if f.Listen != "" {
				v += c.st.dim(" on " + f.Listen)
			}
			if f.Revision > 0 {
				v += c.st.dim(fmt.Sprintf(", revision %d", f.Revision))
			}
			if f.Error != "" && f.State != "refused" {
				v += " " + c.st.red(f.Error)
			}
			kv = append(kv, [2]string{n, v})
		}
	}
	fields(c.Out, c.st, kv)
}

func cmdRevoke(c *Ctx) error {
	cl, err := c.cluster(c.Args[0])
	if err != nil {
		return err
	}
	node := c.Args[1]
	if err := c.confirm(fmt.Sprintf("This revokes %s in %s: it stops at once and can never use its identity again.", node, cl.ID), node); err != nil {
		return err
	}
	base, _ := c.orgPath("/clusters/" + esc(cl.ID) + "/devices/" + esc(node) + "/revoke")
	if err := c.send("POST", base, nil, nil); err != nil {
		return err
	}
	c.done("%s revoked", node)
	return nil
}

func cmdMesh(c *Ctx) error {
	cl, err := c.cluster(c.Args[0])
	if err != nil {
		return err
	}
	base, _ := c.orgPath("/clusters/" + esc(cl.ID) + "/mesh")
	var raw json.RawMessage
	if err := c.get(base, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var v meshView
	_ = json.Unmarshal(raw, &v)
	if !cl.Features.Mesh {
		c.hint("The mesh is off for %s (veilctl clusters features %s --mesh on)", cl.ID, cl.ID)
	}
	if len(v.Members) == 0 {
		c.say("No nodes in the mesh yet.")
		return nil
	}
	if v.Prefix != "" {
		fmt.Fprintf(c.Out, "%s %s\n\n", c.st.dim("addresses"), v.Prefix)
	}
	var rows [][]string
	for _, m := range v.Members {
		state := "offline"
		if m.Online {
			state = "online"
		}
		if !m.Registered {
			state = "waiting"
		}
		eps := strings.Join(m.Endpoints, ", ")
		if eps == "" {
			eps = "-"
		}
		rows = append(rows, []string{c.st.bold(m.Node), m.Role, m.Address, c.st.state(state), eps})
	}
	table(c.Out, c.st, []string{"NODE", "ROLE", "ADDRESS", "STATE", "ENDPOINTS"}, rows)
	var paths [][]string
	for _, m := range v.Members {
		for _, p := range m.Peers {
			path := p.Path
			if path == "" {
				path = "-"
			}
			paths = append(paths, []string{m.Node, p.Node, c.st.state(p.State), path, agoPtr(p.LastHandshake)})
		}
	}
	if len(paths) > 0 {
		fmt.Fprintln(c.Out)
		table(c.Out, c.st, []string{"FROM", "TO", "STATE", "PATH", "HANDSHAKE"}, paths)
	}
	return nil
}

// ---------------------------------------------------------------- tokens, audit, regions

func cmdTokens(c *Ctx) error {
	base, err := c.orgPath("/tokens")
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.get(base, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var ts []apiToken
	_ = json.Unmarshal(raw, &ts)
	if len(ts) == 0 {
		c.say("No API tokens: veilctl tokens create NAME")
		return nil
	}
	var rows [][]string
	for _, t := range ts {
		exp := "never"
		if t.ExpiresAt != nil {
			exp = ago(*t.ExpiresAt)
			if t.ExpiresAt.Before(time.Now()) {
				exp = c.st.red("expired " + exp)
			}
		}
		rows = append(rows, []string{short(t.ID), c.st.bold(t.Name), t.CreatedBy, ago(t.CreatedAt), agoPtr(t.LastUsedAt), exp})
	}
	table(c.Out, c.st, []string{"ID", "NAME", "CREATED BY", "CREATED", "LAST USED", "EXPIRES"}, rows)
	return nil
}

func cmdTokenCreate(c *Ctx) error {
	base, err := c.orgPath("/tokens")
	if err != nil {
		return err
	}
	body := map[string]any{"name": c.Args[0]}
	if c.has("expires") {
		days, err := parseDays(c.flag("expires"))
		if err != nil {
			return &UsageError{c.cmd, "--expires " + err.Error()}
		}
		body["expiresInDays"] = days
	}
	var raw json.RawMessage
	if err := c.send("POST", base, body, &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var t apiToken
	_ = json.Unmarshal(raw, &t)
	c.done("Created the API token %s; it is shown only now:", c.est.bold(t.Name))
	fmt.Fprintln(c.Out, t.Token)
	c.hint("Use it: VEILCTL_TOKEN=%s... veilctl clusters --org %s", t.Token[:min(8, len(t.Token))], strings.TrimPrefix(strings.TrimSuffix(base, "/tokens"), "/api/v1/orgs/"))
	return nil
}

func cmdTokenDelete(c *Ctx) error {
	base, err := c.orgPath("/tokens")
	if err != nil {
		return err
	}
	var ts []apiToken
	if err := c.get(base, &ts); err != nil {
		return err
	}
	var ids []string
	name := map[string]string{}
	for _, t := range ts {
		if t.Name == c.Args[0] {
			ids = []string{t.ID}
			c.Args[0] = t.ID
			name[t.ID] = t.Name
			break
		}
		ids = append(ids, t.ID)
		name[t.ID] = t.Name
	}
	id, err := byPrefix(c.Args[0], ids, "token")
	if err != nil {
		return err
	}
	if err := c.confirm(fmt.Sprintf("This deletes the API token %q: whatever uses it stops working.", name[id]), name[id]); err != nil {
		return err
	}
	if err := c.send("DELETE", base+"/"+esc(id), nil, nil); err != nil {
		return err
	}
	c.done("API token %q deleted", name[id])
	return nil
}

func cmdAudit(c *Ctx) error {
	base, err := c.orgPath("/audit")
	if err != nil {
		return err
	}
	limit := 50
	if c.has("limit") {
		if _, err := fmt.Sscan(c.flag("limit"), &limit); err != nil || limit < 1 {
			return &UsageError{c.cmd, "--limit needs a number"}
		}
	}
	before := c.flag("before")
	var all []json.RawMessage
	for {
		q := url.Values{"limit": {fmt.Sprint(min(limit, 500))}}
		if before != "" {
			q.Set("before", before)
		}
		var page []json.RawMessage
		if err := c.get(base+"?"+q.Encode(), &page); err != nil {
			return err
		}
		all = append(all, page...)
		if !c.on("all") || len(page) == 0 {
			break
		}
		var last auditEntry
		_ = json.Unmarshal(page[len(page)-1], &last)
		before = fmt.Sprint(last.ID)
	}
	if c.json() {
		return c.printJSON(all)
	}
	if len(all) == 0 {
		c.say("Nothing in the audit log.")
		return nil
	}
	var rows [][]string
	var lastID int64
	for _, r := range all {
		var e auditEntry
		_ = json.Unmarshal(r, &e)
		lastID = e.ID
		actor := e.Actor
		if e.ActorKind != "user" {
			actor = e.ActorKind + " " + e.Actor
		}
		details := e.Details
		if len(details) > 60 {
			details = details[:60] + "…"
		}
		rows = append(rows, []string{c.st.dim(e.At.Local().Format("2006-01-02 15:04:05")), actor, c.st.bold(e.Action), e.Target, details})
	}
	table(c.Out, c.st, []string{"TIME", "WHO", "ACTION", "TARGET", "DETAILS"}, rows)
	if !c.on("all") && len(all) == limit {
		c.hint("\nOlder: veilctl audit --before %d (or --all)", lastID)
	}
	return nil
}

func cmdRegions(c *Ctx) error {
	var raw json.RawMessage
	if err := c.get("/api/v1/regions", &raw); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	var rs []region
	_ = json.Unmarshal(raw, &rs)
	var rows [][]string
	for _, r := range rs {
		home := ""
		if r.Home {
			home = c.st.dim("home: accounts, default for new clusters")
		}
		rows = append(rows, []string{c.st.bold(r.Name), home})
	}
	table(c.Out, c.st, []string{"REGION", ""}, rows)
	return nil
}

func cmdCompletion(c *Ctx) error {
	s, err := completionScript(c.Args[0])
	if err != nil {
		return &UsageError{c.cmd, err.Error()}
	}
	fmt.Fprint(c.Out, s)
	return nil
}

// ---------------------------------------------------------------- trial clusters

func (c *Ctx) trialClient(t *TrialRef) *Client {
	return &Client{Base: c.apiURL(), UA: userAgent(c.version), Trial: t.Token}
}

func cmdTrialStart(c *Ctx) error {
	cx := c.current()
	if t := cx.Trial; t != nil && time.Now().Before(t.Expires) {
		c.say("Your trial cluster %s runs until %s (%s).", c.est.bold(t.Cluster), t.Expires.Local().Format("15:04"), ago(t.Expires))
		return cmdTrialStatus(c)
	}
	cl := &Client{Base: c.apiURL(), UA: userAgent(c.version)}
	var raw json.RawMessage
	if _, err := cl.Do(c, "POST", "/api/v1/trial", nil, &raw); err != nil {
		return err
	}
	var t trial
	_ = json.Unmarshal(raw, &t)
	cx.Trial = &TrialRef{Cluster: t.Cluster, Token: t.Token, Expires: t.ExpiresAt, Code: t.JoinCode}
	if err := c.cfg.save(); err != nil {
		return err
	}
	if c.json() {
		return c.printJSON(raw)
	}
	c.done("Trial cluster %s, until %s (%s, then everything is deleted)", c.est.bold(t.Cluster), t.ExpiresAt.Local().Format("15:04"), ago(t.ExpiresAt))
	c.say("")
	c.say("On the first node (Linux with systemd, as root):")
	command := t.Command
	if command == "" {
		command = InstallCommand + t.JoinCode
	}
	c.say("  %s", c.est.cyan(command))
	c.say("")
	if t.DashboardURL != "" {
		c.say("Watch it live: %s", t.DashboardURL)
	}
	c.hint("Here: veilctl trial status --watch    End it now: veilctl trial end")
	fmt.Fprintln(c.Out, t.JoinCode)
	return nil
}

func (c *Ctx) trialRef() (*TrialRef, error) {
	t := c.current().Trial
	if t == nil {
		return nil, errors.New("no trial cluster started here: veilctl trial")
	}
	return t, nil
}

func cmdTrialStatus(c *Ctx) error {
	t, err := c.trialRef()
	if err != nil {
		return err
	}
	cl := c.trialClient(t)
	return c.watch(func() error {
		var raw json.RawMessage
		if _, err := cl.Do(c, "GET", "/api/v1/trial/"+esc(t.Cluster), nil, &raw); err != nil {
			if IsStatus(err, http.StatusNotFound) || IsStatus(err, http.StatusForbidden) {
				return fmt.Errorf("the trial cluster %s has ended", t.Cluster)
			}
			return err
		}
		if c.json() {
			return c.printJSON(raw)
		}
		var tr trial
		_ = json.Unmarshal(raw, &tr)
		used := size(tr.SizeBytes)
		if tr.QuotaBytes > 0 {
			used += " / " + size(tr.QuotaBytes)
		}
		fields(c.Out, c.st, [][2]string{{"cluster", c.st.bold(tr.Cluster)}, {"ends", tr.ExpiresAt.Local().Format("15:04") + " (" + ago(tr.ExpiresAt) + ")"},
			{"revision", fmt.Sprint(tr.Revision)}, {"storage", used}, {"nodes", fmt.Sprintf("%d of at most %d", len(tr.Devices), tr.MaxNodes)}})
		fmt.Fprintln(c.Out)
		if len(tr.Devices) == 0 {
			c.say("No node yet. On the first node:")
			c.say("  %s", c.est.cyan(InstallCommand+t.Code))
			return nil
		}
		c.deviceTable(tr.Devices)
		return nil
	})
}

func cmdTrialEnd(c *Ctx) error {
	t, err := c.trialRef()
	if err != nil {
		return err
	}
	if err := c.confirm(fmt.Sprintf("This ends the trial cluster %s now and deletes its data.", t.Cluster), t.Cluster); err != nil {
		return err
	}
	if _, err := c.trialClient(t).Do(c, "DELETE", "/api/v1/trial/"+esc(t.Cluster), nil, nil); err != nil && !IsStatus(err, http.StatusNotFound) {
		return err
	}
	c.current().Trial = nil
	if err := c.cfg.save(); err != nil {
		return err
	}
	c.done("Trial cluster %s ended", t.Cluster)
	return nil
}

// ---------------------------------------------------------------- completion of values

func completeOnOff(*Ctx) []string { return []string{"on", "off"} }

func completeOrgs(c *Ctx) []string {
	var orgs []myOrg
	if !c.signedIn() || c.get("/api/v1/me/orgs", &orgs) != nil {
		return nil
	}
	var out []string
	for _, o := range orgs {
		out = append(out, o.Slug)
	}
	return out
}

func completeOrgArg(c *Ctx, i int) []string {
	if i == 0 {
		return completeOrgs(c)
	}
	return nil
}

func completeContexts(c *Ctx) []string {
	var out []string
	for n := range c.cfg.Contexts {
		out = append(out, n)
	}
	return out
}

func completeContextArg(c *Ctx, i int) []string {
	if i == 0 {
		return completeContexts(c)
	}
	return nil
}

func completeRegions(c *Ctx) []string {
	var rs []region
	if c.get("/api/v1/regions", &rs) != nil {
		return nil
	}
	var out []string
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

func completeClusters(c *Ctx, i int) []string {
	if i != 0 || !c.signedIn() {
		return nil
	}
	base, err := c.orgPath("/clusters")
	if err != nil {
		return nil
	}
	var cls []cluster
	if c.get(base, &cls) != nil {
		return nil
	}
	var out []string
	for _, cl := range cls {
		out = append(out, cl.ID)
	}
	return out
}

func completeClusterNode(c *Ctx, i int) []string {
	if i == 0 {
		return completeClusters(c, 0)
	}
	if i != 1 || len(c.Args) == 0 {
		return nil
	}
	base, err := c.orgPath("/clusters/" + esc(c.Args[0]) + "/devices")
	if err != nil {
		return nil
	}
	var devs []device
	if c.get(base, &devs) != nil {
		return nil
	}
	var out []string
	for _, d := range devs {
		out = append(out, d.Node)
	}
	return out
}

func completeMembers(c *Ctx, i int) []string {
	if i != 0 || !c.signedIn() {
		return nil
	}
	_, ms, err := c.members()
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range ms {
		out = append(out, m.Email)
	}
	return out
}

func completeTokens(c *Ctx, i int) []string {
	if i != 0 || !c.signedIn() {
		return nil
	}
	base, err := c.orgPath("/tokens")
	if err != nil {
		return nil
	}
	var ts []apiToken
	if c.get(base, &ts) != nil {
		return nil
	}
	var out []string
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}
