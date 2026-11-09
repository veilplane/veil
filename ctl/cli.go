// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// Package ctl is veilctl: the command line for Veilplane's management API (organizations,
// members, clusters, join codes, devices, API tokens, the audit log, trial clusters). This file
// is the small command framework: a tree of commands, flags anywhere on the line, help, "did you
// mean", and shell completion that asks the binary itself (so cluster names complete too).
package ctl

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
)

// Command is one node of the command tree.
type Command struct {
	Name    string
	Aliases []string
	Short   string   // one line, for lists
	Args    string   // synopsis of the positional arguments, e.g. "CLUSTER [NODE]"
	Long    string   // more text for its help
	Example []string // shown in its help
	Group   string   // heading in the parent's list of commands
	Flags   []*Flag
	MinArgs int
	MaxArgs int // -1: any number
	// Run does the work; nil means: show the help (a group of commands), or run Default.
	Run func(c *Ctx) error
	// Default is the subcommand that runs when only the group is named ("veilctl clusters").
	Default string
	// Complete offers values for positional argument i (0-based).
	Complete func(c *Ctx, i int) []string
	Hidden   bool
	Sub      []*Command

	parent *Command
}

// Flag is a --name (and maybe -x) option. Bool flags take no value ("--yes", "--yes=false").
type Flag struct {
	Name     string
	Short    string
	Value    string // placeholder in the help, e.g. "NAME"; empty for bool flags
	Usage    string
	Complete func(c *Ctx) []string
}

func (f *Flag) bool() bool { return f.Value == "" }

func (c *Command) path() string {
	if c.parent == nil {
		return c.Name
	}
	return c.parent.path() + " " + c.Name
}

func (c *Command) find(name string) *Command {
	for _, s := range c.Sub {
		if s.Name == name || slices.Contains(s.Aliases, name) {
			return s
		}
	}
	return nil
}

// link sets the parents of the whole tree.
func (c *Command) link() {
	for _, s := range c.Sub {
		s.parent = c
		s.link()
	}
}

// flags are the flags valid for this command: its own, its ancestors' and the global ones.
func (c *Command) flags(global []*Flag) []*Flag {
	var fs []*Flag
	for x := c; x != nil; x = x.parent {
		fs = append(fs, x.Flags...)
	}
	return append(fs, global...)
}

func lookupFlag(fs []*Flag, name string, short bool) *Flag {
	for _, f := range fs {
		if (!short && f.Name == name) || (short && f.Short != "" && f.Short == name) {
			return f
		}
	}
	return nil
}

// UsageError is a mistake on the command line: the message and the command whose help helps.
type UsageError struct {
	Cmd *Command
	Msg string
}

func (e *UsageError) Error() string { return e.Msg }

// parse finds the command named by argv and splits the rest into flags and arguments. Flags may
// come anywhere, also before the command ("veilctl --org acme clusters").
func parse(root *Command, global []*Flag, argv []string) (*Command, []string, map[string]string, error) {
	// 1. the command: the leading words that name subcommands (flags in between are skipped)
	cmd := root
	words := map[int]bool{}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			name, _, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
			f := lookupFlag(cmd.flags(global), name, !strings.HasPrefix(a, "--"))
			if !hasValue && f != nil && !f.bool() {
				i++ // its value
			}
			continue
		}
		s := cmd.find(a)
		if s == nil {
			break
		}
		cmd = s
		words[i] = true
	}
	// 2. flags and arguments, now that the command is known
	known := cmd.flags(global)
	flags := map[string]string{}
	var args []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case words[i]:
		case a == "--":
			args = append(args, argv[i+1:]...)
			i = len(argv)
		case strings.HasPrefix(a, "-") && a != "-":
			long := strings.HasPrefix(a, "--")
			name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
			f := lookupFlag(known, name, !long)
			if f == nil {
				msg := fmt.Sprintf("unknown flag %s", a)
				var names []string
				for _, k := range known {
					names = append(names, k.Name)
				}
				if s := suggest(name, names); s != "" {
					msg += fmt.Sprintf(" (did you mean --%s?)", s)
				}
				return cmd, nil, nil, &UsageError{cmd, msg}
			}
			switch {
			case f.bool() && hasValue:
				if value != "true" && value != "false" {
					return cmd, nil, nil, &UsageError{cmd, fmt.Sprintf("--%s takes no value (or =true, =false)", f.Name)}
				}
				flags[f.Name] = value
			case f.bool():
				flags[f.Name] = "true"
			case hasValue:
				flags[f.Name] = value
			case i+1 < len(argv):
				i++
				flags[f.Name] = argv[i]
			default:
				return cmd, nil, nil, &UsageError{cmd, fmt.Sprintf("--%s needs a value (%s)", f.Name, f.Value)}
			}
		default:
			args = append(args, a)
		}
	}
	return cmd, args, flags, nil
}

// suggest returns the closest of names to s, if it is close enough to be a typo.
func suggest(s string, names []string) string {
	best, bestD := "", 3
	ls := strings.ToLower(s)
	for _, n := range names {
		ln := strings.ToLower(n)
		d := distance(ls, ln)
		if strings.HasPrefix(ln, ls) && len(ls) >= 3 {
			d = min(d, 1) // the beginning of it
		}
		if d < bestD {
			best, bestD = n, d
		}
	}
	return best
}

// distance is the Levenshtein distance.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

// ---------------------------------------------------------------- help

func (c *Command) help(w io.Writer, global []*Flag, st style) {
	title := c.path()
	if c.Short != "" {
		title += " - " + c.Short
	}
	fmt.Fprintln(w, st.bold(title))
	if c.Long != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, strings.TrimSpace(c.Long))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.bold("Usage"))
	switch {
	case c.Run != nil || c.Default != "":
		line := "  " + c.path()
		if c.Args != "" {
			line += " " + c.Args
		}
		if len(c.Flags) > 0 {
			line += " [flags]"
		}
		fmt.Fprintln(w, line)
		if len(c.Sub) > 0 {
			fmt.Fprintf(w, "  %s COMMAND\n", c.path())
		}
	default:
		fmt.Fprintf(w, "  %s COMMAND\n", c.path())
	}
	if len(c.Sub) > 0 {
		groups := map[string][]*Command{}
		var order []string
		for _, s := range c.Sub {
			if s.Hidden {
				continue
			}
			if _, ok := groups[s.Group]; !ok {
				order = append(order, s.Group)
			}
			groups[s.Group] = append(groups[s.Group], s)
		}
		width := 0
		for _, s := range c.Sub {
			width = max(width, len(s.Name))
		}
		for _, g := range order {
			fmt.Fprintln(w)
			label := g
			if label == "" {
				label = "Commands"
			}
			fmt.Fprintln(w, st.bold(label))
			for _, s := range groups[g] {
				name := s.Name
				if s.Name == c.Default {
					name += "*"
				}
				fmt.Fprintf(w, "  %-*s  %s\n", width+1, name, s.Short)
			}
		}
		if c.Default != "" {
			fmt.Fprintf(w, "\n  * runs when no command is given: %s = %s %s\n", c.path(), c.path(), c.Default)
		}
	}
	if len(c.Flags) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.bold("Flags"))
		printFlags(w, c.Flags)
	}
	if len(c.Example) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.bold("Examples"))
		for _, e := range c.Example {
			fmt.Fprintln(w, "  "+e)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.bold("Global flags"))
	printFlags(w, global)
	if len(c.Sub) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.dim(fmt.Sprintf("More about a command: %s COMMAND --help", c.path())))
	}
}

func printFlags(w io.Writer, fs []*Flag) {
	labels := make([]string, len(fs))
	width := 0
	for i, f := range fs {
		l := "    "
		if f.Short != "" {
			l = "-" + f.Short + ", "
		}
		l += "--" + f.Name
		if f.Value != "" {
			l += " " + f.Value
		}
		labels[i] = l
		width = max(width, len(l))
	}
	for i, f := range fs {
		fmt.Fprintf(w, "  %-*s  %s\n", width, labels[i], f.Usage)
	}
}

// ---------------------------------------------------------------- completion

// complete returns the candidates for the last of words (the word being typed, maybe empty).
func complete(root *Command, global []*Flag, c *Ctx, words []string) []string {
	if len(words) == 0 {
		words = []string{""}
	}
	typed := words[len(words)-1]
	before := words[:len(words)-1]
	cmd, args, _, err := parse(root, global, before)
	if err != nil {
		var ue *UsageError
		if !errors.As(err, &ue) {
			return nil
		}
		cmd = ue.Cmd
	}
	c.cmd, c.Args = cmd, args
	// the value of a flag?
	if n := len(before); n > 0 && strings.HasPrefix(before[n-1], "-") && !strings.Contains(before[n-1], "=") {
		a := before[n-1]
		if f := lookupFlag(cmd.flags(global), strings.TrimLeft(a, "-"), !strings.HasPrefix(a, "--")); f != nil && !f.bool() {
			if f.Complete != nil {
				return filter(f.Complete(c), typed)
			}
			return nil
		}
	}
	if strings.HasPrefix(typed, "-") {
		var out []string
		for _, f := range cmd.flags(global) {
			out = append(out, "--"+f.Name)
		}
		return filter(out, typed)
	}
	var out []string
	if len(args) == 0 {
		for _, s := range cmd.Sub {
			if !s.Hidden {
				out = append(out, s.Name)
			}
		}
	}
	target := cmd
	if len(cmd.Sub) > 0 && cmd.Default != "" && len(args) == 0 {
		target = cmd.find(cmd.Default)
	}
	if target != nil && target.Complete != nil && (target.MaxArgs < 0 || len(args) < target.MaxArgs) {
		out = append(out, target.Complete(c, len(args))...)
	}
	return filter(out, typed)
}

func filter(cands []string, prefix string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range cands {
		if strings.HasPrefix(s, prefix) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// completionScript is the script for a shell; it calls "veilctl __complete WORDS..." for the
// candidates, one per line.
func completionScript(shell string) (string, error) {
	switch shell {
	case "bash":
		return `# veilctl completion for bash: source <(veilctl completion bash)
_veilctl() {
  local cur=${COMP_WORDS[COMP_CWORD]}
  local IFS=$'\n'
  COMPREPLY=($(veilctl __complete "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null))
}
complete -o default -F _veilctl veilctl
`, nil
	case "zsh":
		return `#compdef veilctl
# veilctl completion for zsh: source <(veilctl completion zsh), or save it as _veilctl in $fpath
_veilctl() {
  local -a cands
  cands=("${(@f)$(veilctl __complete "${(@)words[2,CURRENT]}" 2>/dev/null)}")
  compadd -a cands
}
if [ "$funcstack[1]" = "_veilctl" ]; then _veilctl "$@"; else compdef _veilctl veilctl; fi
`, nil
	case "fish":
		return `# veilctl completion for fish: veilctl completion fish | source
complete -c veilctl -f -a '(veilctl __complete (commandline -opc)[2..-1] (commandline -ct) 2>/dev/null)'
`, nil
	}
	return "", fmt.Errorf("no completion for %q (bash, zsh or fish)", shell)
}
