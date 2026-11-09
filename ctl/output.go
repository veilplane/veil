// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------- colors

// style colors text when writing to a terminal (not with NO_COLOR or --no-color).
type style struct{ on bool }

func (s style) wrap(code, t string) string {
	if !s.on || t == "" {
		return t
	}
	return "\x1b[" + code + "m" + t + "\x1b[0m"
}
func (s style) bold(t string) string   { return s.wrap("1", t) }
func (s style) dim(t string) string    { return s.wrap("2", t) }
func (s style) green(t string) string  { return s.wrap("32", t) }
func (s style) yellow(t string) string { return s.wrap("33", t) }
func (s style) red(t string) string    { return s.wrap("31", t) }
func (s style) cyan(t string) string   { return s.wrap("36", t) }

// state colors a state word by what it means.
func (s style) state(t string) string {
	switch t {
	case "running", "connected", "online", "active", "yes", "on", "up":
		return s.green(t)
	case "starting", "joining", "trying", "waiting", "pending":
		return s.yellow(t)
	case "error", "failed", "refused", "unreachable", "revoked", "offline", "disconnected", "suspended", "deleted", "unavailable":
		return s.red(t)
	case "off", "no", "-", "":
		return s.dim(t)
	}
	return t
}

func (s style) ok(msg string) string {
	if s.on {
		return s.green("✓") + " " + msg
	}
	return msg
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

func visible(t string) int { return utf8.RuneCountInString(ansi.ReplaceAllString(t, "")) }

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// ---------------------------------------------------------------- tables

// table writes rows under a header, columns aligned by their visible width (colors do not count).
func table(w io.Writer, st style, header []string, rows [][]string) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, cell := range r {
			widths[i] = max(widths[i], visible(cell))
		}
	}
	line := func(cells []string, head bool) {
		var b strings.Builder
		for i, cell := range cells {
			if head {
				cell = st.dim(cell)
			}
			b.WriteString(cell)
			if i < len(cells)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-visible(cell)+3))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
	line(header, true)
	for _, r := range rows {
		line(r, false)
	}
}

// fields writes "label  value" lines, labels aligned.
func fields(w io.Writer, st style, kv [][2]string) {
	width := 0
	for _, p := range kv {
		width = max(width, len(p[0]))
	}
	for _, p := range kv {
		if p[1] == "" {
			continue
		}
		fmt.Fprintf(w, "%s  %s\n", st.dim(fmt.Sprintf("%-*s", width, p[0])), p[1])
	}
}

// ---------------------------------------------------------------- values

// ago is a time relative to now, for people: "3m ago", "in 2h", "just now".
func ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Until(t)
	future := d > 0
	if !future {
		d = -d
	}
	var s string
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		s = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		s = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%dh", int(d.Hours()))
	case d < 60*24*time.Hour:
		s = fmt.Sprintf("%dd", int(d.Hours()/24))
	default:
		return t.Local().Format("2006-01-02")
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

func agoPtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return ago(*t)
}

// size is a size for people: the round form of it if there is one, so a limit reads as it was
// set (4 GiB, 64 MB); other values in decimal units with one decimal (1.5 MB).
func size(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d B", n)
	}
	best := ""
	bestV := int64(-1)
	for i, div := 0, int64(1000); i < 6 && n >= div; i, div = i+1, div*1000 { // round in decimal
		if n%div == 0 {
			best, bestV = fmt.Sprintf("%d %cB", n/div, "kMGTPE"[i]), n/div
		}
	}
	for i, div := 0, int64(1024); i < 6 && n >= div; i, div = i+1, div*1024 { // round in binary
		if n%div == 0 && (bestV < 0 || n/div < bestV) {
			best, bestV = fmt.Sprintf("%d %ciB", n/div, "KMGTPE"[i]), n/div
		}
	}
	if best != "" && bestV < 1000 {
		return best
	}
	div, exp := int64(1000), 0
	for m := n / 1000; m >= 1000; m /= 1000 {
		div *= 1000
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func onoff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// parseOnOff reads on/off, true/false, yes/no, 1/0.
func parseOnOff(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "on", "true", "yes", "1":
		return true, nil
	case "off", "false", "no", "0":
		return false, nil
	}
	return false, fmt.Errorf("%q: on or off", s)
}

// parseDays reads "90", "90d", "12w", "6m" (months of 30 days), "1y".
func parseDays(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	mult := 1
	switch s[len(s)-1] {
	case 'd':
		s = s[:len(s)-1]
	case 'w':
		mult, s = 7, s[:len(s)-1]
	case 'm':
		mult, s = 30, s[:len(s)-1]
	case 'y':
		mult, s = 365, s[:len(s)-1]
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%q: a number of days like 90, 90d, 12w, 6m or 1y", s)
	}
	return n * mult, nil
}

// ---------------------------------------------------------------- the context of a command

// Ctx is what a command gets: its arguments and flags, the output, the configuration and, on
// first use, the API client.
type Ctx struct {
	context.Context
	Args    []string
	flags   map[string]string
	Out     io.Writer // data: tables, JSON
	Stderr  io.Writer // messages for people
	In      io.Reader
	inr     *bufio.Reader
	st      style // for Out
	est     style // for Err
	tty     bool  // a person at the keyboard (stdin and stderr are terminals)
	cfg     *Config
	version string
	cmd     *Command
	ctxName string
	client  *Client
}

func (c *Ctx) flag(name string) string { return c.flags[name] }
func (c *Ctx) has(name string) bool    { _, ok := c.flags[name]; return ok }
func (c *Ctx) on(name string) bool     { return c.flags[name] == "true" }
func (c *Ctx) json() bool              { return c.on("json") }

// say writes a message for people (stderr), not part of the data.
func (c *Ctx) say(format string, a ...any) { fmt.Fprintf(c.Stderr, format+"\n", a...) }

// done reports a finished change.
func (c *Ctx) done(format string, a ...any) {
	fmt.Fprintln(c.Stderr, c.est.ok(fmt.Sprintf(format, a...)))
}

// hint is a suggestion for what to do next.
func (c *Ctx) hint(format string, a ...any) {
	fmt.Fprintln(c.Stderr, c.est.dim(fmt.Sprintf(format, a...)))
}

// printJSON prints raw JSON indented.
func (c *Ctx) printJSON(v any) error {
	var raw []byte
	switch x := v.(type) {
	case json.RawMessage:
		raw = x
	default:
		var err error
		if raw, err = json.Marshal(v); err != nil {
			return err
		}
	}
	var out any
	if len(raw) == 0 {
		raw = []byte("null")
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Fprintln(c.Out, string(pretty))
	return nil
}

var errCanceled = errors.New("canceled")

// ask reads a line from the person (prompt on stderr).
func (c *Ctx) ask(prompt string) (string, error) {
	if !c.tty {
		return "", fmt.Errorf("%s: no terminal to ask on (pass it as a flag)", strings.TrimSuffix(strings.TrimSpace(prompt), ":"))
	}
	fmt.Fprint(c.Stderr, prompt)
	if c.inr == nil {
		c.inr = bufio.NewReader(c.In) // one reader for every question: it may read ahead
	}
	line, err := c.inr.ReadString('\n')
	if err != nil && line == "" {
		if errors.Is(err, io.EOF) {
			return "", errCanceled
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// confirm asks before something that cannot be undone: the person types expect (the name of
// what goes). --yes skips it; without a terminal and without --yes, it refuses.
func (c *Ctx) confirm(what, expect string) error {
	if c.on("yes") {
		return nil
	}
	if !c.tty {
		return fmt.Errorf("%s\nNot without confirmation: add --yes (there is no terminal to ask on)", what)
	}
	fmt.Fprintln(c.Stderr, c.est.yellow(what))
	answer, err := c.ask(fmt.Sprintf("Type %s to confirm: ", c.est.bold(expect)))
	if err != nil {
		return err
	}
	if answer != expect {
		return errCanceled
	}
	return nil
}
