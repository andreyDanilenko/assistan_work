package cli_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"loki-analyzer/internal/cli"
)

func TestParseOptionsPeriods(t *testing.T) {
	now := time.Date(2026, 10, 9, 14, 30, 0, 0, time.FixedZone("MSK", 3*60*60))
	opts, err := cli.Parse([]string{"logs", "--since", "30m"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Request.End.Equal(now) || !opts.Request.Start.Equal(now.Add(-30*time.Minute)) || opts.Request.Start.Location() != time.UTC || opts.Request.End.Location() != time.UTC {
		t.Fatalf("incorrect relative UTC period: %v to %v", opts.Request.Start, opts.Request.End)
	}
	opts, err = cli.Parse([]string{"logs", "--start", "2026-10-09T14:00:00.123+03:00", "--end", "2026-10-09T14:30:00+03:00"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := opts.Request.Start.Format(time.RFC3339Nano); got != "2026-10-09T11:00:00.123Z" {
		t.Fatalf("start = %s", got)
	}
	if opts.Request.Limit != 20 || opts.Timeout != 30*time.Second || opts.EnvFile != ".env" || opts.ExplicitEnv {
		t.Fatalf("unexpected default settings: %#v", opts)
	}
}

func TestParseOptionsRejectsInvalidInput(t *testing.T) {
	cases := map[string][]string{
		"relative and absolute": {"logs", "--since", "15m", "--start", "2026-10-09T11:00:00Z", "--end", "2026-10-09T11:30:00Z"},
		"missing end":           {"logs", "--start", "2026-10-09T11:00:00Z"},
		"missing start":         {"logs", "--end", "2026-10-09T11:30:00Z"},
		"missing timezone":      {"logs", "--start", "2026-10-09T11:00:00", "--end", "2026-10-09T11:30:00Z"},
		"reversed range":        {"logs", "--start", "2026-10-09T12:00:00Z", "--end", "2026-10-09T11:00:00Z"},
		"empty range":           {"logs", "--start", "2026-10-09T11:00:00Z", "--end", "2026-10-09T11:00:00Z"},
		"absolute over limit":   {"logs", "--start", "2026-10-07T11:00:00Z", "--end", "2026-10-09T11:00:00Z"},
		"relative over limit":   {"logs", "--since", "25h"},
		"zero duration":         {"logs", "--since", "0s"},
		"negative duration":     {"logs", "--since", "-1s"},
		"whitespace query":      {"query", "--query", " \t\n"},
		"missing query":         {"query"},
		"query on logs":         {"logs", "--query", "{}"},
		"project on query":      {"query", "--query", "{}", "--project", "billing"},
		"empty project":         {"logs", "--project", " "},
		"limit on labels":       {"labels", "--limit", "20"},
		"zero limit":            {"logs", "--limit", "0"},
		"large limit":           {"logs", "--limit", "100001"},
		"zero timeout":          {"logs", "--timeout", "0s"},
		"large timeout":         {"logs", "--timeout", "11m"},
		"empty env path":        {"logs", "--env-file", ""},
		"missing label":         {"values"},
		"flag before label":     {"values", "--since", "1m", "app"},
		"positional remainder":  {"logs", "billing"},
		"unknown flag":          {"logs", "--secret", "private-value"},
		"unknown command":       {"missing"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := cli.Parse(args, time.Now()); err == nil || errors.Is(err, cli.ErrHelp) {
				t.Fatalf("invalid input accepted: %#v, error %v", args, err)
			}
		})
	}
}

func TestParseOptionsCommandArgumentsAndHelp(t *testing.T) {
	opts, err := cli.Parse([]string{"values", "app", "--env-file", "settings.env", "--raw"}, time.Now())
	if err != nil || opts.Request.Label != "app" || opts.EnvFile != "settings.env" || !opts.ExplicitEnv || !opts.Raw {
		t.Fatalf("values arguments: %#v, %v", opts, err)
	}
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"logs", "--help"}} {
		if _, err := cli.Parse(args, time.Now()); !errors.Is(err, cli.ErrHelp) {
			t.Fatalf("help arguments %v: %v", args, err)
		}
	}
}

func TestParseTelegramCheck(t *testing.T) {
	opts, err := cli.Parse([]string{"telegram-check", "--env-file", "bot.env", "--timeout", "5s"}, time.Now())
	if err != nil || opts.Mode != cli.TelegramMode || opts.EnvFile != "bot.env" || !opts.ExplicitEnv || opts.Timeout != 5*time.Second {
		t.Fatalf("Telegram arguments: %#v, %v", opts, err)
	}
	if opts.Request.Command != "" || !opts.Request.Start.IsZero() || !opts.Request.End.IsZero() {
		t.Fatal("Telegram initialization must not create a Loki request")
	}
	for _, args := range [][]string{
		{"--raw"}, {"--since", "2m"}, {"--start", "2026-10-09T11:00:00Z"},
		{"--end", "2026-10-09T11:30:00Z"}, {"--limit", "5"},
		{"--project", "orders"}, {"--query", "{}"}, {"--timeout", "0s"},
	} {
		if _, err := cli.Parse(append([]string{"telegram-check"}, args...), time.Now()); err == nil {
			t.Fatalf("unsupported Telegram flags accepted: %v", args)
		}
	}
	if _, err := cli.Parse([]string{"telegram-check", "--help"}, time.Now()); !errors.Is(err, cli.ErrHelp) {
		t.Fatal("Telegram help failed")
	}
}

func TestParseAnalyze(t *testing.T) {
	options, err := cli.Parse([]string{"analyze", "--file", "sample.txt", "--timeout", "5s"}, time.Now())
	if err != nil || options.Mode != cli.AnalyzeMode || options.File != "sample.txt" || options.Timeout != 5*time.Second {
		t.Fatalf("analyze options: %#v, %v", options, err)
	}
	if options.EnvFile != "" || options.Request.Command != "" || !options.Request.Start.IsZero() {
		t.Fatal("offline analysis must not carry environment or Loki query settings")
	}
	for _, args := range [][]string{
		{}, {"--file", " "}, {"--file", "a", "--raw"}, {"--file", "a", "--since", "2m"},
		{"--file", "a", "--env-file", ".env"}, {"--file", "a", "--project", "x"},
		{"--file", "a", "--limit", "5"}, {"--file", "a", "--timeout", "0s"},
	} {
		if _, err := cli.Parse(append([]string{"analyze"}, args...), time.Now()); err == nil {
			t.Fatalf("invalid analysis arguments accepted: %v", args)
		}
	}
	if _, err := cli.Parse([]string{"analyze", "--help"}, time.Now()); !errors.Is(err, cli.ErrHelp) {
		t.Fatal("analyze help failed")
	}
	if _, err := cli.Parse([]string{"logs", "--file", "sample.txt"}, time.Now()); err == nil {
		t.Fatal("file flag must apply only to analyze")
	}
	options, err = cli.Parse([]string{"analyze", "--file", "sample.txt", "--all-orders"}, time.Now())
	if err != nil || !options.AllOrders {
		t.Fatal("analysis must support displaying all orders")
	}
	if _, err := cli.Parse([]string{"logs", "--all-orders"}, time.Now()); err == nil {
		t.Fatal("all-orders flag must apply only to analyze")
	}
}

func TestParseWatch(t *testing.T) {
	now := time.Now()
	options, err := cli.Parse([]string{"watch"}, now)
	if err != nil || options.Mode != cli.WatchMode || options.Once || options.DryRun || options.EnvFile != ".env" {
		t.Fatalf("unexpected watch defaults: %#v, %v", options, err)
	}
	if options.Request.Command != "" || !options.Request.Start.IsZero() || !options.Request.End.IsZero() {
		t.Fatal("watch must calculate each cycle's window later, not freeze a CLI query range")
	}
	options, err = cli.Parse([]string{"watch", "--once", "--dry-run", "--project", "orders", "--env-file", "watch.env", "--timeout", "2m"}, now)
	if err != nil || !options.Once || !options.DryRun || options.Request.Project != "orders" || options.EnvFile != "watch.env" || !options.ExplicitEnv || options.Timeout != 2*time.Minute {
		t.Fatalf("watch overrides were not preserved: %#v, %v", options, err)
	}
	for _, args := range [][]string{
		{"--since", "2m"}, {"--start", "2026-10-09T11:00:00Z"}, {"--end", "2026-10-09T11:30:00Z"},
		{"--limit", "5"}, {"--raw"}, {"--query", "{}"}, {"--file", "sample.txt"}, {"--all-orders"},
		{"--project", " "}, {"--project", strings.Repeat("a", 4097)}, {"--timeout", "0s"},
		{"--timeout", "11m"}, {"--env-file", ""},
	} {
		if _, err := cli.Parse(append([]string{"watch"}, args...), now); err == nil {
			t.Fatalf("invalid watch flags accepted: %v", args)
		}
	}
	if _, err := cli.Parse([]string{"watch", "--help"}, now); !errors.Is(err, cli.ErrHelp) {
		t.Fatal("watch help failed")
	}
}

func TestParseTelegramChats(t *testing.T) {
	options, err := cli.Parse([]string{"telegram-chats", "--env-file", "bot.env", "--timeout", "5s"}, time.Now())
	if err != nil || options.Mode != cli.TelegramChatsMode || options.EnvFile != "bot.env" || !options.ExplicitEnv || options.Timeout != 5*time.Second {
		t.Fatalf("telegram-chats settings: %#v, %v", options, err)
	}
	if options.Request.Command != "" || !options.Request.Start.IsZero() {
		t.Fatal("chat discovery must not create a Loki query")
	}
	for _, args := range [][]string{
		{"--since", "2m"}, {"--project", "orders"}, {"--raw"}, {"--limit", "5"},
		{"--file", "sample.txt"}, {"--all-orders"}, {"--timeout", "0s"}, {"--env-file", ""},
	} {
		if _, err := cli.Parse(append([]string{"telegram-chats"}, args...), time.Now()); err == nil {
			t.Fatalf("invalid chat discovery flags accepted: %v", args)
		}
	}
	if _, err := cli.Parse([]string{"telegram-chats", "--help"}, time.Now()); !errors.Is(err, cli.ErrHelp) {
		t.Fatal("telegram-chats help failed")
	}
}

func TestWatchFlagsAreRejectedByOtherCommands(t *testing.T) {
	for _, base := range [][]string{{"logs"}, {"telegram-check"}, {"telegram-chats"}, {"analyze", "--file", "sample.txt"}} {
		for _, flag := range []string{"--once", "--dry-run"} {
			args := append(append([]string{}, base...), flag)
			if _, err := cli.Parse(args, time.Now()); err == nil {
				t.Fatalf("watch flag accepted by another command: %v", args)
			}
		}
	}
}

func TestParseDatabaseCommandsRejectsNetworkAndWatchFlags(t *testing.T) {
	for _, command := range []struct {
		name string
		mode cli.Mode
	}{{"db-status", cli.DBStatusMode}, {"db-cleanup", cli.DBCleanupMode}} {
		t.Run(command.name, func(t *testing.T) {
			options, err := cli.Parse([]string{command.name, "--env-file", "database.env", "--timeout", "5s"}, time.Now())
			if err != nil || options.Mode != command.mode || options.EnvFile != "database.env" || !options.ExplicitEnv || options.Timeout != 5*time.Second {
				t.Fatalf("unexpected database options: %#v, %v", options, err)
			}
			if options.Request.Command != "" || !options.Request.Start.IsZero() || !options.Request.End.IsZero() {
				t.Fatal("database command created a Loki request")
			}
			for _, flags := range [][]string{
				{"--since", "2m"}, {"--start", "2026-10-11T00:00:00Z"}, {"--end", "2026-10-11T01:00:00Z"},
				{"--query", "{}"}, {"--project", "orders"}, {"--limit", "5"}, {"--raw"},
				{"--once"}, {"--dry-run"}, {"--file", "logs.txt"}, {"--all-orders"},
				{"--timeout", "0s"}, {"--env-file", ""},
			} {
				if _, err := cli.Parse(append([]string{command.name}, flags...), time.Now()); err == nil {
					t.Fatalf("database command accepted unrelated flags: %v", flags)
				}
			}
			if _, err := cli.Parse([]string{command.name, "--help"}, time.Now()); !errors.Is(err, cli.ErrHelp) {
				t.Fatal("database command help failed")
			}
		})
	}
}
