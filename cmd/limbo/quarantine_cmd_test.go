package main

import (
	"flag"
	"reflect"
	"testing"
	"time"
)

// Regression: "verdict ID safe --note x" must parse the flag even though it comes
// after the positional arguments. It once did not, and the verdict was dropped.
func TestFlagsMayFollowPositionals(t *testing.T) {
	tests := []struct {
		args []string
		pos  []string
		note string
		sock string
	}{
		{[]string{"verdict", "q-1", "safe", "--note", "false alarm"}, []string{"verdict", "q-1", "safe"}, "false alarm", "s"},
		{[]string{"--note", "n", "verdict", "q-1", "safe"}, []string{"verdict", "q-1", "safe"}, "n", "s"},
		{[]string{"--socket", "/x.sock", "show", "q-1"}, []string{"show", "q-1"}, "", "/x.sock"},
		{[]string{"list"}, []string{"list"}, "", "s"},
		{nil, nil, "", "s"},
	}
	for _, tc := range tests {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		sock := fs.String("socket", "s", "")
		note := fs.String("note", "", "")
		pos, err := parseInterspersed(fs, tc.args)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(pos, tc.pos) || *note != tc.note || *sock != tc.sock {
			t.Errorf("%v: pos=%v note=%q sock=%q", tc.args, pos, *note, *sock)
		}
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Time
		ok   bool
	}{
		{"24h", now.Add(-24 * time.Hour), true},
		{"7d", now.Add(-7 * 24 * time.Hour), true},
		{"2026-10-01", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), true},
		{"0d", time.Time{}, false},
		{"-5h", time.Time{}, false},
		{"yesterday", time.Time{}, false},
	}
	for _, tc := range tests {
		got, err := parseSince(tc.in, now)
		if (err == nil) != tc.ok || (tc.ok && !got.Equal(tc.want)) {
			t.Errorf("%q: got %v, %v", tc.in, got, err)
		}
	}
}
