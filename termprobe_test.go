package termprobe

import (
	"bytes"
	"testing"
	"time"
)

// scripted hands out chunks one per ReadTimeout call, then reports timeouts.
type scripted struct {
	chunks [][]byte
	calls  int
}

func (s *scripted) ReadTimeout(p []byte, d time.Duration) (int, error) {
	s.calls++
	if len(s.chunks) == 0 {
		return 0, nil
	}
	n := copy(p, s.chunks[0])
	s.chunks[0] = s.chunks[0][n:]
	if len(s.chunks[0]) == 0 {
		s.chunks = s.chunks[1:]
	}
	return n, nil
}

func (s *scripted) set(chunks ...string) {
	s.chunks = nil
	for _, c := range chunks {
		s.chunks = append(s.chunks, []byte(c))
	}
}

const (
	syncTermDA  = "\x1b[=67;84;101;114;109;1;3;0c"
	oldCTermDA  = "\x1b[=67;84;101;114;109;0;9;0c"
	xtermDA     = "\x1b[?64;1;2;6;9;15;16;17;18;21;22;28c"
	fTelnetSXG  = "\x1b[?2;0;640;400S"
	iTermXTV    = "\x1bP>|iTerm2 3.5.14\x1b\\"
	xtermXTV    = "\x1bP>|XTerm(390)\x1b\\"
	tmuxXTV     = "\x1bP>|tmux 3.4\x1b\\"
	rqssTrue    = "\x1bP1$r0;38;2;1;2;3m\x1b\\"
	rqssTrueCol = "\x1bP1$r0;38:2::1:2:3m\x1b\\"
	rqss256     = "\x1bP1$r0;38;5;16m\x1b\\"
	rqssNone    = "\x1bP0$r\x1b\\"
)

func TestDecide(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  Depth
		cterm string
		term  string
	}{
		{"silent (NetRunner, Linux console)", "", Depth16, "", ""},
		{"SyncTERM 1.3", syncTermDA, DepthTrue, "1.3", ""},
		{"CTerm 0.9", oldCTermDA, Depth16, "0.9", ""},
		{"fTelnet: only the sixel geometry reply", fTelnetSXG, DepthTrue, "", ""},
		{"plain xterm DA only", xtermDA, Depth16, "", ""},
		{"iTerm2 full set", iTermXTV + rqssTrueCol + fTelnetSXG + xtermDA, DepthTrue, "", "iTerm2 3.5.14"},
		{"modern xterm", xtermXTV + rqssTrue + xtermDA, DepthTrue, "", "XTerm(390)"},
		{"256-color terminal that quantized", rqss256 + xtermDA, Depth256, "", ""},
		{"quantized echo outranks a known name", iTermXTV + rqss256 + xtermDA, Depth256, "", "iTerm2 3.5.14"},
		{"unlisted terminal answering XTVERSION", tmuxXTV + xtermDA, Depth256, "", "tmux 3.4"},
		{"DECRQSS refused, DA plain", rqssNone + xtermDA, Depth16, "", ""},
		{"BEL-terminated XTVERSION", "\x1bP>|kitty(0.36.2)\x07" + xtermDA, DepthTrue, "", "kitty(0.36.2)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Decide([]byte(c.in), 400*time.Millisecond)
			if r.Depth != c.want {
				t.Fatalf("depth = %s, want %s (%s)", r.Depth, c.want, r.Reason)
			}
			if r.CTerm != c.cterm {
				t.Fatalf("cterm = %q, want %q", r.CTerm, c.cterm)
			}
			if r.Terminal != c.term {
				t.Fatalf("terminal = %q, want %q", r.Terminal, c.term)
			}
			if len(r.Leftover) != 0 {
				t.Fatalf("leftover = %q, want none", r.Leftover)
			}
			if r.Reason == "" {
				t.Fatal("empty reason")
			}
		})
	}
}

func TestLeftoverPreservesKeystrokes(t *testing.T) {
	in := "ab" + iTermXTV + "\x1b[A" + rqssTrue + "q" + syncTermDA + "zz"
	r := Decide([]byte(in), time.Second)
	if r.Depth != DepthTrue {
		t.Fatalf("depth = %s (%s)", r.Depth, r.Reason)
	}
	if got, want := string(r.Leftover), "ab\x1b[Aqzz"; got != want {
		t.Fatalf("leftover = %q, want %q", got, want)
	}
}

func TestUnknownSequencesStayInLeftover(t *testing.T) {
	// A cursor-position report from an earlier size probe, and a lone ESC.
	in := "\x1b[24;80R\x1b"
	r := Decide([]byte(in), time.Second)
	if r.Depth != Depth16 {
		t.Fatalf("depth = %s", r.Depth)
	}
	if string(r.Leftover) != in {
		t.Fatalf("leftover = %q, want %q", r.Leftover, in)
	}
}

func TestColorDepthStopsAtDA(t *testing.T) {
	var out bytes.Buffer
	s := &scripted{}
	s.set(iTermXTV, xtermDA, "never read")
	r := ColorDepth(&out, s, 2*time.Second)
	if out.String() != Queries {
		t.Fatalf("wrote %q", out.String())
	}
	if r.Depth != DepthTrue {
		t.Fatalf("got %s", r)
	}
	if s.calls != 2 {
		t.Fatalf("reads = %d, want 2 (stop on the DA reply)", s.calls)
	}
	if len(s.chunks) != 1 {
		t.Fatalf("the probe read past the DA reply")
	}
}

func TestColorDepthSilentTimesOut(t *testing.T) {
	var out bytes.Buffer
	start := time.Now()
	r := ColorDepth(&out, &scripted{}, 120*time.Millisecond)
	el := time.Since(start)
	if r.Depth != Depth16 {
		t.Fatalf("got %s", r)
	}
	if el > 100*time.Millisecond {
		// the scripted reader returns instantly, so the loop spins until the
		// deadline; it must not overrun it by much
		t.Logf("elapsed %v", el)
	}
}

func TestSplitReplies(t *testing.T) {
	// A reply arriving one byte at a time must still be recognised.
	s := &scripted{}
	for _, b := range []byte(rqss256 + syncTermDA) {
		s.chunks = append(s.chunks, []byte{b})
	}
	r := ColorDepth(&bytes.Buffer{}, s, time.Second)
	if r.Depth != Depth256 {
		t.Fatalf("got %s", r)
	}
}

func TestPollReader(t *testing.T) {
	data := []byte("x")
	calls := 0
	read := func(p []byte) (int, bool, error) {
		calls++
		if calls < 3 {
			return 0, true, nil
		}
		return copy(p, data), false, nil
	}
	pr := PollReader(read, time.Millisecond)
	buf := make([]byte, 4)
	n, err := pr.ReadTimeout(buf, 500*time.Millisecond)
	if n != 1 || err != nil || buf[0] != 'x' {
		t.Fatalf("n=%d err=%v", n, err)
	}
	// Exhausted: again=true forever -> timeout as (0, nil)
	pr = PollReader(func(p []byte) (int, bool, error) { return 0, true, nil }, time.Millisecond)
	n, err = pr.ReadTimeout(buf, 20*time.Millisecond)
	if n != 0 || err != nil {
		t.Fatalf("timeout n=%d err=%v", n, err)
	}
}

func TestChanReader(t *testing.T) {
	ch := make(chan []byte, 2)
	ch <- []byte("abc")
	cr := ChanReader(ch)
	buf := make([]byte, 2)
	n, err := cr.ReadTimeout(buf, time.Second)
	if n != 2 || err != nil || string(buf[:2]) != "ab" {
		t.Fatalf("n=%d err=%v buf=%q", n, err, buf[:n])
	}
	n, _ = cr.ReadTimeout(buf, time.Second)
	if n != 1 || buf[0] != 'c' {
		t.Fatalf("remainder n=%d %q", n, buf[:n])
	}
	n, err = cr.ReadTimeout(buf, 10*time.Millisecond)
	if n != 0 || err != nil {
		t.Fatalf("timeout n=%d err=%v", n, err)
	}
	close(ch)
	if _, err = cr.ReadTimeout(buf, time.Second); err == nil {
		t.Fatal("closed channel should read as EOF")
	}
}

const (
	syncTerm1316DA = "\x1b[=67;84;101;114;109;1;316;0c"
	ctdaPixels     = "\x1b[<1;2;3;4;5;6;7c"
	ctdaNoPixels   = "\x1b[<1;2;3;5c"
	xtermSixelDA   = "\x1b[?64;1;2;4;6;9;15;16;17;18;21;22;28c"
	fTelnetDA      = "\x1b[=67;84;101;114;109;1;189c"
	fTelnetCTDA    = "\x1b[<0;4;7;8c"
	cellReply      = "\x1b[6;20;10t"
	areaReplies    = "\x1b[4;480;800t\x1b[8;24;80t"
)

func TestSixelDecision(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		sixel        bool
		cellW, cellH int
	}{
		{"silent", "", false, 0, 0},
		{"xterm without sixel", xtermDA, false, 0, 0},
		{"xterm with sixel, cell reply", xtermSixelDA + cellReply, true, 10, 20},
		{"xterm with sixel, area replies only", xtermSixelDA + areaReplies, true, 10, 20},
		{"xterm with sixel, no size", xtermSixelDA, true, 0, 0},
		{"SyncTERM 1.3 without CTDA", syncTermDA, false, 0, 0},
		{"fTelnet_enhanced: CTerm 1.189 answers CTDA with pixels", fTelnetDA + fTelnetCTDA, true, 0, 0},
		{"SyncTERM 1.316 with pixel ops", syncTerm1316DA + ctdaPixels, true, 0, 0},
		{"SyncTERM 1.316 text mode", syncTerm1316DA + ctdaNoPixels, false, 0, 0},
		{"SyncTERM 1.316 no CTDA", syncTerm1316DA, false, 0, 0},
		{"conformance level 4 alone is not sixel", "\x1b[?4c", false, 0, 0},
		{"insane cell size ignored", xtermSixelDA + "\x1b[6;2000;1t", true, 0, 0},
	}
	for _, c := range cases {
		r := Decide([]byte(c.in), time.Second)
		if r.Sixel != c.sixel || r.CellW != c.cellW || r.CellH != c.cellH {
			t.Errorf("%s: sixel=%v cell=%dx%d (%s), want %v %dx%d", c.name, r.Sixel, r.CellW, r.CellH, r.SixelReason, c.sixel, c.cellW, c.cellH)
		}
		if len(r.Leftover) != 0 {
			t.Errorf("%s: leftover %q", c.name, r.Leftover)
		}
	}
}

func TestSecondBurstForCTerm(t *testing.T) {
	var out bytes.Buffer
	s := &scripted{}
	s.set(syncTerm1316DA, ctdaPixels+"\x1b[6;16;8t", syncTerm1316DA, "typed")
	r := ColorDepth(&out, s, time.Second)
	want := Queries + ctdaQuery + cellQueries + "\x1b[c"
	if out.String() != want {
		t.Fatalf("wrote %q, want %q", out.String(), want)
	}
	if !r.Sixel || r.CellW != 8 || r.CellH != 16 || r.Depth != DepthTrue {
		t.Fatalf("got %s / %s", r, r.SixelReason)
	}
	if len(s.chunks) != 1 {
		t.Fatalf("read past the second DA reply")
	}
}

// An older CTerm revision is still asked CTDA: fTelnet_enhanced reports
// 1.189 and answers it with pixel operations.
func TestSecondBurstForOldCTermRevision(t *testing.T) {
	var out bytes.Buffer
	s := &scripted{}
	s.set(fTelnetDA, fTelnetCTDA+fTelnetDA)
	r := ColorDepth(&out, s, time.Second)
	want := Queries + ctdaQuery + cellQueries + "\x1b[c"
	if out.String() != want {
		t.Fatalf("wrote %q, want %q", out.String(), want)
	}
	if !r.Sixel || r.CTerm != "1.189" {
		t.Fatalf("got %s / %s", r, r.SixelReason)
	}
	if string(r.Raw) != fTelnetDA+fTelnetCTDA+fTelnetDA {
		t.Fatalf("raw = %q", r.Raw)
	}
}

func TestNoSecondBurstForPlainTerminals(t *testing.T) {
	for _, reply := range []string{"", xtermDA} {
		var out bytes.Buffer
		s := &scripted{}
		s.set(reply)
		ColorDepth(&out, s, 80*time.Millisecond)
		if out.String() != Queries {
			t.Errorf("reply %q: wrote %q, want only the first burst", reply, out.String())
		}
	}
}
