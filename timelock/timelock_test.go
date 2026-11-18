package timelock

import "testing"

const now = int64(1_800_000_000_000)

var a = Assumptions{FastBlockMs: 100_000, SlowBlockMs: 400_000}

func TestHeightWindow(t *testing.T) {
	w, err := HeightWindow(now, 1000, 1010, a)
	if err != nil || w.Earliest != now+1_000_000 || w.Latest != now+4_000_000 {
		t.Fatalf("got %+v %v", w, err)
	}
	w, _ = HeightWindow(now, 1000, 900, a)
	if w.Earliest != now || w.Latest != now {
		t.Fatal("past height must be open now")
	}
}

func TestHeightNotAfter(t *testing.T) {
	// 10 slow blocks = 4,000,000 ms; 4,399,999 ms still floors to 10.
	h, err := HeightNotAfter(now, 1000, now+4_399_999, a)
	if err != nil || h != 1010 {
		t.Fatalf("got %d %v", h, err)
	}
	w, _ := HeightWindow(now, 1000, h, a)
	if w.Latest > now+4_399_999 {
		t.Fatal("window opens after the deadline")
	}
	if _, err := HeightNotAfter(now, 1000, now+399_999, a); err == nil {
		t.Fatal("sub-block deadline accepted")
	}
}

func TestHeightNotBefore(t *testing.T) {
	// 1,000,001 ms needs ceil(10.00001) = 11 fast blocks.
	h, err := HeightNotBefore(now, 1000, now+1_000_001, a)
	if err != nil || h != 1011 {
		t.Fatalf("got %d %v", h, err)
	}
	w, _ := HeightWindow(now, 1000, h, a)
	if w.Earliest < now+1_000_001 {
		t.Fatal("window opens before the deadline")
	}
	h, _ = HeightNotBefore(now, 1000, now-5, a)
	if h != 1001 {
		t.Fatalf("past deadline -> next block, got %d", h)
	}
}

func TestOrderingRule(t *testing.T) {
	init := MsWindow(now + 10_000_000)
	resp, _ := HeightWindow(now, 1000, 1015, a) // latest = now+6,000,000
	if err := CheckOrdering(init, resp, 3_000_000); err != nil {
		t.Fatalf("safe ordering rejected: %v", err)
	}
	if err := CheckOrdering(init, resp, 4_000_000); err == nil {
		t.Fatal("ordering with exactly zero slack accepted") // 10,000,000 <= 6,000,000+4,000,000
	}
	if err := CheckOrdering(resp, init, 1); err == nil {
		t.Fatal("reversed legs accepted")
	}
	if err := CheckOrdering(init, resp, 0); err == nil {
		t.Fatal("zero margin accepted")
	}
}

func TestPickResponderHeightFromInitiatorDeadline(t *testing.T) {
	// The coordinator's recipe: responder height = HeightNotAfter(initiator deadline - margin).
	initDeadline, margin := now+20_000_000, int64(5_000_000)
	h, err := HeightNotAfter(now, 1000, initDeadline-margin-1, a)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := HeightWindow(now, 1000, h, a)
	if err := CheckOrdering(MsWindow(initDeadline), resp, margin); err != nil {
		t.Fatalf("recipe produced unsafe ordering: %v", err)
	}
}

func TestPearlDefault(t *testing.T) {
	if PearlDefault.FastBlockMs != 97_000 || PearlDefault.SlowBlockMs != 388_000 {
		t.Fatal("Pearl defaults drifted from 3m14s target")
	}
	if err := (Assumptions{FastBlockMs: 2, SlowBlockMs: 1}).check(); err == nil {
		t.Fatal("inverted assumptions accepted")
	}
}
