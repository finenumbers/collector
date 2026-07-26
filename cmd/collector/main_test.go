package main

import "testing"

func TestCorrelationBudgetRemainsAvailableDuringReplay(t *testing.T) {
	if got := correlationBudget(true); got == 0 || got >= correlationBudget(false) {
		t.Fatalf("replay budget=%d normal budget=%d", got, correlationBudget(false))
	}
}
