package ingest

import (
	"context"
	"testing"

	"collector/internal/analytics"
	"collector/internal/equipment"
)

type countingCDRAnalytics struct {
	calls int
}

func (client *countingCDRAnalytics) InsertCDRBatch(
	context.Context, []analytics.CDRRecord,
) error {
	client.calls++
	return nil
}

func TestRawSoftswitchNeverCallsAnalytics(t *testing.T) {
	template, err := equipment.Resolve(equipment.TemplateSoftswitchRawV1)
	if err != nil {
		t.Fatal(err)
	}
	client := &countingCDRAnalytics{}
	if err := insertCDRForTemplate(context.Background(), template, client, nil); err != nil {
		t.Fatal(err)
	}
	if client.calls != 0 {
		t.Fatalf("raw archive made %d analytics calls", client.calls)
	}
}

func TestTypedTemplateCallsAnalytics(t *testing.T) {
	template, err := equipment.Resolve(equipment.TemplateEltex3410)
	if err != nil {
		t.Fatal(err)
	}
	client := &countingCDRAnalytics{}
	if err := insertCDRForTemplate(context.Background(), template, client, nil); err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 {
		t.Fatalf("typed CDR made %d analytics calls", client.calls)
	}
}
