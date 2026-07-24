package ingest

import "sync/atomic"

type Metrics struct {
	acceptedDatagrams atomic.Uint64
	rejectedDatagrams atomic.Uint64
	spoolWriteErrors  atomic.Uint64
}

type MetricsSnapshot struct {
	AcceptedDatagrams uint64 `json:"acceptedDatagrams"`
	RejectedDatagrams uint64 `json:"rejectedDatagrams"`
	SpoolWriteErrors  uint64 `json:"spoolWriteErrors"`
}

func (m *Metrics) RecordAccepted() {
	if m != nil {
		m.acceptedDatagrams.Add(1)
	}
}

func (m *Metrics) RecordRejected() {
	if m != nil {
		m.rejectedDatagrams.Add(1)
	}
}

func (m *Metrics) RecordSpoolError() {
	if m != nil {
		m.spoolWriteErrors.Add(1)
	}
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		AcceptedDatagrams: m.acceptedDatagrams.Load(),
		RejectedDatagrams: m.rejectedDatagrams.Load(),
		SpoolWriteErrors:  m.spoolWriteErrors.Load(),
	}
}
