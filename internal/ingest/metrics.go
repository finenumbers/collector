package ingest

import "sync/atomic"

type Metrics struct {
	acceptedDatagrams atomic.Uint64
	rejectedDatagrams atomic.Uint64
	spoolWriteErrors  atomic.Uint64
	handoffErrors     atomic.Uint64
	handedOff         atomic.Uint64
}

type MetricsSnapshot struct {
	AcceptedDatagrams uint64 `json:"acceptedDatagrams"`
	RejectedDatagrams uint64 `json:"rejectedDatagrams"`
	SpoolWriteErrors  uint64 `json:"spoolWriteErrors"`
	HandoffErrors     uint64 `json:"handoffErrors"`
	HandedOff         uint64 `json:"handedOff"`
}

func (m *Metrics) RecordAccepted() {
	m.RecordAcceptedN(1)
}

func (m *Metrics) RecordAcceptedN(count uint64) {
	if m != nil {
		m.acceptedDatagrams.Add(count)
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

func (m *Metrics) RecordHandoffError() {
	if m != nil {
		m.handoffErrors.Add(1)
	}
}

func (m *Metrics) RecordHandedOff() {
	if m != nil {
		m.handedOff.Add(1)
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
		HandoffErrors:     m.handoffErrors.Load(),
		HandedOff:         m.handedOff.Load(),
	}
}
