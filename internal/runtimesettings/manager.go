package runtimesettings

import (
	"sync/atomic"
)

// Manager holds the authoritative runtime Document for hot consumers.
type Manager struct {
	value atomic.Pointer[Document]
}

func NewManager(initial Document) *Manager {
	manager := &Manager{}
	clone := initial.Clone()
	manager.value.Store(&clone)
	return manager
}

func (m *Manager) Snapshot() Document {
	if m == nil {
		return Defaults()
	}
	current := m.value.Load()
	if current == nil {
		return Defaults()
	}
	return current.Clone()
}

func (m *Manager) Replace(next Document) {
	clone := next.Clone()
	m.value.Store(&clone)
}
