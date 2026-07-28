package runtimesettings

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type ContainersSettings struct {
	APICpus           string `json:"apiCpus"`
	APIMemory         string `json:"apiMemory"`
	ExportCpus        string `json:"exportCpus"`
	ExportMemory      string `json:"exportMemory"`
	MaintenanceCpus   string `json:"maintenanceCpus"`
	MaintenanceMemory string `json:"maintenanceMemory"`
	AppCpus           string `json:"appCpus"`
	AppMemory         string `json:"appMemory"`
}

func defaultContainers() ContainersSettings {
	return ContainersSettings{
		APICpus:           "2",
		APIMemory:         "2G",
		ExportCpus:        "2",
		ExportMemory:      "2G",
		MaintenanceCpus:   "2",
		MaintenanceMemory: "2G",
		AppCpus:           "4",
		AppMemory:         "4G",
	}
}

func (c ContainersSettings) Validate() error {
	for _, item := range []struct {
		name string
		cpus string
		mem  string
	}{
		{"containers.api", c.APICpus, c.APIMemory},
		{"containers.export", c.ExportCpus, c.ExportMemory},
		{"containers.maintenance", c.MaintenanceCpus, c.MaintenanceMemory},
		{"containers.app", c.AppCpus, c.AppMemory},
	} {
		if err := requireCPU(item.name+".cpus", item.cpus); err != nil {
			return err
		}
		if err := requireMemory(item.name+".memory", item.mem); err != nil {
			return err
		}
	}
	return nil
}

func requireCPU(name, raw string) error {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return fmt.Errorf("%s: invalid CPU count %q", name, raw)
	}
	if value < 0.25 || value > 64 {
		return fmt.Errorf("%s must be between 0.25 and 64", name)
	}
	return nil
}

func requireMemory(name, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("%s is required", name)
	}
	upper := strings.ToUpper(raw)
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(upper, "GI") || strings.HasSuffix(upper, "G"):
		multiplier = 1 << 30
		upper = strings.TrimSuffix(strings.TrimSuffix(upper, "GI"), "G")
	case strings.HasSuffix(upper, "MI") || strings.HasSuffix(upper, "M"):
		multiplier = 1 << 20
		upper = strings.TrimSuffix(strings.TrimSuffix(upper, "MI"), "M")
	case strings.HasSuffix(upper, "KI") || strings.HasSuffix(upper, "K"):
		multiplier = 1 << 10
		upper = strings.TrimSuffix(strings.TrimSuffix(upper, "KI"), "K")
	default:
		if _, err := strconv.ParseInt(upper, 10, 64); err != nil {
			return fmt.Errorf("%s: use docker memory syntax like 2G or 512M", name)
		}
	}
	amount, err := strconv.ParseFloat(upper, 64)
	if err != nil || amount <= 0 {
		return fmt.Errorf("%s: invalid memory %q", name, raw)
	}
	bytes := int64(amount * float64(multiplier))
	if bytes < 128<<20 || bytes > 256<<30 {
		return fmt.Errorf("%s must be between 128M and 256G", name)
	}
	return nil
}

func containersFromEnv() ContainersSettings {
	c := defaultContainers()
	c.APICpus = envOr("COLLECTOR_API_CPUS", c.APICpus)
	c.APIMemory = envOr("COLLECTOR_API_MEMORY", c.APIMemory)
	c.ExportCpus = envOr("COLLECTOR_EXPORT_CPUS", c.ExportCpus)
	c.ExportMemory = envOr("COLLECTOR_EXPORT_MEMORY", c.ExportMemory)
	c.MaintenanceCpus = envOr("COLLECTOR_MAINTENANCE_CPUS", c.MaintenanceCpus)
	c.MaintenanceMemory = envOr("COLLECTOR_MAINTENANCE_MEMORY", c.MaintenanceMemory)
	c.AppCpus = envOr("COLLECTOR_CPUS", c.AppCpus)
	c.AppMemory = envOr("COLLECTOR_MEMORY", c.AppMemory)
	return c
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

// ComposeEnvFragment renders KEY=value lines for docker compose / host .env sync.
func (c ContainersSettings) ComposeEnvFragment() string {
	var b strings.Builder
	b.WriteString("# Generated from Настройки → Параметры. Apply with docker compose up -d --force-recreate\n")
	b.WriteString("COLLECTOR_API_CPUS=" + c.APICpus + "\n")
	b.WriteString("COLLECTOR_API_MEMORY=" + c.APIMemory + "\n")
	b.WriteString("COLLECTOR_EXPORT_CPUS=" + c.ExportCpus + "\n")
	b.WriteString("COLLECTOR_EXPORT_MEMORY=" + c.ExportMemory + "\n")
	b.WriteString("COLLECTOR_MAINTENANCE_CPUS=" + c.MaintenanceCpus + "\n")
	b.WriteString("COLLECTOR_MAINTENANCE_MEMORY=" + c.MaintenanceMemory + "\n")
	b.WriteString("COLLECTOR_CPUS=" + c.AppCpus + "\n")
	b.WriteString("COLLECTOR_MEMORY=" + c.AppMemory + "\n")
	return b.String()
}
