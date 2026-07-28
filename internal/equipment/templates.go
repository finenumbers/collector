package equipment

import (
	"errors"
	"sort"
)

const (
	CategoryEquipment  = "equipment"
	CategorySoftswitch = "softswitch"

	TemplateEltex3410     = "eltex-smg-1016m-3.410"
	TemplateEltex3232     = "eltex-smg-1016m-3.23.2"
	TemplateSatelRTUCDRV1 = "satel-rtu-cdr-v1"
	SatelRTUParserVersion = "satel-rtu-cdr-v1"
)

type Capabilities struct {
	Syslog    bool `json:"syslog"`
	TypedCDR  bool `json:"typedCdr"`
	RawCDR    bool `json:"rawCdr"`
	Antifraud bool `json:"antifraud"`
	Radius    bool `json:"radius"`
}

type Template struct {
	Key          string       `json:"key"`
	Category     string       `json:"category"`
	DisplayName  string       `json:"displayName"`
	Capabilities Capabilities `json:"capabilities"`
}

var registry = map[string]Template{
	TemplateEltex3410: {
		Key: TemplateEltex3410, Category: CategoryEquipment,
		DisplayName: "Eltex SMG-1016M (3.410)",
		Capabilities: Capabilities{
			Syslog: true, TypedCDR: true, RawCDR: true, Antifraud: true, Radius: true,
		},
	},
	TemplateEltex3232: {
		Key: TemplateEltex3232, Category: CategoryEquipment,
		DisplayName: "Eltex SMG-1016M (3.23.2)",
		Capabilities: Capabilities{
			Syslog: true, TypedCDR: true, RawCDR: true, Antifraud: true, Radius: true,
		},
	},
	TemplateSatelRTUCDRV1: {
		Key: TemplateSatelRTUCDRV1, Category: CategorySoftswitch,
		DisplayName: "Satel RTU",
		Capabilities: Capabilities{
			TypedCDR: true, RawCDR: true,
		},
	},
}

var ErrUnknownTemplate = errors.New("unknown equipment template")

func Resolve(key string) (Template, error) {
	template, ok := registry[key]
	if !ok {
		return Template{}, ErrUnknownTemplate
	}
	return template, nil
}

func List() []Template {
	result := make([]Template, 0, len(registry))
	for _, template := range registry {
		result = append(result, template)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Category == result[j].Category {
			return result[i].Key < result[j].Key
		}
		return result[i].Category < result[j].Category
	})
	return result
}

func EltexTemplateForFirmware(firmware string) string {
	if firmware == "3.410" {
		return TemplateEltex3410
	}
	return TemplateEltex3232
}
