package catalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("params are not a JSON object: %v", err)
	}
	return m
}

func TestEveryClassHasSchema(t *testing.T) {
	for _, c := range Classes() {
		if len(c.Fields) == 0 {
			t.Errorf("class %s has no fields", c.ID)
		}
		for _, f := range c.Fields {
			checkField(t, c.ID, f)
		}
	}
}

// checkField ensures a field is renderable: known type, enum options, list items,
// and the default itself passes validation.
func checkField(t *testing.T, class string, f Field) {
	t.Helper()
	switch f.Type {
	case "string", "text", "int", "number", "bool":
	case "enum":
		if len(f.Options) == 0 {
			t.Errorf("%s.%s: enum without options", class, f.Key)
		}
	case "list":
		if len(f.Item) == 0 {
			t.Errorf("%s.%s: list without item fields", class, f.Key)
		}
		for _, it := range f.Item {
			checkField(t, class+"."+f.Key, it)
		}
	default:
		t.Errorf("%s.%s: unknown type %q", class, f.Key, f.Type)
	}
	if f.Default != nil && f.Type != "list" {
		def := f.Default
		if n, ok := def.(int); ok { // JSON-числа приходят как float64
			def = float64(n)
		}
		if err := validateValue(f, def, f.Key); err != nil {
			t.Errorf("%s: default fails validation: %v", class, err)
		}
	}
}

func TestDefaultsAndPresetsAreValid(t *testing.T) {
	for _, c := range Classes() {
		if err := ValidateParams(c.ID, decode(t, c.DefaultParams)); err != nil {
			t.Errorf("default params of %s: %v", c.ID, err)
		}
	}
	presets := Presets()
	if len(presets) < 10 {
		t.Fatalf("expected the bundled presets, got %d", len(presets))
	}
	for _, p := range presets {
		if _, ok := ClassByID(p.Class); !ok {
			t.Errorf("preset %s: unknown class %s", p.PresetID, p.Class)
			continue
		}
		if err := ValidateParams(p.Class, decode(t, p.Params)); err != nil {
			t.Errorf("preset %s: %v", p.PresetID, err)
		}
	}
}

func TestPresetPortsMovedOutOfParams(t *testing.T) {
	for _, p := range Presets() {
		if p.PresetID != "portscan-detector" {
			continue
		}
		if p.Ports == "" {
			t.Fatal("expected ports to move to the preset's own field")
		}
		if _, still := decode(t, p.Params)["ports"]; still {
			t.Fatal("ports must not stay inside params")
		}
		return
	}
	t.Fatal("portscan-detector preset not found")
}

func TestValidateParamsRejectsBadValues(t *testing.T) {
	cases := []struct {
		class  string
		params string
		want   string
	}{
		{"dialog", `{"decoder":"xml"}`, "decoder"},
		{"dialog", `{"rules":[{"match":"(unclosed"}]}`, "rules[0].match"},
		{"dialog", `{"rules":"nope"}`, "ожидается список"},
		{"dialog", `{"max_commands":1.5}`, "целое"},
		{"banner", `{"close_after_input":"yes"}`, "true/false"},
		{"banner", `{"banner_hex":"zz"}`, "hex"},
		{"http", `{"routes":[{"status":999}]}`, "routes[0].status"},
		{"tarpit", `{"delay_ms":"fast"}`, "число"},
		{"udp", `{"helper":"ftp"}`, "helper"},
	}
	for _, tc := range cases {
		err := ValidateParams(tc.class, decode(t, json.RawMessage(tc.params)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s %s: expected error containing %q, got %v", tc.class, tc.params, tc.want, err)
		}
	}
}

func TestValidateParamsKeepsUnknownKeys(t *testing.T) {
	// Ручной JSON с полями, которых нет в схеме, не отвергаем.
	if err := ValidateParams("banner", map[string]any{"my_note": 42.0}); err != nil {
		t.Fatalf("unknown keys must be allowed, got %v", err)
	}
}

func TestClasses(t *testing.T) {
	cls := Classes()
	if len(cls) != 12 {
		t.Fatalf("expected 12 classes, got %d", len(cls))
	}

	expectedClasses := map[string]string{
		"port_listener":    "Low",
		"banner":           "Low",
		"dialog":           "Medium",
		"http":             "Medium",
		"tarpit":           "Low",
		"honeytoken":       "Medium",
		"udp":              "Low",
		"iec104":           "ICS/SCADA",
		"scada":            "ICS/SCADA",
		"high_interaction": "High",
		"low_extra":        "Low",
		"medium_extra":     "Medium",
	}

	for _, c := range cls {
		if c.Level == "" {
			t.Errorf("class %s has empty Level", c.ID)
		}
		expectedLevel, ok := expectedClasses[c.ID]
		if !ok {
			t.Errorf("unexpected class %s", c.ID)
		} else if c.Level != expectedLevel {
			t.Errorf("class %s has level %q, expected %q", c.ID, c.Level, expectedLevel)
		}
		if len(c.Fields) == 0 {
			t.Errorf("class %s has empty Fields", c.ID)
		}
	}
}

func TestPresets(t *testing.T) {
	presets := Presets()
	if len(presets) < 14 {
		t.Fatalf("expected at least 14 presets, got %d", len(presets))
	}

	requiredPresets := []string{
		"iec104-substation",
		"scada-modbus-plc",
		"high-shell-sandbox",
		"mqtt-broker",
	}

	presetMap := make(map[string]Preset)
	for _, p := range presets {
		presetMap[p.PresetID] = p
	}

	for _, reqID := range requiredPresets {
		p, ok := presetMap[reqID]
		if !ok {
			t.Errorf("missing required preset: %s", reqID)
			continue
		}
		if p.Class == "" {
			t.Errorf("preset %s has empty class", reqID)
		}
		if p.Port <= 0 && p.Ports == "" {
			t.Errorf("preset %s has no port or ports", reqID)
		}
		if len(p.Tags) == 0 {
			t.Errorf("preset %s has no tags", reqID)
		}
		if err := ValidateParams(p.Class, decode(t, p.Params)); err != nil {
			t.Errorf("preset %s params validation failed: %v", reqID, err)
		}
	}
}
