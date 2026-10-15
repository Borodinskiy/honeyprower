package catalog

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

const maxListItems = 200

// ValidateParams checks params of a class against its schema: types, enum
// values, numeric ranges, regex and hex syntax. Keys the schema doesn't know
// are left alone, so hand-written JSON stays possible.
func ValidateParams(classID string, params map[string]any) error {
	return validateFields(Schema(classID), params, "")
}

// ValidateFields — то же по произвольной схеме (у своих ловушек она из манифеста).
func ValidateFields(fields []Field, params map[string]any) error {
	return validateFields(fields, params, "")
}

func validateFields(fields []Field, obj map[string]any, prefix string) error {
	for _, f := range fields {
		v, ok := obj[f.Key]
		if !ok || v == nil {
			continue
		}
		if err := validateValue(f, v, prefix+f.Key); err != nil {
			return err
		}
	}
	return nil
}

func validateValue(f Field, v any, path string) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%s: %s", path, fmt.Sprintf(format, a...))
	}
	switch f.Type {
	case "string", "text", "enum":
		s, ok := v.(string)
		if !ok {
			return fail("ожидается строка")
		}
		if f.Type == "enum" && !hasOption(f.Options, s) {
			return fail("недопустимое значение %q", s)
		}
		if f.Regex && s != "" {
			if _, err := regexp.Compile(s); err != nil {
				return fail("некорректное регулярное выражение: %v", err)
			}
		}
		if f.Hex && !isHex(s) {
			return fail("ожидаются байты в hex (например 0a1b2c)")
		}
	case "int", "number":
		n, ok := v.(float64)
		if !ok {
			return fail("ожидается число")
		}
		if f.Type == "int" && n != math.Trunc(n) {
			return fail("ожидается целое число")
		}
		if f.Min != nil && n < *f.Min {
			return fail("не меньше %v", *f.Min)
		}
		if f.Max != nil && n > *f.Max {
			return fail("не больше %v", *f.Max)
		}
	case "bool":
		if _, ok := v.(bool); !ok {
			return fail("ожидается true/false")
		}
	case "list":
		items, ok := v.([]any)
		if !ok {
			return fail("ожидается список")
		}
		if len(items) > maxListItems {
			return fail("не больше %d элементов", maxListItems)
		}
		for i, it := range items {
			obj, ok := it.(map[string]any)
			if !ok {
				return fmt.Errorf("%s[%d]: ожидается объект", path, i)
			}
			if err := validateFields(f.Item, obj, fmt.Sprintf("%s[%d].", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func hasOption(opts []Option, v string) bool {
	for _, o := range opts {
		if o.Value == v {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	n := 0
	for _, c := range s {
		switch {
		case c == ' ' || c == ':' || c == '\n' || c == '\t':
		case strings.ContainsRune("0123456789abcdefABCDEF", c):
			n++
		default:
			return false
		}
	}
	return n%2 == 0
}
