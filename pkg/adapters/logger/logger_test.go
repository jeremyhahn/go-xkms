// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package logger

import (
	"errors"
	"testing"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LevelFatal, "FATAL"},
		{Level(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()

			if result != tt.expected {
				t.Errorf("Level.String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestString(t *testing.T) {
	field := String("key", "value")

	if field.Key != "key" {
		t.Errorf("Key = %v, want key", field.Key)
	}

	if field.Value != "value" {
		t.Errorf("Value = %v, want value", field.Value)
	}
}

func TestInt(t *testing.T) {
	field := Int("count", 42)

	if field.Key != "count" {
		t.Errorf("Key = %v, want count", field.Key)
	}

	if field.Value != 42 {
		t.Errorf("Value = %v, want 42", field.Value)
	}
}

func TestInt64(t *testing.T) {
	field := Int64("bignum", 9223372036854775807)

	if field.Key != "bignum" {
		t.Errorf("Key = %v, want bignum", field.Key)
	}

	if field.Value != int64(9223372036854775807) {
		t.Errorf("Value = %v, want 9223372036854775807", field.Value)
	}
}

func TestFloat64(t *testing.T) {
	field := Float64("pi", 3.14159)

	if field.Key != "pi" {
		t.Errorf("Key = %v, want pi", field.Key)
	}

	if field.Value != 3.14159 {
		t.Errorf("Value = %v, want 3.14159", field.Value)
	}
}

func TestBool(t *testing.T) {
	field := Bool("enabled", true)

	if field.Key != "enabled" {
		t.Errorf("Key = %v, want enabled", field.Key)
	}

	if field.Value != true {
		t.Errorf("Value = %v, want true", field.Value)
	}
}

func TestError(t *testing.T) {
	err := errors.New("test error")
	field := Error(err)

	if field.Key != "error" {
		t.Errorf("Key = %v, want error", field.Key)
	}

	if field.Value != err {
		t.Errorf("Value = %v, want %v", field.Value, err)
	}
}

func TestAny(t *testing.T) {
	type CustomType struct {
		Name  string
		Value int
	}

	custom := CustomType{Name: "test", Value: 123}
	field := Any("custom", custom)

	if field.Key != "custom" {
		t.Errorf("Key = %v, want custom", field.Key)
	}

	if field.Value != custom {
		t.Errorf("Value = %v, want %v", field.Value, custom)
	}
}

func TestStrings(t *testing.T) {
	values := []string{"a", "b", "c"}
	field := Strings("items", values)

	if field.Key != "items" {
		t.Errorf("Key = %v, want items", field.Key)
	}

	if slice, ok := field.Value.([]string); !ok {
		t.Errorf("Value type = %T, want []string", field.Value)
	} else {
		if len(slice) != 3 {
			t.Errorf("len(Value) = %v, want 3", len(slice))
		}
		for i, v := range values {
			if slice[i] != v {
				t.Errorf("Value[%d] = %v, want %v", i, slice[i], v)
			}
		}
	}
}

func TestInts(t *testing.T) {
	values := []int{1, 2, 3, 4, 5}
	field := Ints("numbers", values)

	if field.Key != "numbers" {
		t.Errorf("Key = %v, want numbers", field.Key)
	}

	if slice, ok := field.Value.([]int); !ok {
		t.Errorf("Value type = %T, want []int", field.Value)
	} else {
		if len(slice) != 5 {
			t.Errorf("len(Value) = %v, want 5", len(slice))
		}
		for i, v := range values {
			if slice[i] != v {
				t.Errorf("Value[%d] = %v, want %v", i, slice[i], v)
			}
		}
	}
}

func TestField_Struct(t *testing.T) {
	// Test that Field struct can be created directly
	field := Field{
		Key:   "direct",
		Value: "created",
	}

	if field.Key != "direct" {
		t.Errorf("Key = %v, want direct", field.Key)
	}

	if field.Value != "created" {
		t.Errorf("Value = %v, want created", field.Value)
	}
}
