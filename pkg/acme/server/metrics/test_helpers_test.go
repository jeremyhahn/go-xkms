// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// getCounterValue retrieves the value of a counter with labels for testing
func getCounterValue(t *testing.T, counter *prometheus.CounterVec, labels ...string) float64 {
	metric := &dto.Metric{}
	c, err := counter.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	err = c.Write(metric)
	require.NoError(t, err)
	return metric.Counter.GetValue()
}

// getCounterValueSingle retrieves the value of a counter with a single label for testing
func getCounterValueSingle(t *testing.T, counter *prometheus.CounterVec, label string) float64 {
	metric := &dto.Metric{}
	c, err := counter.GetMetricWithLabelValues(label)
	require.NoError(t, err)
	err = c.Write(metric)
	require.NoError(t, err)
	return metric.Counter.GetValue()
}

// getCounterValueSimple retrieves the value of a simple counter for testing
func getCounterValueSimple(t *testing.T, counter prometheus.Counter) float64 {
	metric := &dto.Metric{}
	err := counter.Write(metric)
	require.NoError(t, err)
	return metric.Counter.GetValue()
}

// getGaugeValue retrieves the value of a gauge for testing
func getGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	metric := &dto.Metric{}
	err := gauge.Write(metric)
	require.NoError(t, err)
	return metric.Gauge.GetValue()
}

// getHistogramCount retrieves the sample count from a histogram vec for testing
func getHistogramCount(t *testing.T, hist *prometheus.HistogramVec, labels ...string) uint64 {
	metric := &dto.Metric{}

	// Get the observer (histogram) with labels
	observer, err := hist.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)

	// Cast to the concrete histogram type that has Write method
	if h, ok := observer.(prometheus.Metric); ok {
		err = h.Write(metric)
		require.NoError(t, err)
		require.NotNil(t, metric.Histogram)
		return metric.Histogram.GetSampleCount()
	}

	t.Fatalf("unexpected type: %T", observer)
	return 0
}

// getHistogramCountSimple retrieves the sample count from a simple histogram for testing
func getHistogramCountSimple(t *testing.T, hist prometheus.Histogram) uint64 {
	metric := &dto.Metric{}

	// Cast to prometheus.Metric which has the Write method
	if h, ok := hist.(prometheus.Metric); ok {
		err := h.Write(metric)
		require.NoError(t, err)
		require.NotNil(t, metric.Histogram)
		return metric.Histogram.GetSampleCount()
	}

	t.Fatalf("unexpected type: %T", hist)
	return 0
}
