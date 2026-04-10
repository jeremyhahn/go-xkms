// Copyright (c) 2025 Jeremy Hahn
// Licensed under the AGPL-3.0 license with Commercial Licensing Option.
// See LICENSE file in the project root for full license information.

//go:build integration && conformance

// Package conformance provides OASIS PKCS#11 v3.0 conformance testing and reporting.
// This file implements conformance report generation in multiple formats.
package conformance

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Report Data Structures
// =============================================================================

// ConformanceReport represents a complete PKCS#11 conformance test report.
type ConformanceReport struct {
	// Header information
	Title       string    `json:"title"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Duration    string    `json:"duration"`

	// Module information
	ModuleInfo ModuleInfo `json:"module_info"`

	// Test results by category
	Categories []CategoryResult `json:"categories"`

	// Summary statistics
	Summary ReportSummary `json:"summary"`

	// Profile compliance
	Profiles []ProfileComplianceResult `json:"profiles"`
}

// ModuleInfo contains information about the tested PKCS#11 module.
type ModuleInfo struct {
	LibraryDescription   string `json:"library_description"`
	LibraryVersion       string `json:"library_version"`
	ManufacturerID       string `json:"manufacturer_id"`
	CryptokiVersion      string `json:"cryptoki_version"`
	TokenLabel           string `json:"token_label"`
	TokenModel           string `json:"token_model"`
	TokenSerialNumber    string `json:"token_serial_number"`
	TokenHardwareVersion string `json:"token_hardware_version"`
	TokenFirmwareVersion string `json:"token_firmware_version"`
	SlotCount            int    `json:"slot_count"`
	MechanismCount       int    `json:"mechanism_count"`
}

// CategoryResult holds test results for a specific category.
type CategoryResult struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Tests       []TestResult `json:"tests"`
	Passed      int          `json:"passed"`
	Failed      int          `json:"failed"`
	Skipped     int          `json:"skipped"`
	Duration    string       `json:"duration"`
}

// TestResult represents a single test result.
type TestResult struct {
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	Status        string       `json:"status"` // "passed", "failed", "skipped"
	Duration      string       `json:"duration"`
	ErrorMessage  string       `json:"error_message,omitempty"`
	SpecReference string       `json:"spec_reference,omitempty"`
	SubTests      []TestResult `json:"sub_tests,omitempty"`
	LogMessages   []string     `json:"log_messages,omitempty"`
}

// ReportSummary provides overall statistics.
type ReportSummary struct {
	TotalTests       int     `json:"total_tests"`
	PassedTests      int     `json:"passed_tests"`
	FailedTests      int     `json:"failed_tests"`
	SkippedTests     int     `json:"skipped_tests"`
	PassRate         float64 `json:"pass_rate"`
	ConformanceLevel string  `json:"conformance_level"`
}

// ProfileComplianceResult shows compliance with a specific profile.
type ProfileComplianceResult struct {
	ProfileName          string   `json:"profile_name"`
	RequiredMechanisms   int      `json:"required_mechanisms"`
	SupportedMechanisms  int      `json:"supported_mechanisms"`
	MissingMechanisms    []string `json:"missing_mechanisms,omitempty"`
	CompliancePercentage float64  `json:"compliance_percentage"`
	IsCompliant          bool     `json:"is_compliant"`
}

// =============================================================================
// Report Collector
// =============================================================================

// ReportCollector accumulates test results during test execution.
type ReportCollector struct {
	mu         sync.Mutex
	startTime  time.Time
	moduleInfo ModuleInfo
	categories map[string]*CategoryResult
	order      []string // Maintain category order
}

// NewReportCollector creates a new report collector.
func NewReportCollector() *ReportCollector {
	return &ReportCollector{
		startTime:  time.Now(),
		categories: make(map[string]*CategoryResult),
		order:      make([]string, 0),
	}
}

// SetModuleInfo sets the module information for the report.
func (rc *ReportCollector) SetModuleInfo(info ModuleInfo) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.moduleInfo = info
}

// AddCategory adds a new test category.
func (rc *ReportCollector) AddCategory(name, description string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if _, exists := rc.categories[name]; !exists {
		rc.categories[name] = &CategoryResult{
			Name:        name,
			Description: description,
			Tests:       make([]TestResult, 0),
		}
		rc.order = append(rc.order, name)
	}
}

// AddTestResult adds a test result to a category.
func (rc *ReportCollector) AddTestResult(categoryName string, result TestResult) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if category, exists := rc.categories[categoryName]; exists {
		category.Tests = append(category.Tests, result)

		switch result.Status {
		case "passed":
			category.Passed++
		case "failed":
			category.Failed++
		case "skipped":
			category.Skipped++
		}
	}
}

// GenerateReport creates a complete conformance report.
func (rc *ReportCollector) GenerateReport() *ConformanceReport {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	duration := time.Since(rc.startTime)

	report := &ConformanceReport{
		Title:       "OASIS PKCS#11 v3.0 Conformance Test Report",
		Version:     "1.0.0",
		GeneratedAt: time.Now(),
		Duration:    duration.String(),
		ModuleInfo:  rc.moduleInfo,
		Categories:  make([]CategoryResult, 0, len(rc.order)),
	}

	// Add categories in order
	totalPassed := 0
	totalFailed := 0
	totalSkipped := 0

	for _, name := range rc.order {
		if category, exists := rc.categories[name]; exists {
			report.Categories = append(report.Categories, *category)
			totalPassed += category.Passed
			totalFailed += category.Failed
			totalSkipped += category.Skipped
		}
	}

	// Calculate summary
	totalTests := totalPassed + totalFailed + totalSkipped
	passRate := 0.0
	if totalTests > 0 {
		passRate = float64(totalPassed) / float64(totalTests) * 100
	}

	report.Summary = ReportSummary{
		TotalTests:       totalTests,
		PassedTests:      totalPassed,
		FailedTests:      totalFailed,
		SkippedTests:     totalSkipped,
		PassRate:         passRate,
		ConformanceLevel: getConformanceLevel(passRate),
	}

	return report
}

// =============================================================================
// Report Generators
// =============================================================================

// WriteJSONReport writes the report in JSON format.
func WriteJSONReport(report *ConformanceReport, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// WriteJSONReportToFile writes the JSON report to a file.
func WriteJSONReportToFile(report *ConformanceReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create JSON report file: %w", err)
	}
	defer file.Close()

	return WriteJSONReport(report, file)
}

// WriteHTMLReport writes the report in HTML format.
func WriteHTMLReport(report *ConformanceReport, w io.Writer) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"statusClass": func(status string) string {
			switch status {
			case "passed":
				return "status-passed"
			case "failed":
				return "status-failed"
			case "skipped":
				return "status-skipped"
			default:
				return ""
			}
		},
		"formatPercent": func(f float64) string {
			return fmt.Sprintf("%.1f%%", f)
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	return tmpl.Execute(w, report)
}

// WriteHTMLReportToFile writes the HTML report to a file.
func WriteHTMLReportToFile(report *ConformanceReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create HTML report file: %w", err)
	}
	defer file.Close()

	return WriteHTMLReport(report, file)
}

// WriteTextReport writes a plain text summary report.
func WriteTextReport(report *ConformanceReport, w io.Writer) error {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 78) + "\n")
	sb.WriteString(fmt.Sprintf(" %s\n", report.Title))
	sb.WriteString("=" + strings.Repeat("=", 78) + "\n\n")

	// Module info
	sb.WriteString("MODULE INFORMATION\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	sb.WriteString(fmt.Sprintf("Library:    %s\n", report.ModuleInfo.LibraryDescription))
	sb.WriteString(fmt.Sprintf("Version:    %s\n", report.ModuleInfo.LibraryVersion))
	sb.WriteString(fmt.Sprintf("Cryptoki:   %s\n", report.ModuleInfo.CryptokiVersion))
	sb.WriteString(fmt.Sprintf("Token:      %s\n", report.ModuleInfo.TokenLabel))
	sb.WriteString(fmt.Sprintf("Mechanisms: %d\n\n", report.ModuleInfo.MechanismCount))

	// Summary
	sb.WriteString("TEST SUMMARY\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	sb.WriteString(fmt.Sprintf("Total Tests:   %d\n", report.Summary.TotalTests))
	sb.WriteString(fmt.Sprintf("Passed:        %d\n", report.Summary.PassedTests))
	sb.WriteString(fmt.Sprintf("Failed:        %d\n", report.Summary.FailedTests))
	sb.WriteString(fmt.Sprintf("Skipped:       %d\n", report.Summary.SkippedTests))
	sb.WriteString(fmt.Sprintf("Pass Rate:     %.1f%%\n", report.Summary.PassRate))
	sb.WriteString(fmt.Sprintf("Conformance:   %s\n\n", report.Summary.ConformanceLevel))

	// Categories
	sb.WriteString("RESULTS BY CATEGORY\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")

	for _, category := range report.Categories {
		sb.WriteString(fmt.Sprintf("\n%s\n", category.Name))
		sb.WriteString(fmt.Sprintf("  Passed: %d, Failed: %d, Skipped: %d\n",
			category.Passed, category.Failed, category.Skipped))

		// List failed tests
		for _, test := range category.Tests {
			if test.Status == "failed" {
				sb.WriteString(fmt.Sprintf("  [FAIL] %s\n", test.Name))
				if test.ErrorMessage != "" {
					sb.WriteString(fmt.Sprintf("         %s\n", test.ErrorMessage))
				}
			}
		}
	}

	// Profile compliance
	if len(report.Profiles) > 0 {
		sb.WriteString("\nPROFILE COMPLIANCE\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")

		for _, profile := range report.Profiles {
			status := "NOT COMPLIANT"
			if profile.IsCompliant {
				status = "COMPLIANT"
			}
			sb.WriteString(fmt.Sprintf("%-25s: %.1f%% (%s)\n",
				profile.ProfileName, profile.CompliancePercentage, status))
		}
	}

	sb.WriteString("\n" + strings.Repeat("=", 79) + "\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Duration:  %s\n", report.Duration))

	_, err := w.Write([]byte(sb.String()))
	return err
}

// WriteTextReportToFile writes the text report to a file.
func WriteTextReportToFile(report *ConformanceReport, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create text report file: %w", err)
	}
	defer file.Close()

	return WriteTextReport(report, file)
}

// =============================================================================
// JUnit XML Report for CI/CD Integration
// =============================================================================

// JUnitTestSuites represents the root element of JUnit XML.
type JUnitTestSuites struct {
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Errors     int              `xml:"errors,attr"`
	Skipped    int              `xml:"skipped,attr"`
	Time       float64          `xml:"time,attr"`
	TestSuites []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite represents a test suite in JUnit XML.
type JUnitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      float64         `xml:"time,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents a test case in JUnit XML.
type JUnitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Skipped   *JUnitSkipped `xml:"skipped,omitempty"`
}

// JUnitFailure represents a test failure.
type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// JUnitSkipped represents a skipped test.
type JUnitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}

// ConvertToJUnit converts a conformance report to JUnit format.
func ConvertToJUnit(report *ConformanceReport) *JUnitTestSuites {
	suites := &JUnitTestSuites{
		Name:       "PKCS11 Conformance",
		Tests:      report.Summary.TotalTests,
		Failures:   report.Summary.FailedTests,
		Skipped:    report.Summary.SkippedTests,
		TestSuites: make([]JUnitTestSuite, 0, len(report.Categories)),
	}

	for _, category := range report.Categories {
		suite := JUnitTestSuite{
			Name:      category.Name,
			Tests:     len(category.Tests),
			Failures:  category.Failed,
			Skipped:   category.Skipped,
			TestCases: make([]JUnitTestCase, 0, len(category.Tests)),
		}

		for _, test := range category.Tests {
			tc := JUnitTestCase{
				Name:      test.Name,
				ClassName: category.Name,
			}

			switch test.Status {
			case "failed":
				tc.Failure = &JUnitFailure{
					Message: test.ErrorMessage,
					Type:    "AssertionError",
					Content: test.ErrorMessage,
				}
			case "skipped":
				tc.Skipped = &JUnitSkipped{
					Message: test.ErrorMessage,
				}
			}

			suite.TestCases = append(suite.TestCases, tc)
		}

		suites.TestSuites = append(suites.TestSuites, suite)
	}

	return suites
}

// =============================================================================
// Conformance Level Determination
// =============================================================================

// ConformanceLevel represents the level of PKCS#11 conformance.
type ConformanceLevel string

const (
	ConformanceFull    ConformanceLevel = "Full Conformance"
	ConformanceHigh    ConformanceLevel = "High Conformance"
	ConformancePartial ConformanceLevel = "Partial Conformance"
	ConformanceLow     ConformanceLevel = "Low Conformance"
	ConformanceNone    ConformanceLevel = "Non-Conformant"
)

func getConformanceLevel(passRate float64) string {
	switch {
	case passRate >= 100:
		return string(ConformanceFull)
	case passRate >= 95:
		return string(ConformanceHigh)
	case passRate >= 80:
		return string(ConformancePartial)
	case passRate >= 50:
		return string(ConformanceLow)
	default:
		return string(ConformanceNone)
	}
}

// =============================================================================
// Mechanism Coverage Analysis
// =============================================================================

// MechanismCoverage tracks which mechanisms have been tested.
type MechanismCoverage struct {
	mu      sync.Mutex
	tested  map[uint64]bool
	results map[uint64]string // "passed", "failed", "skipped"
}

// NewMechanismCoverage creates a new mechanism coverage tracker.
func NewMechanismCoverage() *MechanismCoverage {
	return &MechanismCoverage{
		tested:  make(map[uint64]bool),
		results: make(map[uint64]string),
	}
}

// MarkTested marks a mechanism as tested with the given result.
func (mc *MechanismCoverage) MarkTested(mechanism uint64, result string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.tested[mechanism] = true
	mc.results[mechanism] = result
}

// GetCoverage returns the coverage statistics.
func (mc *MechanismCoverage) GetCoverage(totalMechanisms []uint64) (tested, passed, failed int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	for _, mech := range totalMechanisms {
		if mc.tested[mech] {
			tested++
			if mc.results[mech] == "passed" {
				passed++
			} else if mc.results[mech] == "failed" {
				failed++
			}
		}
	}
	return
}

// GetUntestedMechanisms returns mechanisms that haven't been tested.
func (mc *MechanismCoverage) GetUntestedMechanisms(allMechanisms []uint64) []uint64 {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	untested := make([]uint64, 0)
	for _, mech := range allMechanisms {
		if !mc.tested[mech] {
			untested = append(untested, mech)
		}
	}
	sort.Slice(untested, func(i, j int) bool {
		return untested[i] < untested[j]
	})
	return untested
}

// =============================================================================
// HTML Template
// =============================================================================

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        :root {
            --color-passed: #28a745;
            --color-failed: #dc3545;
            --color-skipped: #ffc107;
            --color-bg: #f8f9fa;
            --color-border: #dee2e6;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #212529;
            background-color: var(--color-bg);
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
        }

        header h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }

        header .meta {
            opacity: 0.9;
            font-size: 0.9em;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid var(--color-border);
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            line-height: 1;
        }

        .stat-card .label {
            color: #6c757d;
            margin-top: 5px;
        }

        .stat-card.passed .value { color: var(--color-passed); }
        .stat-card.failed .value { color: var(--color-failed); }
        .stat-card.skipped .value { color: var(--color-skipped); }

        .module-info {
            padding: 30px;
            border-bottom: 1px solid var(--color-border);
        }

        .module-info h2 {
            margin-bottom: 15px;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 10px;
        }

        .info-item {
            display: flex;
        }

        .info-item .label {
            font-weight: 600;
            width: 150px;
            flex-shrink: 0;
        }

        .categories {
            padding: 30px;
        }

        .categories h2 {
            margin-bottom: 20px;
        }

        .category {
            margin-bottom: 30px;
            border: 1px solid var(--color-border);
            border-radius: 8px;
            overflow: hidden;
        }

        .category-header {
            background: #f8f9fa;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }

        .category-header h3 {
            font-size: 1.1em;
        }

        .category-stats {
            display: flex;
            gap: 15px;
        }

        .category-stats span {
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .category-stats .passed { background: #d4edda; color: #155724; }
        .category-stats .failed { background: #f8d7da; color: #721c24; }
        .category-stats .skipped { background: #fff3cd; color: #856404; }

        .test-list {
            border-top: 1px solid var(--color-border);
        }

        .test-item {
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #eee;
        }

        .test-item:last-child {
            border-bottom: none;
        }

        .test-name {
            flex: 1;
        }

        .status-badge {
            padding: 3px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-passed { background: #d4edda; color: #155724; }
        .status-failed { background: #f8d7da; color: #721c24; }
        .status-skipped { background: #fff3cd; color: #856404; }

        .profiles {
            padding: 30px;
            background: #f8f9fa;
        }

        .profiles h2 {
            margin-bottom: 20px;
        }

        .profile-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }

        .profile-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .progress-bar {
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: var(--color-passed);
            transition: width 0.3s ease;
        }

        footer {
            padding: 20px 30px;
            background: #f8f9fa;
            border-top: 1px solid var(--color-border);
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{.Title}}</h1>
            <div class="meta">
                Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05"}} | Duration: {{.Duration}}
            </div>
        </header>

        <div class="summary">
            <div class="stat-card">
                <div class="value">{{.Summary.TotalTests}}</div>
                <div class="label">Total Tests</div>
            </div>
            <div class="stat-card passed">
                <div class="value">{{.Summary.PassedTests}}</div>
                <div class="label">Passed</div>
            </div>
            <div class="stat-card failed">
                <div class="value">{{.Summary.FailedTests}}</div>
                <div class="label">Failed</div>
            </div>
            <div class="stat-card skipped">
                <div class="value">{{.Summary.SkippedTests}}</div>
                <div class="label">Skipped</div>
            </div>
            <div class="stat-card">
                <div class="value">{{formatPercent .Summary.PassRate}}</div>
                <div class="label">Pass Rate</div>
            </div>
            <div class="stat-card">
                <div class="value" style="font-size: 1.2em;">{{.Summary.ConformanceLevel}}</div>
                <div class="label">Conformance</div>
            </div>
        </div>

        <div class="module-info">
            <h2>Module Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="label">Library:</span>
                    <span>{{.ModuleInfo.LibraryDescription}}</span>
                </div>
                <div class="info-item">
                    <span class="label">Version:</span>
                    <span>{{.ModuleInfo.LibraryVersion}}</span>
                </div>
                <div class="info-item">
                    <span class="label">Cryptoki:</span>
                    <span>{{.ModuleInfo.CryptokiVersion}}</span>
                </div>
                <div class="info-item">
                    <span class="label">Token:</span>
                    <span>{{.ModuleInfo.TokenLabel}}</span>
                </div>
                <div class="info-item">
                    <span class="label">Model:</span>
                    <span>{{.ModuleInfo.TokenModel}}</span>
                </div>
                <div class="info-item">
                    <span class="label">Mechanisms:</span>
                    <span>{{.ModuleInfo.MechanismCount}}</span>
                </div>
            </div>
        </div>

        <div class="categories">
            <h2>Test Results by Category</h2>
            {{range .Categories}}
            <div class="category">
                <div class="category-header">
                    <h3>{{.Name}}</h3>
                    <div class="category-stats">
                        <span class="passed">{{.Passed}} passed</span>
                        {{if gt .Failed 0}}<span class="failed">{{.Failed}} failed</span>{{end}}
                        {{if gt .Skipped 0}}<span class="skipped">{{.Skipped}} skipped</span>{{end}}
                    </div>
                </div>
                <div class="test-list">
                    {{range .Tests}}
                    <div class="test-item">
                        <span class="test-name">{{.Name}}</span>
                        <span class="status-badge {{statusClass .Status}}">{{.Status}}</span>
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>

        {{if .Profiles}}
        <div class="profiles">
            <h2>Profile Compliance</h2>
            {{range .Profiles}}
            <div class="profile-card">
                <div class="profile-header">
                    <h3>{{.ProfileName}}</h3>
                    <span>{{formatPercent .CompliancePercentage}} ({{.SupportedMechanisms}}/{{.RequiredMechanisms}})</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {{.CompliancePercentage}}%;"></div>
                </div>
                {{if .MissingMechanisms}}
                <div style="margin-top: 10px; font-size: 0.9em; color: #6c757d;">
                    Missing: {{range $i, $m := .MissingMechanisms}}{{if $i}}, {{end}}{{$m}}{{end}}
                </div>
                {{end}}
            </div>
            {{end}}
        </div>
        {{end}}

        <footer>
            OASIS PKCS#11 v3.0 Conformance Test Report | Version {{.Version}}
        </footer>
    </div>
</body>
</html>`
