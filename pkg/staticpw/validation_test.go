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

package staticpw

import (
	"strings"
	"testing"
)

func TestValidateFolderPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name:    "empty path is valid (root)",
			path:    "",
			wantErr: nil,
		},
		{
			name:    "single folder",
			path:    "Work",
			wantErr: nil,
		},
		{
			name:    "nested folder",
			path:    "Work/Email",
			wantErr: nil,
		},
		{
			name:    "deeply nested folder",
			path:    "Work/Email/Projects/2025",
			wantErr: nil,
		},
		{
			name:    "folder with hyphen",
			path:    "my-folder",
			wantErr: nil,
		},
		{
			name:    "folder with underscore",
			path:    "my_folder",
			wantErr: nil,
		},
		{
			name:    "folder with space",
			path:    "My Folder",
			wantErr: nil,
		},
		{
			name:    "folder with numbers",
			path:    "Project2025",
			wantErr: nil,
		},
		{
			name:    "leading slash invalid",
			path:    "/Work",
			wantErr: ErrInvalidFolderPath,
		},
		{
			name:    "trailing slash invalid",
			path:    "Work/",
			wantErr: ErrInvalidFolderPath,
		},
		{
			name:    "double slash invalid",
			path:    "Work//Email",
			wantErr: ErrInvalidFolderPath,
		},
		{
			name:    "empty segment invalid",
			path:    "Work//",
			wantErr: ErrInvalidFolderPath,
		},
		{
			name:    "special characters invalid",
			path:    "Work@Email",
			wantErr: ErrInvalidFolderPath,
		},
		{
			name:    "single character folder",
			path:    "A",
			wantErr: nil,
		},
		{
			name:    "too deep",
			path:    "a/b/c/d/e/f/g/h/i/j/k",
			wantErr: ErrFolderPathTooDeep,
		},
		{
			name:    "max depth is valid",
			path:    "a/b/c/d/e/f/g/h/i/j",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFolderPath(tt.path)
			if err != tt.wantErr {
				t.Errorf("ValidateFolderPath(%q) = %v, want %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFolderPath_LongSegment(t *testing.T) {
	longName := strings.Repeat("a", MaxFolderNameLength+1)
	err := ValidateFolderPath(longName)
	if err != ErrInvalidFolderPath {
		t.Errorf("ValidateFolderPath(long segment) = %v, want ErrInvalidFolderPath", err)
	}

	validLongName := strings.Repeat("a", MaxFolderNameLength)
	err = ValidateFolderPath(validLongName)
	if err != nil {
		t.Errorf("ValidateFolderPath(max length segment) = %v, want nil", err)
	}
}

func TestNormalizeFolderPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty path",
			input: "",
			want:  "",
		},
		{
			name:  "simple path",
			input: "Work",
			want:  "Work",
		},
		{
			name:  "nested path",
			input: "Work/Email",
			want:  "Work/Email",
		},
		{
			name:  "whitespace in segments",
			input: " Work / Email ",
			want:  "Work/Email",
		},
		{
			name:  "double slashes",
			input: "Work//Email",
			want:  "Work/Email",
		},
		{
			name:  "leading trailing slashes",
			input: "/Work/Email/",
			want:  "Work/Email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeFolderPath(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeFolderPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsSubfolder(t *testing.T) {
	tests := []struct {
		name       string
		parentPath string
		childPath  string
		want       bool
	}{
		{
			name:       "direct child",
			parentPath: "Work",
			childPath:  "Work/Email",
			want:       true,
		},
		{
			name:       "nested child",
			parentPath: "Work",
			childPath:  "Work/Email/Projects",
			want:       true,
		},
		{
			name:       "same path is not subfolder",
			parentPath: "Work",
			childPath:  "Work",
			want:       false,
		},
		{
			name:       "different path",
			parentPath: "Work",
			childPath:  "Personal",
			want:       false,
		},
		{
			name:       "similar prefix but not subfolder",
			parentPath: "Work",
			childPath:  "Work2",
			want:       false,
		},
		{
			name:       "root parent",
			parentPath: "",
			childPath:  "Work",
			want:       true,
		},
		{
			name:       "root parent nested",
			parentPath: "",
			childPath:  "Work/Email",
			want:       true,
		},
		{
			name:       "root to root is not subfolder",
			parentPath: "",
			childPath:  "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSubfolder(tt.parentPath, tt.childPath)
			if got != tt.want {
				t.Errorf("IsSubfolder(%q, %q) = %v, want %v", tt.parentPath, tt.childPath, got, tt.want)
			}
		})
	}
}

func TestIsDirectChild(t *testing.T) {
	tests := []struct {
		name       string
		parentPath string
		childPath  string
		want       bool
	}{
		{
			name:       "direct child",
			parentPath: "Work",
			childPath:  "Work/Email",
			want:       true,
		},
		{
			name:       "nested child is not direct",
			parentPath: "Work",
			childPath:  "Work/Email/Projects",
			want:       false,
		},
		{
			name:       "same path",
			parentPath: "Work",
			childPath:  "Work",
			want:       false,
		},
		{
			name:       "root direct child",
			parentPath: "",
			childPath:  "Work",
			want:       true,
		},
		{
			name:       "root nested child is not direct",
			parentPath: "",
			childPath:  "Work/Email",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDirectChild(tt.parentPath, tt.childPath)
			if got != tt.want {
				t.Errorf("IsDirectChild(%q, %q) = %v, want %v", tt.parentPath, tt.childPath, got, tt.want)
			}
		})
	}
}

func TestGetParentFolder(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "empty path",
			path: "",
			want: "",
		},
		{
			name: "root level",
			path: "Work",
			want: "",
		},
		{
			name: "one level deep",
			path: "Work/Email",
			want: "Work",
		},
		{
			name: "two levels deep",
			path: "Work/Email/Projects",
			want: "Work/Email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetParentFolder(tt.path)
			if got != tt.want {
				t.Errorf("GetParentFolder(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestGetFolderName(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "empty path",
			path: "",
			want: "",
		},
		{
			name: "root level",
			path: "Work",
			want: "Work",
		},
		{
			name: "nested",
			path: "Work/Email",
			want: "Email",
		},
		{
			name: "deeply nested",
			path: "Work/Email/Projects/2025",
			want: "2025",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetFolderName(tt.path)
			if got != tt.want {
				t.Errorf("GetFolderName(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
