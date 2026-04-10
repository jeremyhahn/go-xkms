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

package transport

import "time"

// TeamInfo contains summary information about a team.
type TeamInfo struct {
	Name      string    `json:"name"`
	TenantID  string    `json:"tenant_id,omitempty"`
	OwnerID   string    `json:"owner_id"`
	Members   []string  `json:"members"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateTeamRequest contains parameters for creating a new team.
type CreateTeamRequest struct {
	Name     string   `json:"name"`
	TenantID string   `json:"tenant_id,omitempty"`
	Members  []string `json:"members,omitempty"`
}

// CreateTeamResponse contains the result of team creation.
type CreateTeamResponse struct {
	Team TeamInfo `json:"team"`
}

// GetTeamResponse contains a single team's details.
type GetTeamResponse struct {
	Team TeamInfo `json:"team"`
}

// ListTeamsRequest contains pagination parameters for listing teams.
type ListTeamsRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	PageRequest
}

// ListTeamsResponse contains a list of teams with pagination metadata.
type ListTeamsResponse struct {
	Teams      []TeamInfo   `json:"teams"`
	Pagination PageResponse `json:"pagination"`
}

// UpdateTeamRequest contains parameters for updating an existing team.
type UpdateTeamRequest struct {
	Name     string   `json:"name"`
	TenantID string   `json:"tenant_id,omitempty"`
	OwnerID  string   `json:"owner_id,omitempty"`
	Members  []string `json:"members,omitempty"`
}

// UpdateTeamResponse contains the result of a team update.
type UpdateTeamResponse struct {
	Team TeamInfo `json:"team"`
}

// AddTeamMemberRequest contains parameters for adding a member to a team.
type AddTeamMemberRequest struct {
	MemberID string `json:"member_id"`
}

// RemoveTeamMemberRequest is intentionally empty as the member ID is
// specified in the URL path parameter.
type RemoveTeamMemberRequest struct{}
