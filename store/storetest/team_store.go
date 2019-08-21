// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package storetest

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost-server/model"
	"github.com/mattermost/mattermost-server/store"
)

func TestTeamStore(t *testing.T, ss store.Store) {
	createDefaultRoles(t, ss)

	t.Run("Save", func(t *testing.T) { testTeamStoreSave(t, ss) })
	t.Run("Update", func(t *testing.T) { testTeamStoreUpdate(t, ss) })
	t.Run("Get", func(t *testing.T) { testTeamStoreGet(t, ss) })
	t.Run("GetByName", func(t *testing.T) { testTeamStoreGetByName(t, ss) })
	t.Run("SearchAll", func(t *testing.T) { testTeamStoreSearchAll(t, ss) })
	t.Run("SearchOpen", func(t *testing.T) { testTeamStoreSearchOpen(t, ss) })
	t.Run("SearchPrivate", func(t *testing.T) { testTeamStoreSearchPrivate(t, ss) })
	t.Run("GetByInviteId", func(t *testing.T) { testTeamStoreGetByInviteId(t, ss) })
	t.Run("ByUserId", func(t *testing.T) { testTeamStoreByUserId(t, ss) })
	t.Run("GetAllTeamListing", func(t *testing.T) { testGetAllTeamListing(t, ss) })
	t.Run("GetAllTeamPageListing", func(t *testing.T) { testGetAllTeamPageListing(t, ss) })
	t.Run("GetAllPrivateTeamListing", func(t *testing.T) { testGetAllPrivateTeamListing(t, ss) })
	t.Run("GetAllPrivateTeamPageListing", func(t *testing.T) { testGetAllPrivateTeamPageListing(t, ss) })
	t.Run("Delete", func(t *testing.T) { testDelete(t, ss) })
	t.Run("TeamCount", func(t *testing.T) { testTeamCount(t, ss) })
	t.Run("TeamMembers", func(t *testing.T) { testTeamMembers(t, ss) })
	t.Run("SaveTeamMemberMaxMembers", func(t *testing.T) { testSaveTeamMemberMaxMembers(t, ss) })
	t.Run("GetTeamMember", func(t *testing.T) { testGetTeamMember(t, ss) })
	t.Run("GetTeamMembersByIds", func(t *testing.T) { testGetTeamMembersByIds(t, ss) })
	t.Run("MemberCount", func(t *testing.T) { testTeamStoreMemberCount(t, ss) })
	t.Run("GetChannelUnreadsForAllTeams", func(t *testing.T) { testGetChannelUnreadsForAllTeams(t, ss) })
	t.Run("GetChannelUnreadsForTeam", func(t *testing.T) { testGetChannelUnreadsForTeam(t, ss) })
	t.Run("UpdateLastTeamIconUpdate", func(t *testing.T) { testUpdateLastTeamIconUpdate(t, ss) })
	t.Run("GetTeamsByScheme", func(t *testing.T) { testGetTeamsByScheme(t, ss) })
	t.Run("MigrateTeamMembers", func(t *testing.T) { testTeamStoreMigrateTeamMembers(t, ss) })
	t.Run("ResetAllTeamSchemes", func(t *testing.T) { testResetAllTeamSchemes(t, ss) })
	t.Run("ClearAllCustomRoleAssignments", func(t *testing.T) { testTeamStoreClearAllCustomRoleAssignments(t, ss) })
	t.Run("AnalyticsGetTeamCountForScheme", func(t *testing.T) { testTeamStoreAnalyticsGetTeamCountForScheme(t, ss) })
	t.Run("GetAllForExportAfter", func(t *testing.T) { testTeamStoreGetAllForExportAfter(t, ss) })
	t.Run("GetTeamMembersForExport", func(t *testing.T) { testTeamStoreGetTeamMembersForExport(t, ss) })
	t.Run("GetTeamsForUserWithPagination", func(t *testing.T) { testTeamMembersWithPagination(t, ss) })
}

func testTeamStoreSave(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN

	if _, err := ss.Team().Save(&o1); err != nil {
		t.Fatal("couldn't save item", err)
	}

	if _, err := ss.Team().Save(&o1); err == nil {
		t.Fatal("shouldn't be able to update from save")
	}

	o1.Id = ""
	if _, err := ss.Team().Save(&o1); err == nil {
		t.Fatal("should be unique domain")
	}
}

func testTeamStoreUpdate(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	if _, err := ss.Team().Save(&o1); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	if _, err := ss.Team().Update(&o1); err != nil {
		t.Fatal(err)
	}

	o1.Id = "missing"
	if _, err := ss.Team().Update(&o1); err == nil {
		t.Fatal("Update should have failed because of missing key")
	}

	o1.Id = model.NewId()
	if _, err := ss.Team().Update(&o1); err == nil {
		t.Fatal("Update should have faile because id change")
	}
}

func testTeamStoreGet(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	_, err := ss.Team().Save(&o1)
	require.Nil(t, err)

	r1, err := ss.Team().Get(o1.Id)
	require.Nil(t, err)
	require.Equal(t, r1.ToJson(), o1.ToJson())

	_, err = ss.Team().Get("")
	require.NotNil(t, err, "Missing id should have failed")
}

func testTeamStoreGetByName(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN

	if _, err := ss.Team().Save(&o1); err != nil {
		t.Fatal(err)
	}

	if team, err := ss.Team().GetByName(o1.Name); err != nil {
		t.Fatal(err)
	} else {
		if team.ToJson() != o1.ToJson() {
			t.Fatal("invalid returned team")
		}
	}

	if _, err := ss.Team().GetByName(""); err == nil {
		t.Fatal("Missing id should have failed")
	}
}

func testTeamStoreSearchAll(t *testing.T, ss store.Store) {
	o := model.Team{}
	o.DisplayName = "ADisplayName" + model.NewId()
	o.Name = "zzzzzz-" + model.NewId() + "a"
	o.Email = MakeEmail()
	o.Type = model.TEAM_OPEN
	o.AllowOpenInvite = true

	_, err := ss.Team().Save(&o)
	require.Nil(t, err)

	p := model.Team{}
	p.DisplayName = "ADisplayName" + model.NewId()
	p.Name = "zzzzzz-" + model.NewId() + "a"
	p.Email = MakeEmail()
	p.Type = model.TEAM_OPEN
	p.AllowOpenInvite = false

	_, err = ss.Team().Save(&p)
	require.Nil(t, err)

	testCases := []struct {
		Name            string
		Term            string
		ExpectedLenth   int
		ExpectedFirstId string
	}{
		{
			"Search for open team name",
			o.Name,
			1,
			o.Id,
		},
		{
			"Search for open team displayName",
			o.DisplayName,
			1,
			o.Id,
		},
		{
			"Search for open team without results",
			"junk",
			0,
			"",
		},
		{
			"Search for private team",
			p.DisplayName,
			1,
			p.Id,
		},
		{
			"Search for both teams",
			"zzzzzz",
			2,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			r1, err := ss.Team().SearchAll(tc.Term)
			require.Nil(t, err)
			require.Equal(t, tc.ExpectedLenth, len(r1))
			if tc.ExpectedFirstId != "" {
				assert.Equal(t, tc.ExpectedFirstId, r1[0].Id)
			}
		})
	}
}

func testTeamStoreSearchOpen(t *testing.T, ss store.Store) {
	o := model.Team{}
	o.DisplayName = "ADisplayName" + model.NewId()
	o.Name = "zz" + model.NewId() + "a"
	o.Email = MakeEmail()
	o.Type = model.TEAM_OPEN
	o.AllowOpenInvite = true

	_, err := ss.Team().Save(&o)
	require.Nil(t, err)

	p := model.Team{}
	p.DisplayName = "ADisplayName" + model.NewId()
	p.Name = "zz" + model.NewId() + "a"
	p.Email = MakeEmail()
	p.Type = model.TEAM_OPEN
	p.AllowOpenInvite = false

	_, err = ss.Team().Save(&p)
	require.Nil(t, err)

	testCases := []struct {
		Name            string
		Term            string
		ExpectedLength  int
		ExpectedFirstId string
	}{
		{
			"Search for open team name",
			o.Name,
			1,
			o.Id,
		},
		{
			"Search for open team displayName",
			o.DisplayName,
			1,
			o.Id,
		},
		{
			"Search for open team without results",
			"junk",
			0,
			"",
		},
		{
			"Search for a private team (expected no results)",
			p.DisplayName,
			0,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			r1, err := ss.Team().SearchOpen(tc.Term)
			require.Nil(t, err)
			results := r1
			require.Equal(t, tc.ExpectedLength, len(results))
			if tc.ExpectedFirstId != "" {
				assert.Equal(t, tc.ExpectedFirstId, results[0].Id)
			}
		})
	}
}

func testTeamStoreSearchPrivate(t *testing.T, ss store.Store) {
	o := model.Team{}
	o.DisplayName = "ADisplayName" + model.NewId()
	o.Name = "zz" + model.NewId() + "a"
	o.Email = MakeEmail()
	o.Type = model.TEAM_OPEN
	o.AllowOpenInvite = true

	_, err := ss.Team().Save(&o)
	require.Nil(t, err)

	p := model.Team{}
	p.DisplayName = "ADisplayName" + model.NewId()
	p.Name = "zz" + model.NewId() + "a"
	p.Email = MakeEmail()
	p.Type = model.TEAM_OPEN
	p.AllowOpenInvite = false

	_, err = ss.Team().Save(&p)
	require.Nil(t, err)

	testCases := []struct {
		Name            string
		Term            string
		ExpectedLength  int
		ExpectedFirstId string
	}{
		{
			"Search for private team name",
			p.Name,
			1,
			p.Id,
		},
		{
			"Search for private team displayName",
			p.DisplayName,
			1,
			p.Id,
		},
		{
			"Search for private team without results",
			"junk",
			0,
			"",
		},
		{
			"Search for a open team (expected no results)",
			o.DisplayName,
			0,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			r1, err := ss.Team().SearchPrivate(tc.Term)
			require.Nil(t, err)
			results := r1
			require.Equal(t, tc.ExpectedLength, len(results))
			if tc.ExpectedFirstId != "" {
				assert.Equal(t, tc.ExpectedFirstId, results[0].Id)
			}
		})
	}
}

func testTeamStoreGetByInviteId(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.InviteId = model.NewId()

	save1, err := ss.Team().Save(&o1)
	if err != nil {
		t.Fatal(err)
	}

	o2 := model.Team{}
	o2.DisplayName = "DisplayName"
	o2.Name = "zz" + model.NewId() + "b"
	o2.Email = MakeEmail()
	o2.Type = model.TEAM_OPEN

	if r1, err := ss.Team().GetByInviteId(save1.InviteId); err != nil {
		t.Fatal(err)
	} else {
		if r1.ToJson() != o1.ToJson() {
			t.Fatal("invalid returned team")
		}
	}

	if _, err := ss.Team().GetByInviteId(""); err == nil {
		t.Fatal("Missing id should have failed")
	}
}

func testTeamStoreByUserId(t *testing.T, ss store.Store) {
	o1 := &model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.InviteId = model.NewId()
	o1, err := ss.Team().Save(o1)
	require.Nil(t, err)

	m1 := &model.TeamMember{TeamId: o1.Id, UserId: model.NewId()}
	_, err = ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	if teams, err := ss.Team().GetTeamsByUserId(m1.UserId); err != nil {
		t.Fatal(err)
	} else {
		if len(teams) == 0 {
			t.Fatal("Should return a team")
		}

		if teams[0].Id != o1.Id {
			t.Fatal("should be a member")
		}

	}
}

func testGetAllTeamListing(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.AllowOpenInvite = true
	_, err := ss.Team().Save(&o1)
	require.Nil(t, err)

	o2 := model.Team{}
	o2.DisplayName = "DisplayName"
	o2.Name = "zz" + model.NewId() + "b"
	o2.Email = MakeEmail()
	o2.Type = model.TEAM_OPEN
	_, err = ss.Team().Save(&o2)
	require.Nil(t, err)

	o3 := model.Team{}
	o3.DisplayName = "DisplayName"
	o3.Name = "z-z-z" + model.NewId() + "b"
	o3.Email = MakeEmail()
	o3.Type = model.TEAM_INVITE
	o3.AllowOpenInvite = true
	_, err = ss.Team().Save(&o3)
	require.Nil(t, err)

	o4 := model.Team{}
	o4.DisplayName = "DisplayName"
	o4.Name = "zz" + model.NewId() + "b"
	o4.Email = MakeEmail()
	o4.Type = model.TEAM_INVITE
	_, err = ss.Team().Save(&o4)
	require.Nil(t, err)

	if teams, err := ss.Team().GetAllTeamListing(); err != nil {
		t.Fatal(err)
	} else {
		for _, team := range teams {
			if !team.AllowOpenInvite {
				t.Fatal("should have returned team with AllowOpenInvite as true")
			}
		}

		if len(teams) == 0 {
			t.Fatal("failed team listing")
		}
	}
}

func testGetAllTeamPageListing(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.AllowOpenInvite = true
	_, err := ss.Team().Save(&o1)
	require.Nil(t, err)

	o2 := model.Team{}
	o2.DisplayName = "DisplayName"
	o2.Name = "zz" + model.NewId() + "b"
	o2.Email = MakeEmail()
	o2.Type = model.TEAM_OPEN
	o2.AllowOpenInvite = false
	_, err = ss.Team().Save(&o2)
	require.Nil(t, err)

	o3 := model.Team{}
	o3.DisplayName = "DisplayName"
	o3.Name = "z-z-z" + model.NewId() + "b"
	o3.Email = MakeEmail()
	o3.Type = model.TEAM_INVITE
	o3.AllowOpenInvite = true
	_, err = ss.Team().Save(&o3)
	require.Nil(t, err)

	o4 := model.Team{}
	o4.DisplayName = "DisplayName"
	o4.Name = "zz" + model.NewId() + "b"
	o4.Email = MakeEmail()
	o4.Type = model.TEAM_INVITE
	o4.AllowOpenInvite = false
	_, err = ss.Team().Save(&o4)
	require.Nil(t, err)

	teams, err := ss.Team().GetAllTeamPageListing(0, 10)
	require.Nil(t, err)

	for _, team := range teams {
		if !team.AllowOpenInvite {
			t.Fatal("should have returned team with AllowOpenInvite as true")
		}
	}

	if len(teams) > 10 {
		t.Fatal("should have returned max of 10 teams")
	}

	o5 := model.Team{}
	o5.DisplayName = "DisplayName"
	o5.Name = "z-z-z" + model.NewId() + "b"
	o5.Email = MakeEmail()
	o5.Type = model.TEAM_OPEN
	o5.AllowOpenInvite = true
	_, err = ss.Team().Save(&o5)
	require.Nil(t, err)

	teams, err = ss.Team().GetAllTeamPageListing(0, 4)
	require.Nil(t, err)

	for _, team := range teams {
		if !team.AllowOpenInvite {
			t.Fatal("should have returned team with AllowOpenInvite as true")
		}
	}

	if len(teams) > 4 {
		t.Fatal("should have returned max of 4 teams")
	}

	teams, err = ss.Team().GetAllTeamPageListing(1, 1)
	require.Nil(t, err)

	for _, team := range teams {
		if !team.AllowOpenInvite {
			t.Fatal("should have returned team with AllowOpenInvite as true")
		}
	}

	if len(teams) > 1 {
		t.Fatal("should have returned max of 1 team")
	}
}

func testGetAllPrivateTeamListing(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.AllowOpenInvite = true
	_, err := ss.Team().Save(&o1)
	require.Nil(t, err)

	o2 := model.Team{}
	o2.DisplayName = "DisplayName"
	o2.Name = "zz" + model.NewId() + "b"
	o2.Email = MakeEmail()
	o2.Type = model.TEAM_OPEN
	_, err = ss.Team().Save(&o2)
	require.Nil(t, err)

	o3 := model.Team{}
	o3.DisplayName = "DisplayName"
	o3.Name = "z-z-z" + model.NewId() + "b"
	o3.Email = MakeEmail()
	o3.Type = model.TEAM_INVITE
	o3.AllowOpenInvite = true
	_, err = ss.Team().Save(&o3)
	require.Nil(t, err)

	o4 := model.Team{}
	o4.DisplayName = "DisplayName"
	o4.Name = "zz" + model.NewId() + "b"
	o4.Email = MakeEmail()
	o4.Type = model.TEAM_INVITE
	_, err = ss.Team().Save(&o4)
	require.Nil(t, err)

	if teams, err := ss.Team().GetAllPrivateTeamListing(); err != nil {
		t.Fatal(err)
	} else {
		for _, team := range teams {
			if team.AllowOpenInvite {
				t.Fatal("should have returned team with AllowOpenInvite as false")
			}
		}

		if len(teams) == 0 {
			t.Fatal("failed team listing")
		}
	}
}

func testGetAllPrivateTeamPageListing(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.AllowOpenInvite = true
	_, err := ss.Team().Save(&o1)
	require.Nil(t, err)

	o2 := model.Team{}
	o2.DisplayName = "DisplayName"
	o2.Name = "zz" + model.NewId() + "b"
	o2.Email = MakeEmail()
	o2.Type = model.TEAM_OPEN
	o2.AllowOpenInvite = false
	_, err = ss.Team().Save(&o2)
	require.Nil(t, err)

	o3 := model.Team{}
	o3.DisplayName = "DisplayName"
	o3.Name = "z-z-z" + model.NewId() + "b"
	o3.Email = MakeEmail()
	o3.Type = model.TEAM_INVITE
	o3.AllowOpenInvite = true
	_, err = ss.Team().Save(&o3)
	require.Nil(t, err)

	o4 := model.Team{}
	o4.DisplayName = "DisplayName"
	o4.Name = "zz" + model.NewId() + "b"
	o4.Email = MakeEmail()
	o4.Type = model.TEAM_INVITE
	o4.AllowOpenInvite = false
	_, err = ss.Team().Save(&o4)
	require.Nil(t, err)

	if teams, listErr := ss.Team().GetAllPrivateTeamPageListing(0, 10); listErr != nil {
		t.Fatal(listErr)
	} else {
		for _, team := range teams {
			if team.AllowOpenInvite {
				t.Fatal("should have returned team with AllowOpenInvite as false")
			}
		}

		if len(teams) > 10 {
			t.Fatal("should have returned max of 10 teams")
		}
	}

	o5 := model.Team{}
	o5.DisplayName = "DisplayName"
	o5.Name = "z-z-z" + model.NewId() + "b"
	o5.Email = MakeEmail()
	o5.Type = model.TEAM_OPEN
	o5.AllowOpenInvite = true
	_, err = ss.Team().Save(&o5)
	require.Nil(t, err)

	if teams, listErr := ss.Team().GetAllPrivateTeamPageListing(0, 4); listErr != nil {
		t.Fatal(listErr)
	} else {
		for _, team := range teams {
			if team.AllowOpenInvite {
				t.Fatal("should have returned team with AllowOpenInvite as false")
			}
		}

		if len(teams) > 4 {
			t.Fatal("should have returned max of 4 teams")
		}
	}

	if teams, listErr := ss.Team().GetAllPrivateTeamPageListing(1, 1); listErr != nil {
		t.Fatal(listErr)
	} else {
		for _, team := range teams {
			if team.AllowOpenInvite {
				t.Fatal("should have returned team with AllowOpenInvite as false")
			}
		}

		if len(teams) > 1 {
			t.Fatal("should have returned max of 1 team")
		}
	}
}

func testDelete(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.AllowOpenInvite = true
	_, err := ss.Team().Save(&o1)
	require.Nil(t, err)

	o2 := model.Team{}
	o2.DisplayName = "DisplayName"
	o2.Name = "zz" + model.NewId() + "b"
	o2.Email = MakeEmail()
	o2.Type = model.TEAM_OPEN
	_, err = ss.Team().Save(&o2)
	require.Nil(t, err)

	if r1 := ss.Team().PermanentDelete(o1.Id); r1 != nil {
		t.Fatal(r1)
	}
}

func testTeamCount(t *testing.T, ss store.Store) {
	o1 := model.Team{}
	o1.DisplayName = "DisplayName"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.AllowOpenInvite = true
	_, err := ss.Team().Save(&o1)
	require.Nil(t, err)

	if teamCount, err := ss.Team().AnalyticsTeamCount(); err != nil {
		t.Fatal(err)
	} else {
		if teamCount == 0 {
			t.Fatal("should be at least 1 team")
		}
	}
}

func testTeamMembers(t *testing.T, ss store.Store) {
	teamId1 := model.NewId()
	teamId2 := model.NewId()

	m1 := &model.TeamMember{TeamId: teamId1, UserId: model.NewId()}
	m2 := &model.TeamMember{TeamId: teamId1, UserId: model.NewId()}
	m3 := &model.TeamMember{TeamId: teamId2, UserId: model.NewId()}

	_, err := ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m2, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m3, -1)
	require.Nil(t, err)

	ms, err := ss.Team().GetMembers(teamId1, 0, 100, nil)
	require.Nil(t, err)
	assert.Len(t, ms, 2)

	if ms, err = ss.Team().GetMembers(teamId2, 0, 100, nil); err != nil {
		t.Fatal(err)
	} else {

		require.Len(t, ms, 1)
		require.Equal(t, m3.UserId, ms[0].UserId)
	}

	if ms, err = ss.Team().GetTeamsForUser(m1.UserId); err != nil {
		t.Fatal(err)
	} else {

		require.Len(t, ms, 1)
		require.Equal(t, m1.TeamId, ms[0].TeamId)
	}

	if err = ss.Team().RemoveMember(teamId1, m1.UserId); err != nil {
		t.Fatal(err)
	}

	if ms, err = ss.Team().GetMembers(teamId1, 0, 100, nil); err != nil {
		t.Fatal(err)
	} else {

		require.Len(t, ms, 1)
		require.Equal(t, m2.UserId, ms[0].UserId)
	}

	_, err = ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	if err = ss.Team().RemoveAllMembersByTeam(teamId1); err != nil {
		t.Fatal(err)
	}

	if ms, err = ss.Team().GetMembers(teamId1, 0, 100, nil); err != nil {
		t.Fatal(err)
	} else {

		require.Len(t, ms, 0)
	}

	uid := model.NewId()
	m4 := &model.TeamMember{TeamId: teamId1, UserId: uid}
	m5 := &model.TeamMember{TeamId: teamId2, UserId: uid}
	_, err = ss.Team().SaveMember(m4, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m5, -1)
	require.Nil(t, err)

	if ms, err = ss.Team().GetTeamsForUser(uid); err != nil {
		t.Fatal(err)
	} else {

		require.Len(t, ms, 2)
	}

	if err = ss.Team().RemoveAllMembersByUser(uid); err != nil {
		t.Fatal(err)
	}

	if ms, err = ss.Team().GetTeamsForUser(m1.UserId); err != nil {
		t.Fatal(err)
	} else {

		require.Len(t, ms, 0)
	}
}

func testTeamMembersWithPagination(t *testing.T, ss store.Store) {
	teamId1 := model.NewId()
	teamId2 := model.NewId()

	m1 := &model.TeamMember{TeamId: teamId1, UserId: model.NewId()}
	m2 := &model.TeamMember{TeamId: teamId1, UserId: model.NewId()}
	m3 := &model.TeamMember{TeamId: teamId2, UserId: model.NewId()}

	_, err := ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	_, err = ss.Team().SaveMember(m2, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m3, -1)
	require.Nil(t, err)

	ms, errTeam := ss.Team().GetTeamsForUserWithPagination(m1.UserId, 0, 1)
	require.Nil(t, errTeam)

	require.Len(t, ms, 1)
	require.Equal(t, m1.TeamId, ms[0].TeamId)

	e := ss.Team().RemoveMember(teamId1, m1.UserId)
	require.Nil(t, e)

	ms, err = ss.Team().GetMembers(teamId1, 0, 100, nil)
	require.Nil(t, err)

	require.Len(t, ms, 1)
	require.Equal(t, m2.UserId, ms[0].UserId)

	_, err = ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	err = ss.Team().RemoveAllMembersByTeam(teamId1)
	require.Nil(t, err)

	uid := model.NewId()
	m4 := &model.TeamMember{TeamId: teamId1, UserId: uid}
	m5 := &model.TeamMember{TeamId: teamId2, UserId: uid}
	_, err = ss.Team().SaveMember(m4, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m5, -1)
	require.Nil(t, err)

	result, err := ss.Team().GetTeamsForUserWithPagination(uid, 0, 1)
	require.Nil(t, err)
	require.Len(t, result, 1)

	err = ss.Team().RemoveAllMembersByUser(uid)
	require.Nil(t, err)

	result, err = ss.Team().GetTeamsForUserWithPagination(uid, 1, 1)
	require.Nil(t, err)
	require.Len(t, result, 0)
}

func testSaveTeamMemberMaxMembers(t *testing.T, ss store.Store) {
	maxUsersPerTeam := 5

	team, errSave := ss.Team().Save(&model.Team{
		DisplayName: "DisplayName",
		Name:        "z-z-z" + model.NewId() + "b",
		Type:        model.TEAM_OPEN,
	})
	require.Nil(t, errSave)
	defer func() {
		ss.Team().PermanentDelete(team.Id)
	}()

	userIds := make([]string, maxUsersPerTeam)

	for i := 0; i < maxUsersPerTeam; i++ {
		user, err := ss.User().Save(&model.User{
			Username: model.NewId(),
			Email:    MakeEmail(),
		})
		require.Nil(t, err)
		userIds[i] = user.Id

		defer func(userId string) {
			ss.User().PermanentDelete(userId)
		}(userIds[i])

		_, err = ss.Team().SaveMember(&model.TeamMember{
			TeamId: team.Id,
			UserId: userIds[i],
		}, maxUsersPerTeam)
		require.Nil(t, err)

		defer func(userId string) {
			ss.Team().RemoveMember(team.Id, userId)
		}(userIds[i])
	}

	if totalMemberCount, err := ss.Team().GetTotalMemberCount(team.Id, nil); err != nil {
		t.Fatal(err)
	} else if int(totalMemberCount) != maxUsersPerTeam {
		t.Fatalf("should start with 5 team members, had %v instead", totalMemberCount)
	}

	user, err := ss.User().Save(&model.User{
		Username: model.NewId(),
		Email:    MakeEmail(),
	})
	require.Nil(t, err)
	newUserId := user.Id
	defer func() {
		ss.User().PermanentDelete(newUserId)
	}()

	if _, err = ss.Team().SaveMember(&model.TeamMember{
		TeamId: team.Id,
		UserId: newUserId,
	}, maxUsersPerTeam); err == nil {
		t.Fatal("shouldn't be able to save member when at maximum members per team")
	}

	if totalMemberCount, teamErr := ss.Team().GetTotalMemberCount(team.Id, nil); teamErr != nil {
		t.Fatal(teamErr)
	} else if int(totalMemberCount) != maxUsersPerTeam {
		t.Fatalf("should still have 5 team members, had %v instead", totalMemberCount)
	}

	// Leaving the team from the UI sets DeleteAt instead of using TeamStore.RemoveMember
	if _, teamErr := ss.Team().UpdateMember(&model.TeamMember{
		TeamId:   team.Id,
		UserId:   userIds[0],
		DeleteAt: 1234,
	}); teamErr != nil {
		panic(teamErr)
	}

	if totalMemberCount, teamErr := ss.Team().GetTotalMemberCount(team.Id, nil); teamErr != nil {
		t.Fatal(teamErr)
	} else if int(totalMemberCount) != maxUsersPerTeam-1 {
		t.Fatalf("should now only have 4 team members, had %v instead", totalMemberCount)
	}

	if _, err = ss.Team().SaveMember(&model.TeamMember{TeamId: team.Id, UserId: newUserId}, maxUsersPerTeam); err != nil {
		t.Fatal("should've been able to save new member after deleting one", err)
	} else {
		defer func(userId string) {
			ss.Team().RemoveMember(team.Id, userId)
		}(newUserId)
	}

	if totalMemberCount, teamErr := ss.Team().GetTotalMemberCount(team.Id, nil); teamErr != nil {
		t.Fatal(teamErr)
	} else if int(totalMemberCount) != maxUsersPerTeam {
		t.Fatalf("should have 5 team members again, had %v instead", totalMemberCount)
	}

	// Deactivating a user should make them stop counting against max members
	user2, err := ss.User().Get(userIds[1])
	require.Nil(t, err)
	user2.DeleteAt = 1234
	_, err = ss.User().Update(user2, true)
	require.Nil(t, err)

	user, err = ss.User().Save(&model.User{
		Username: model.NewId(),
		Email:    MakeEmail(),
	})
	require.Nil(t, err)
	newUserId2 := user.Id
	if _, err := ss.Team().SaveMember(&model.TeamMember{TeamId: team.Id, UserId: newUserId2}, maxUsersPerTeam); err != nil {
		t.Fatal("should've been able to save new member after deleting one", err)
	} else {
		defer func(userId string) {
			ss.Team().RemoveMember(team.Id, userId)
		}(newUserId2)
	}
}

func testGetTeamMember(t *testing.T, ss store.Store) {
	teamId1 := model.NewId()

	m1 := &model.TeamMember{TeamId: teamId1, UserId: model.NewId()}
	_, err := ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	var rm1 *model.TeamMember
	if rm1, err = ss.Team().GetMember(m1.TeamId, m1.UserId); err != nil {
		t.Fatal(err)
	} else {

		if rm1.TeamId != m1.TeamId {
			t.Fatal("bad team id")
		}

		if rm1.UserId != m1.UserId {
			t.Fatal("bad user id")
		}
	}

	if _, err = ss.Team().GetMember(m1.TeamId, ""); err == nil {
		t.Fatal("empty user id - should have failed")
	}

	if _, err = ss.Team().GetMember("", m1.UserId); err == nil {
		t.Fatal("empty team id - should have failed")
	}

	// Test with a custom team scheme.
	s2 := &model.Scheme{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Description: model.NewId(),
		Scope:       model.SCHEME_SCOPE_TEAM,
	}
	s2, err = ss.Scheme().Save(s2)
	require.Nil(t, err)
	t.Log(s2)

	t2, err := ss.Team().Save(&model.Team{
		DisplayName: "DisplayName",
		Name:        "z-z-z" + model.NewId() + "b",
		Type:        model.TEAM_OPEN,
		SchemeId:    &s2.Id,
	})
	require.Nil(t, err)

	defer func() {
		ss.Team().PermanentDelete(t2.Id)
	}()

	m2 := &model.TeamMember{TeamId: t2.Id, UserId: model.NewId(), SchemeUser: true}
	_, err = ss.Team().SaveMember(m2, -1)
	require.Nil(t, err)

	m3, err := ss.Team().GetMember(m2.TeamId, m2.UserId)
	require.Nil(t, err)
	t.Log(m3)

	assert.Equal(t, s2.DefaultTeamUserRole, m3.Roles)

	m4 := &model.TeamMember{TeamId: t2.Id, UserId: model.NewId(), SchemeGuest: true}
	_, err = ss.Team().SaveMember(m4, -1)
	require.Nil(t, err)

	m5, err := ss.Team().GetMember(m4.TeamId, m4.UserId)
	require.Nil(t, err)

	assert.Equal(t, s2.DefaultTeamGuestRole, m5.Roles)
}

func testGetTeamMembersByIds(t *testing.T, ss store.Store) {
	teamId1 := model.NewId()

	m1 := &model.TeamMember{TeamId: teamId1, UserId: model.NewId()}
	_, err := ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	var r []*model.TeamMember
	if r, err = ss.Team().GetMembersByIds(m1.TeamId, []string{m1.UserId}, nil); err != nil {
		t.Fatal(err)
	} else {
		rm1 := r[0]

		if rm1.TeamId != m1.TeamId {
			t.Fatal("bad team id")
		}

		if rm1.UserId != m1.UserId {
			t.Fatal("bad user id")
		}
	}

	m2 := &model.TeamMember{TeamId: teamId1, UserId: model.NewId()}
	_, err = ss.Team().SaveMember(m2, -1)
	require.Nil(t, err)

	if rm, err := ss.Team().GetMembersByIds(m1.TeamId, []string{m1.UserId, m2.UserId, model.NewId()}, nil); err != nil {
		t.Fatal(err)
	} else {

		if len(rm) != 2 {
			t.Fatal("return wrong number of results")
		}
	}

	if _, err := ss.Team().GetMembersByIds(m1.TeamId, []string{}, nil); err == nil {
		t.Fatal("empty user ids - should have failed")
	}
}

func testTeamStoreMemberCount(t *testing.T, ss store.Store) {
	u1 := &model.User{}
	u1.Email = MakeEmail()
	_, err := ss.User().Save(u1)
	require.Nil(t, err)

	u2 := &model.User{}
	u2.Email = MakeEmail()
	u2.DeleteAt = 1
	_, err = ss.User().Save(u2)
	require.Nil(t, err)

	teamId1 := model.NewId()
	m1 := &model.TeamMember{TeamId: teamId1, UserId: u1.Id}
	_, err = ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	m2 := &model.TeamMember{TeamId: teamId1, UserId: u2.Id}
	_, err = ss.Team().SaveMember(m2, -1)
	require.Nil(t, err)

	var totalMemberCount int64
	if totalMemberCount, err = ss.Team().GetTotalMemberCount(teamId1, nil); err != nil {
		t.Fatal(err)
	} else {
		if totalMemberCount != 2 {
			t.Fatal("wrong count")
		}
	}

	var result int64
	if result, err = ss.Team().GetActiveMemberCount(teamId1, nil); err != nil {
		t.Fatal(err)
	} else {
		if result != 1 {
			t.Fatal("wrong count")
		}
	}

	m3 := &model.TeamMember{TeamId: teamId1, UserId: model.NewId()}
	_, err = ss.Team().SaveMember(m3, -1)
	require.Nil(t, err)

	if totalMemberCount, err := ss.Team().GetTotalMemberCount(teamId1, nil); err != nil {
		t.Fatal(err)
	} else {
		if totalMemberCount != 2 {
			t.Fatal("wrong count")
		}
	}

	if result, err := ss.Team().GetActiveMemberCount(teamId1, nil); err != nil {
		t.Fatal(err)
	} else {
		if result != 1 {
			t.Fatal("wrong count")
		}
	}
}

func testGetChannelUnreadsForAllTeams(t *testing.T, ss store.Store) {
	teamId1 := model.NewId()
	teamId2 := model.NewId()

	uid := model.NewId()
	m1 := &model.TeamMember{TeamId: teamId1, UserId: uid}
	m2 := &model.TeamMember{TeamId: teamId2, UserId: uid}
	_, err := ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m2, -1)
	require.Nil(t, err)

	c1 := &model.Channel{TeamId: m1.TeamId, Name: model.NewId(), DisplayName: "Town Square", Type: model.CHANNEL_OPEN, TotalMsgCount: 100}
	_, err = ss.Channel().Save(c1, -1)
	require.Nil(t, err)

	c2 := &model.Channel{TeamId: m2.TeamId, Name: model.NewId(), DisplayName: "Town Square", Type: model.CHANNEL_OPEN, TotalMsgCount: 100}
	_, err = ss.Channel().Save(c2, -1)
	require.Nil(t, err)

	cm1 := &model.ChannelMember{ChannelId: c1.Id, UserId: m1.UserId, NotifyProps: model.GetDefaultChannelNotifyProps(), MsgCount: 90}
	_, err = ss.Channel().SaveMember(cm1)
	require.Nil(t, err)
	cm2 := &model.ChannelMember{ChannelId: c2.Id, UserId: m2.UserId, NotifyProps: model.GetDefaultChannelNotifyProps(), MsgCount: 90}
	_, err = ss.Channel().SaveMember(cm2)
	require.Nil(t, err)

	if ms1, err := ss.Team().GetChannelUnreadsForAllTeams("", uid); err != nil {
		t.Fatal(err)
	} else {
		membersMap := make(map[string]bool)
		for i := range ms1 {
			id := ms1[i].TeamId
			if _, ok := membersMap[id]; !ok {
				membersMap[id] = true
			}
		}
		if len(membersMap) != 2 {
			t.Fatal("Should be the unreads for all the teams")
		}

		if ms1[0].MsgCount != 10 {
			t.Fatal("subtraction failed")
		}
	}

	if ms2, err := ss.Team().GetChannelUnreadsForAllTeams(teamId1, uid); err != nil {
		t.Fatal(err)
	} else {
		membersMap := make(map[string]bool)
		for i := range ms2 {
			id := ms2[i].TeamId
			if _, ok := membersMap[id]; !ok {
				membersMap[id] = true
			}
		}

		if len(membersMap) != 1 {
			t.Fatal("Should be the unreads for just one team")
		}

		if ms2[0].MsgCount != 10 {
			t.Fatal("subtraction failed")
		}
	}

	if err := ss.Team().RemoveAllMembersByUser(uid); err != nil {
		t.Fatal(err)
	}
}

func testGetChannelUnreadsForTeam(t *testing.T, ss store.Store) {
	teamId1 := model.NewId()

	uid := model.NewId()
	m1 := &model.TeamMember{TeamId: teamId1, UserId: uid}
	_, err := ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	c1 := &model.Channel{TeamId: m1.TeamId, Name: model.NewId(), DisplayName: "Town Square", Type: model.CHANNEL_OPEN, TotalMsgCount: 100}
	_, err = ss.Channel().Save(c1, -1)
	require.Nil(t, err)

	c2 := &model.Channel{TeamId: m1.TeamId, Name: model.NewId(), DisplayName: "Town Square", Type: model.CHANNEL_OPEN, TotalMsgCount: 100}
	_, err = ss.Channel().Save(c2, -1)
	require.Nil(t, err)

	cm1 := &model.ChannelMember{ChannelId: c1.Id, UserId: m1.UserId, NotifyProps: model.GetDefaultChannelNotifyProps(), MsgCount: 90}
	_, err = ss.Channel().SaveMember(cm1)
	require.Nil(t, err)
	cm2 := &model.ChannelMember{ChannelId: c2.Id, UserId: m1.UserId, NotifyProps: model.GetDefaultChannelNotifyProps(), MsgCount: 90}
	_, err = ss.Channel().SaveMember(cm2)
	require.Nil(t, err)

	if ms, err := ss.Team().GetChannelUnreadsForTeam(m1.TeamId, m1.UserId); err != nil {
		t.Fatal(err)
	} else {
		if len(ms) != 2 {
			t.Fatal("wrong length")
		}

		if ms[0].MsgCount != 10 {
			t.Fatal("subtraction failed")
		}
	}
}

func testUpdateLastTeamIconUpdate(t *testing.T, ss store.Store) {

	// team icon initially updated a second ago
	lastTeamIconUpdateInitial := model.GetMillis() - 1000

	o1 := &model.Team{}
	o1.DisplayName = "Display Name"
	o1.Name = "z-z-z" + model.NewId() + "b"
	o1.Email = MakeEmail()
	o1.Type = model.TEAM_OPEN
	o1.LastTeamIconUpdate = lastTeamIconUpdateInitial
	o1, err := ss.Team().Save(o1)
	require.Nil(t, err)

	curTime := model.GetMillis()

	if err = ss.Team().UpdateLastTeamIconUpdate(o1.Id, curTime); err != nil {
		t.Fatal(err)
	}

	ro1, err := ss.Team().Get(o1.Id)
	require.Nil(t, err)

	if ro1.LastTeamIconUpdate <= lastTeamIconUpdateInitial {
		t.Fatal("LastTeamIconUpdate not updated")
	}
}

func testGetTeamsByScheme(t *testing.T, ss store.Store) {
	// Create some schemes.
	s1 := &model.Scheme{
		DisplayName: model.NewId(),
		Name:        model.NewId(),
		Description: model.NewId(),
		Scope:       model.SCHEME_SCOPE_TEAM,
	}

	s2 := &model.Scheme{
		DisplayName: model.NewId(),
		Name:        model.NewId(),
		Description: model.NewId(),
		Scope:       model.SCHEME_SCOPE_TEAM,
	}

	s1, err := ss.Scheme().Save(s1)
	require.Nil(t, err)
	s2, err = ss.Scheme().Save(s2)
	require.Nil(t, err)

	// Create and save some teams.
	t1 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
		SchemeId:    &s1.Id,
	}

	t2 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
		SchemeId:    &s1.Id,
	}

	t3 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
	}

	_, err = ss.Team().Save(t1)
	require.Nil(t, err)

	_, err = ss.Team().Save(t2)
	require.Nil(t, err)

	_, err = ss.Team().Save(t3)
	require.Nil(t, err)

	// Get the teams by a valid Scheme ID.
	d, err := ss.Team().GetTeamsByScheme(s1.Id, 0, 100)
	assert.Nil(t, err)
	assert.Len(t, d, 2)

	// Get the teams by a valid Scheme ID where there aren't any matching Teams.
	d, err = ss.Team().GetTeamsByScheme(s2.Id, 0, 100)
	assert.Nil(t, err)
	assert.Len(t, d, 0)

	// Get the teams by an invalid Scheme ID.
	d, err = ss.Team().GetTeamsByScheme(model.NewId(), 0, 100)
	assert.Nil(t, err)
	assert.Len(t, d, 0)
}

func testTeamStoreMigrateTeamMembers(t *testing.T, ss store.Store) {
	s1 := model.NewId()
	t1 := &model.Team{
		DisplayName: "Name",
		Name:        "z-z-z" + model.NewId() + "b",
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
		InviteId:    model.NewId(),
		SchemeId:    &s1,
	}
	t1, err := ss.Team().Save(t1)
	require.Nil(t, err)

	tm1 := &model.TeamMember{
		TeamId:        t1.Id,
		UserId:        model.NewId(),
		ExplicitRoles: "team_admin team_user",
	}
	tm2 := &model.TeamMember{
		TeamId:        t1.Id,
		UserId:        model.NewId(),
		ExplicitRoles: "team_user",
	}
	tm3 := &model.TeamMember{
		TeamId:        t1.Id,
		UserId:        model.NewId(),
		ExplicitRoles: "something_else",
	}

	tm1, err = ss.Team().SaveMember(tm1, -1)
	require.Nil(t, err)
	tm2, err = ss.Team().SaveMember(tm2, -1)
	require.Nil(t, err)
	tm3, err = ss.Team().SaveMember(tm3, -1)
	require.Nil(t, err)

	lastDoneTeamId := strings.Repeat("0", 26)
	lastDoneUserId := strings.Repeat("0", 26)

	for {
		res, e := ss.Team().MigrateTeamMembers(lastDoneTeamId, lastDoneUserId)
		if assert.Nil(t, e) {
			if res == nil {
				break
			}
			lastDoneTeamId = res["TeamId"]
			lastDoneUserId = res["UserId"]
		}
	}

	tm1b, err := ss.Team().GetMember(tm1.TeamId, tm1.UserId)
	assert.Nil(t, err)
	assert.Equal(t, "", tm1b.ExplicitRoles)
	assert.True(t, tm1b.SchemeUser)
	assert.True(t, tm1b.SchemeAdmin)

	tm2b, err := ss.Team().GetMember(tm2.TeamId, tm2.UserId)
	assert.Nil(t, err)
	assert.Equal(t, "", tm2b.ExplicitRoles)
	assert.True(t, tm2b.SchemeUser)
	assert.False(t, tm2b.SchemeAdmin)

	tm3b, err := ss.Team().GetMember(tm3.TeamId, tm3.UserId)
	assert.Nil(t, err)
	assert.Equal(t, "something_else", tm3b.ExplicitRoles)
	assert.False(t, tm3b.SchemeUser)
	assert.False(t, tm3b.SchemeAdmin)
}

func testResetAllTeamSchemes(t *testing.T, ss store.Store) {
	s1 := &model.Scheme{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Description: model.NewId(),
		Scope:       model.SCHEME_SCOPE_TEAM,
	}
	s1, err := ss.Scheme().Save(s1)
	require.Nil(t, err)

	t1 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
		SchemeId:    &s1.Id,
	}

	t2 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
		SchemeId:    &s1.Id,
	}

	t1, err = ss.Team().Save(t1)
	require.Nil(t, err)
	t2, err = ss.Team().Save(t2)
	require.Nil(t, err)

	assert.Equal(t, s1.Id, *t1.SchemeId)
	assert.Equal(t, s1.Id, *t2.SchemeId)

	res := ss.Team().ResetAllTeamSchemes()
	assert.Nil(t, res)

	t1, err = ss.Team().Get(t1.Id)
	require.Nil(t, err)

	t2, err = ss.Team().Get(t2.Id)
	require.Nil(t, err)

	assert.Equal(t, "", *t1.SchemeId)
	assert.Equal(t, "", *t2.SchemeId)
}

func testTeamStoreClearAllCustomRoleAssignments(t *testing.T, ss store.Store) {
	m1 := &model.TeamMember{
		TeamId:        model.NewId(),
		UserId:        model.NewId(),
		ExplicitRoles: "team_user team_admin team_post_all_public",
	}
	m2 := &model.TeamMember{
		TeamId:        model.NewId(),
		UserId:        model.NewId(),
		ExplicitRoles: "team_user custom_role team_admin another_custom_role",
	}
	m3 := &model.TeamMember{
		TeamId:        model.NewId(),
		UserId:        model.NewId(),
		ExplicitRoles: "team_user",
	}
	m4 := &model.TeamMember{
		TeamId:        model.NewId(),
		UserId:        model.NewId(),
		ExplicitRoles: "custom_only",
	}

	_, err := ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m2, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m3, -1)
	require.Nil(t, err)
	_, err = ss.Team().SaveMember(m4, -1)
	require.Nil(t, err)

	require.Nil(t, (ss.Team().ClearAllCustomRoleAssignments()))

	r1, err := ss.Team().GetMember(m1.TeamId, m1.UserId)
	require.Nil(t, err)
	assert.Equal(t, m1.ExplicitRoles, r1.Roles)

	r2, err := ss.Team().GetMember(m2.TeamId, m2.UserId)
	require.Nil(t, err)
	assert.Equal(t, "team_user team_admin", r2.Roles)

	r3, err := ss.Team().GetMember(m3.TeamId, m3.UserId)
	require.Nil(t, err)
	assert.Equal(t, m3.ExplicitRoles, r3.Roles)

	r4, err := ss.Team().GetMember(m4.TeamId, m4.UserId)
	require.Nil(t, err)
	assert.Equal(t, "", r4.Roles)
}

func testTeamStoreAnalyticsGetTeamCountForScheme(t *testing.T, ss store.Store) {
	s1 := &model.Scheme{
		DisplayName: model.NewId(),
		Name:        model.NewId(),
		Description: model.NewId(),
		Scope:       model.SCHEME_SCOPE_TEAM,
	}
	s1, err := ss.Scheme().Save(s1)
	require.Nil(t, err)

	count1, err := ss.Team().AnalyticsGetTeamCountForScheme(s1.Id)
	assert.Nil(t, err)
	assert.Equal(t, int64(0), count1)

	t1 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
		SchemeId:    &s1.Id,
	}
	_, err = ss.Team().Save(t1)
	require.Nil(t, err)

	count2, err := ss.Team().AnalyticsGetTeamCountForScheme(s1.Id)
	assert.Nil(t, err)
	assert.Equal(t, int64(1), count2)

	t2 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
		SchemeId:    &s1.Id,
	}
	_, err = ss.Team().Save(t2)
	require.Nil(t, err)

	count3, err := ss.Team().AnalyticsGetTeamCountForScheme(s1.Id)
	assert.Nil(t, err)
	assert.Equal(t, int64(2), count3)

	t3 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
	}
	_, err = ss.Team().Save(t3)
	require.Nil(t, err)

	count4, err := ss.Team().AnalyticsGetTeamCountForScheme(s1.Id)
	assert.Nil(t, err)
	assert.Equal(t, int64(2), count4)

	t4 := &model.Team{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Email:       MakeEmail(),
		Type:        model.TEAM_OPEN,
		SchemeId:    &s1.Id,
		DeleteAt:    model.GetMillis(),
	}
	_, err = ss.Team().Save(t4)
	require.Nil(t, err)

	count5, err := ss.Team().AnalyticsGetTeamCountForScheme(s1.Id)
	assert.Nil(t, err)
	assert.Equal(t, int64(2), count5)
}

func testTeamStoreGetAllForExportAfter(t *testing.T, ss store.Store) {
	t1 := model.Team{}
	t1.DisplayName = "Name"
	t1.Name = "zz" + model.NewId()
	t1.Email = MakeEmail()
	t1.Type = model.TEAM_OPEN
	_, err := ss.Team().Save(&t1)
	require.Nil(t, err)

	d1, err := ss.Team().GetAllForExportAfter(10000, strings.Repeat("0", 26))
	assert.Nil(t, err)

	found := false
	for _, team := range d1 {
		if team.Id == t1.Id {
			found = true
			assert.Equal(t, t1.Id, team.Id)
			assert.Nil(t, team.SchemeId)
			assert.Equal(t, t1.Name, team.Name)
		}
	}
	assert.True(t, found)
}

func testTeamStoreGetTeamMembersForExport(t *testing.T, ss store.Store) {
	t1 := model.Team{}
	t1.DisplayName = "Name"
	t1.Name = "zz" + model.NewId()
	t1.Email = MakeEmail()
	t1.Type = model.TEAM_OPEN
	_, err := ss.Team().Save(&t1)
	require.Nil(t, err)

	u1 := model.User{}
	u1.Email = MakeEmail()
	u1.Nickname = model.NewId()
	_, err = ss.User().Save(&u1)
	require.Nil(t, err)

	u2 := model.User{}
	u2.Email = MakeEmail()
	u2.Nickname = model.NewId()
	_, err = ss.User().Save(&u2)
	require.Nil(t, err)

	m1 := &model.TeamMember{TeamId: t1.Id, UserId: u1.Id}
	_, err = ss.Team().SaveMember(m1, -1)
	require.Nil(t, err)

	m2 := &model.TeamMember{TeamId: t1.Id, UserId: u2.Id}
	_, err = ss.Team().SaveMember(m2, -1)
	require.Nil(t, err)

	d1, err := ss.Team().GetTeamMembersForExport(u1.Id)
	assert.Nil(t, err)

	assert.Len(t, d1, 1)

	tmfe1 := d1[0]
	assert.Equal(t, t1.Id, tmfe1.TeamId)
	assert.Equal(t, u1.Id, tmfe1.UserId)
	assert.Equal(t, t1.Name, tmfe1.TeamName)
}
