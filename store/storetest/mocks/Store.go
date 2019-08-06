// Code generated by mockery v1.0.0. DO NOT EDIT.

// Regenerate this file using `make store-mocks`.

package mocks

import mock "github.com/stretchr/testify/mock"
import store "github.com/mattermost/mattermost-server/store"

// Store is an autogenerated mock type for the Store type
type Store struct {
	mock.Mock
}

// Audit provides a mock function with given fields:
func (_m *Store) Audit() store.AuditStore {
	ret := _m.Called()

	var r0 store.AuditStore
	if rf, ok := ret.Get(0).(func() store.AuditStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.AuditStore)
		}
	}

	return r0
}

// Bot provides a mock function with given fields:
func (_m *Store) Bot() store.BotStore {
	ret := _m.Called()

	var r0 store.BotStore
	if rf, ok := ret.Get(0).(func() store.BotStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.BotStore)
		}
	}

	return r0
}

// Channel provides a mock function with given fields:
func (_m *Store) Channel() store.ChannelStore {
	ret := _m.Called()

	var r0 store.ChannelStore
	if rf, ok := ret.Get(0).(func() store.ChannelStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.ChannelStore)
		}
	}

	return r0
}

// ChannelMemberHistory provides a mock function with given fields:
func (_m *Store) ChannelMemberHistory() store.ChannelMemberHistoryStore {
	ret := _m.Called()

	var r0 store.ChannelMemberHistoryStore
	if rf, ok := ret.Get(0).(func() store.ChannelMemberHistoryStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.ChannelMemberHistoryStore)
		}
	}

	return r0
}

// Close provides a mock function with given fields:
func (_m *Store) Close() {
	_m.Called()
}

// ClusterDiscovery provides a mock function with given fields:
func (_m *Store) ClusterDiscovery() store.ClusterDiscoveryStore {
	ret := _m.Called()

	var r0 store.ClusterDiscoveryStore
	if rf, ok := ret.Get(0).(func() store.ClusterDiscoveryStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.ClusterDiscoveryStore)
		}
	}

	return r0
}

// Command provides a mock function with given fields:
func (_m *Store) Command() store.CommandStore {
	ret := _m.Called()

	var r0 store.CommandStore
	if rf, ok := ret.Get(0).(func() store.CommandStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.CommandStore)
		}
	}

	return r0
}

// CommandWebhook provides a mock function with given fields:
func (_m *Store) CommandWebhook() store.CommandWebhookStore {
	ret := _m.Called()

	var r0 store.CommandWebhookStore
	if rf, ok := ret.Get(0).(func() store.CommandWebhookStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.CommandWebhookStore)
		}
	}

	return r0
}

// Compliance provides a mock function with given fields:
func (_m *Store) Compliance() store.ComplianceStore {
	ret := _m.Called()

	var r0 store.ComplianceStore
	if rf, ok := ret.Get(0).(func() store.ComplianceStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.ComplianceStore)
		}
	}

	return r0
}

// DropAllTables provides a mock function with given fields:
func (_m *Store) DropAllTables() {
	_m.Called()
}

// Emoji provides a mock function with given fields:
func (_m *Store) Emoji() store.EmojiStore {
	ret := _m.Called()

	var r0 store.EmojiStore
	if rf, ok := ret.Get(0).(func() store.EmojiStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.EmojiStore)
		}
	}

	return r0
}

// FileInfo provides a mock function with given fields:
func (_m *Store) FileInfo() store.FileInfoStore {
	ret := _m.Called()

	var r0 store.FileInfoStore
	if rf, ok := ret.Get(0).(func() store.FileInfoStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.FileInfoStore)
		}
	}

	return r0
}

// GetCurrentSchemaVersion provides a mock function with given fields:
func (_m *Store) GetCurrentSchemaVersion() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Group provides a mock function with given fields:
func (_m *Store) Group() store.GroupStore {
	ret := _m.Called()

	var r0 store.GroupStore
	if rf, ok := ret.Get(0).(func() store.GroupStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.GroupStore)
		}
	}

	return r0
}

// Job provides a mock function with given fields:
func (_m *Store) Job() store.JobStore {
	ret := _m.Called()

	var r0 store.JobStore
	if rf, ok := ret.Get(0).(func() store.JobStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.JobStore)
		}
	}

	return r0
}

// License provides a mock function with given fields:
func (_m *Store) License() store.LicenseStore {
	ret := _m.Called()

	var r0 store.LicenseStore
	if rf, ok := ret.Get(0).(func() store.LicenseStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.LicenseStore)
		}
	}

	return r0
}

// LinkMetadata provides a mock function with given fields:
func (_m *Store) LinkMetadata() store.LinkMetadataStore {
	ret := _m.Called()

	var r0 store.LinkMetadataStore
	if rf, ok := ret.Get(0).(func() store.LinkMetadataStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.LinkMetadataStore)
		}
	}

	return r0
}

// LockToMaster provides a mock function with given fields:
func (_m *Store) LockToMaster() {
	_m.Called()
}

// MarkSystemRanUnitTests provides a mock function with given fields:
func (_m *Store) MarkSystemRanUnitTests() {
	_m.Called()
}

// OAuth provides a mock function with given fields:
func (_m *Store) OAuth() store.OAuthStore {
	ret := _m.Called()

	var r0 store.OAuthStore
	if rf, ok := ret.Get(0).(func() store.OAuthStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.OAuthStore)
		}
	}

	return r0
}

// Plugin provides a mock function with given fields:
func (_m *Store) Plugin() store.PluginStore {
	ret := _m.Called()

	var r0 store.PluginStore
	if rf, ok := ret.Get(0).(func() store.PluginStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.PluginStore)
		}
	}

	return r0
}

// Post provides a mock function with given fields:
func (_m *Store) Post() store.PostStore {
	ret := _m.Called()

	var r0 store.PostStore
	if rf, ok := ret.Get(0).(func() store.PostStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.PostStore)
		}
	}

	return r0
}

// Preference provides a mock function with given fields:
func (_m *Store) Preference() store.PreferenceStore {
	ret := _m.Called()

	var r0 store.PreferenceStore
	if rf, ok := ret.Get(0).(func() store.PreferenceStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.PreferenceStore)
		}
	}

	return r0
}

// Reaction provides a mock function with given fields:
func (_m *Store) Reaction() store.ReactionStore {
	ret := _m.Called()

	var r0 store.ReactionStore
	if rf, ok := ret.Get(0).(func() store.ReactionStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.ReactionStore)
		}
	}

	return r0
}

// Role provides a mock function with given fields:
func (_m *Store) Role() store.RoleStore {
	ret := _m.Called()

	var r0 store.RoleStore
	if rf, ok := ret.Get(0).(func() store.RoleStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.RoleStore)
		}
	}

	return r0
}

// Scheme provides a mock function with given fields:
func (_m *Store) Scheme() store.SchemeStore {
	ret := _m.Called()

	var r0 store.SchemeStore
	if rf, ok := ret.Get(0).(func() store.SchemeStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.SchemeStore)
		}
	}

	return r0
}

// Session provides a mock function with given fields:
func (_m *Store) Session() store.SessionStore {
	ret := _m.Called()

	var r0 store.SessionStore
	if rf, ok := ret.Get(0).(func() store.SessionStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.SessionStore)
		}
	}

	return r0
}

// Status provides a mock function with given fields:
func (_m *Store) Status() store.StatusStore {
	ret := _m.Called()

	var r0 store.StatusStore
	if rf, ok := ret.Get(0).(func() store.StatusStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.StatusStore)
		}
	}

	return r0
}

// System provides a mock function with given fields:
func (_m *Store) System() store.SystemStore {
	ret := _m.Called()

	var r0 store.SystemStore
	if rf, ok := ret.Get(0).(func() store.SystemStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.SystemStore)
		}
	}

	return r0
}

// Team provides a mock function with given fields:
func (_m *Store) Team() store.TeamStore {
	ret := _m.Called()

	var r0 store.TeamStore
	if rf, ok := ret.Get(0).(func() store.TeamStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.TeamStore)
		}
	}

	return r0
}

// TermsOfService provides a mock function with given fields:
func (_m *Store) TermsOfService() store.TermsOfServiceStore {
	ret := _m.Called()

	var r0 store.TermsOfServiceStore
	if rf, ok := ret.Get(0).(func() store.TermsOfServiceStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.TermsOfServiceStore)
		}
	}

	return r0
}

// Token provides a mock function with given fields:
func (_m *Store) Token() store.TokenStore {
	ret := _m.Called()

	var r0 store.TokenStore
	if rf, ok := ret.Get(0).(func() store.TokenStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.TokenStore)
		}
	}

	return r0
}

// TotalMasterDbConnections provides a mock function with given fields:
func (_m *Store) TotalMasterDbConnections() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// TotalReadDbConnections provides a mock function with given fields:
func (_m *Store) TotalReadDbConnections() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// TotalSearchDbConnections provides a mock function with given fields:
func (_m *Store) TotalSearchDbConnections() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// UnlockFromMaster provides a mock function with given fields:
func (_m *Store) UnlockFromMaster() {
	_m.Called()
}

// User provides a mock function with given fields:
func (_m *Store) User() store.UserStore {
	ret := _m.Called()

	var r0 store.UserStore
	if rf, ok := ret.Get(0).(func() store.UserStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.UserStore)
		}
	}

	return r0
}

// UserAccessToken provides a mock function with given fields:
func (_m *Store) UserAccessToken() store.UserAccessTokenStore {
	ret := _m.Called()

	var r0 store.UserAccessTokenStore
	if rf, ok := ret.Get(0).(func() store.UserAccessTokenStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.UserAccessTokenStore)
		}
	}

	return r0
}

// UserTermsOfService provides a mock function with given fields:
func (_m *Store) UserTermsOfService() store.UserTermsOfServiceStore {
	ret := _m.Called()

	var r0 store.UserTermsOfServiceStore
	if rf, ok := ret.Get(0).(func() store.UserTermsOfServiceStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.UserTermsOfServiceStore)
		}
	}

	return r0
}

// Webhook provides a mock function with given fields:
func (_m *Store) Webhook() store.WebhookStore {
	ret := _m.Called()

	var r0 store.WebhookStore
	if rf, ok := ret.Get(0).(func() store.WebhookStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.WebhookStore)
		}
	}

	return r0
}
