// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import {connect} from 'react-redux';
import type {ConnectedProps} from 'react-redux';
import {bindActionCreators} from 'redux';
import type {Dispatch} from 'redux';

import type {Team} from '@mattermost/types/teams';

import {getTeam, patchTeam} from 'mattermost-redux/actions/teams';
import {getConfig} from 'mattermost-redux/selectors/entities/general';
import {Preferences} from 'mattermost-redux/constants';
import {Permissions} from 'mattermost-redux/constants';
import {haveISystemPermission} from 'mattermost-redux/selectors/entities/roles';

import type {GlobalState} from 'types/store/index';

import TeamThemeTab from './team_theme_tab';

export type OwnProps = {
    team: Team;
    hasChanges: boolean;
    hasChangeTabError: boolean;
    setHasChanges: (hasChanges: boolean) => void;
    setHasChangeTabError: (hasChangesError: boolean) => void;
    closeModal: () => void;
    collapseModal: () => void;
};

function mapStateToProps(state: GlobalState) {
    const config = getConfig(state);
    const isSystemAdmin = haveISystemPermission(state, {permission: Permissions.MANAGE_SYSTEM});
    
    return {
        themes: Preferences.THEMES,
        allowCustomThemes: config.AllowCustomThemes !== 'false',
        isSystemAdmin,
    };
}

function mapDispatchToProps(dispatch: Dispatch) {
    return {
        actions: bindActionCreators({
            getTeam,
            patchTeam,
        }, dispatch),
    };
}

const connector = connect(mapStateToProps, mapDispatchToProps);

export type PropsFromRedux = ConnectedProps<typeof connector>;

export default connector(TeamThemeTab);