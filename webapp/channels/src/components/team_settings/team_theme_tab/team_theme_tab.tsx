// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React, {useCallback, useState} from 'react';
import {FormattedMessage, useIntl} from 'react-intl';

import type {Team} from '@mattermost/types/teams';
import type {Theme} from 'mattermost-redux/selectors/entities/preferences';

import ModalSection from 'components/widgets/modals/components/modal_section';
import SaveChangesPanel, {type SaveChangesPanelState} from 'components/widgets/modals/components/save_changes_panel';
import Toggle from 'components/toggle';
import PremadeThemeChooser from 'components/user_settings/display/user_settings_theme/premade_theme_chooser';
import CustomThemeChooser from 'components/user_settings/display/user_settings_theme/custom_theme_chooser/custom_theme_chooser';

import type {PropsFromRedux, OwnProps} from '.';

import './team_theme_tab.scss';
import Constants from 'utils/constants';

type Props = PropsFromRedux & OwnProps;

const TeamThemeTab = ({
    team,
    themes,
    allowCustomThemes,
    hasChanges,
    hasChangeTabError,
    setHasChanges,
    setHasChangeTabError,
    closeModal,
    collapseModal,
    isSystemAdmin,
    actions,
}: Props) => {
    const initialTheme = (() => {
        try {
            return team.settings?.theme ? JSON.parse(team.settings.theme) : themes.denim;
        } catch (e) {
            console.error('Error parsing team theme:', e);
            return themes.denim;
        }
    })();
    const initialHasTheme = Boolean(team.settings?.theme);
    
    // If initialTheme is not a valid theme object due to null/undefined settings, use default theme
    const [theme, setTheme] = useState<Theme>(() => {
        try {
            if (initialTheme && typeof initialTheme === 'object' && 'type' in initialTheme) {
                return initialTheme;
            }
            return themes.denim;
        } catch (e) {
            return themes.denim;
        }
    });
    const [hasTeamTheme, setHasTeamTheme] = useState<boolean>(initialHasTheme);
    const [themeType, setThemeType] = useState<string>(theme.type || 'premade');
    const [saveChangesPanelState, setSaveChangesPanelState] = useState<SaveChangesPanelState>();
    const [isSaving, setIsSaving] = useState<boolean>(false);
    const [serverError, setServerError] = useState<string>('');

    const {formatMessage} = useIntl();

    const handleSubmit = useCallback(async (): Promise<void> => {
        const teamUpdate: Partial<Team> = {
            id: team.id,
            settings: team.settings || {},
        };

        if (hasTeamTheme) {
            teamUpdate.settings = {
                ...teamUpdate.settings,
                theme: JSON.stringify(theme),
            };
        } else if (teamUpdate.settings?.theme) {
            // Remove theme from settings
            const { theme: _, ...restSettings } = teamUpdate.settings;
            teamUpdate.settings = restSettings;
        }

        setIsSaving(true);
        const {error} = await actions.patchTeam(teamUpdate);
        setIsSaving(false);

        if (error) {
            setServerError(error.message);
            setSaveChangesPanelState('error');
            return;
        }

        setSaveChangesPanelState('saved');
        setHasChangeTabError(false);
    }, [actions, theme, hasTeamTheme, team.id, setHasChangeTabError]);

    const handleUpdateTheme = useCallback((newTheme: Theme): void => {
        setTheme(newTheme);
        setSaveChangesPanelState('editing');
        setHasChanges(true);
    }, [setHasChanges]);

    const handleToggleTheme = useCallback((enabled: boolean): void => {
        setHasTeamTheme(enabled);
        setSaveChangesPanelState('editing');
        setHasChanges(true);
    }, [setHasChanges]);

    const handleUpdateType = useCallback((newType: string): void => {
        setThemeType(newType);
    }, []);

    const handleCancel = useCallback(() => {
        setTheme(initialTheme);
        setHasTeamTheme(initialHasTheme);
        setThemeType(initialTheme.type || 'premade');
        setServerError('');
        setSaveChangesPanelState(undefined);
        setHasChanges(false);
        setHasChangeTabError(false);
    }, [initialTheme, initialHasTheme, setHasChanges, setHasChangeTabError]);

    const handleClose = useCallback(() => {
        setSaveChangesPanelState(undefined);
        setHasChanges(false);
        setHasChangeTabError(false);
    }, [setHasChanges, setHasChangeTabError]);

    const handleCollapseModal = useCallback(() => {
        if (hasChanges) {
            setHasChangeTabError(true);
            return;
        }
        collapseModal();
    }, [collapseModal, hasChanges, setHasChangeTabError]);

    // Only team admins and system admins can set theme
    if (!isSystemAdmin && team.type !== 'O') {
        return (
            <ModalSection
                content={
                    <div className='ThemeSettingDescription'>
                        <FormattedMessage
                            id='team_settings.theme.permissionError'
                            defaultMessage='You must be a Team or System Admin to manage team themes.'
                        />
                    </div>
                }
            />
        );
    }

    const displayCustom = themeType === 'custom';
    
    let themeChooser;
    if (hasTeamTheme) {
        const inputs = [];

        if (allowCustomThemes) {
            inputs.push(
                <div
                    key='premadeCustom'
                    className='user-settings__radio-group-inline'
                >
                    <div className='radio radio-inline'>
                        <label>
                            <input
                                id='standardThemes'
                                type='radio'
                                name='theme'
                                checked={!displayCustom}
                                onChange={() => handleUpdateType('premade')}
                            />
                            <FormattedMessage
                                id='user.settings.display.theme.premadeThemes'
                                defaultMessage='Premade Themes'
                            />
                        </label>
                    </div>
                    <div className='radio radio-inline'>
                        <label>
                            <input
                                id='customThemes'
                                type='radio'
                                name='theme'
                                checked={displayCustom}
                                onChange={() => handleUpdateType('custom')}
                            />
                            <FormattedMessage
                                id='user.settings.display.theme.customTheme'
                                defaultMessage='Custom Theme'
                            />
                        </label>
                    </div>
                </div>,
            );

            inputs.push(
                displayCustom ? (
                    <div key='customThemeChooser'>
                        <CustomThemeChooser
                            theme={theme}
                            updateTheme={handleUpdateTheme}
                        />
                    </div>
                ) : (
                    <div key='premadeThemeChooser'>
                        <br/>
                        <PremadeThemeChooser
                            theme={theme}
                            updateTheme={handleUpdateTheme}
                        />
                    </div>
                ),
            );
        } else {
            inputs.push(
                <div key='premadeThemeChooser'>
                    <br/>
                    <PremadeThemeChooser
                        theme={theme}
                        updateTheme={handleUpdateTheme}
                    />
                </div>,
            );
        }

        themeChooser = (
            <fieldset>
                <legend className='hidden-label'>
                    <FormattedMessage
                        id='team_settings.theme.title'
                        defaultMessage='Team Theme'
                    />
                </legend>
                <div>{inputs}</div>
            </fieldset>
        );
    }

    const modalSectionContent = (
        <>
            <div className='modal-header'>
                <button
                    id='closeButton'
                    type='button'
                    className='close'
                    data-dismiss='modal'
                    onClick={closeModal}
                >
                    <span aria-hidden='true'>{'×'}</span>
                </button>
                <h4 className='modal-title'>
                    <div className='modal-back'>
                        <i
                            className='fa fa-angle-left'
                            aria-label={formatMessage({
                                id: 'generic_icons.collapse',
                                defaultMessage: 'Collapse Icon',
                            })}
                            onClick={handleCollapseModal}
                        />
                    </div>
                    <span>{formatMessage({id: 'team_settings_modal.title', defaultMessage: 'Team Settings'})}</span>
                </h4>
            </div>
            <div
                className='user-settings team-theme-tab-content'
                id='themeSettings'
                role='tabpanel'
            >
                <h3 className='ThemeSettingHeader'>
                    <FormattedMessage
                        id='team_settings.theme.title'
                        defaultMessage='Team Theme'
                    />
                </h3>
                <div className='ThemeSettingDescription'>
                    <FormattedMessage
                        id='team_settings.theme.description'
                        defaultMessage='Enable a mandatory team theme to ensure all team members have a consistent appearance.'
                    />
                </div>
                
                <div className='team-settings-theme-toggle'>
                    <label>
                        <FormattedMessage
                            id='team_settings.theme.enable'
                            defaultMessage='Enable mandatory team theme'
                        />
                    </label>
                    <div className='float-right'>
                        <Toggle
                            id='team-theme-toggle'
                            onToggle={handleToggleTheme}
                            toggled={hasTeamTheme}
                        />
                    </div>
                </div>
                
                {themeChooser}
                
                {hasChanges && (
                    <SaveChangesPanel
                        handleCancel={handleCancel}
                        handleSubmit={handleSubmit}
                        handleClose={handleClose}
                        tabChangeError={hasChangeTabError}
                        state={saveChangesPanelState}
                        isSaving={isSaving}
                        serverError={serverError}
                    />
                )}
            </div>
        </>
    );

    return <ModalSection content={modalSectionContent} />;
};

export default TeamThemeTab;