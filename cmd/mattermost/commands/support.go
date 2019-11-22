package commands

import (
	"github.com/spf13/cobra"
)

var SupportCmd = &cobra.Command{
	Use:                        "support",
	Short:                      "Get Mattermost support",
	Long:                       "Get support from Mattermost on any service related issues",
}

var SupportHelpCmd = &cobra.Command{
	Use:                        "help [subject] [body]",
	Short:                      "Create support ticket",
	Long:                       "Create a new support ticket with Mattermost support",
	Example:                    "support help \"Users disabled after LDAP Sync\" \"After changing a setting in our LDAP config all of our users got disabled.\" ",
	Args:                       cobra.MinimumNArgs(2),
	RunE:                       supportHelpCmdF,
}

func init()  {
	SupportCmd.AddCommand(SupportHelpCmd)
	RootCmd.AddCommand(SupportCmd)
}

func supportHelpCmdF(command *cobra.Command, args []string) error {
	subject := args[0]
	body := args[1]

	a, err := InitDBCommandContextCobra(command)
	if err != nil {
		CommandPrettyPrintln(err)
	}
	defer a.Shutdown()

	err = a.SendSupportEmail("changeme@example.com", subject, body)
	if err != nil {
		CommandPrettyPrintln(err)
	}

	return nil
}
