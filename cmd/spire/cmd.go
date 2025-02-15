//  Copyright (C) 2020 Maker Ecosystem Growth Holdings, INC.
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as
//  published by the Free Software Foundation, either version 3 of the
//  License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"github.com/spf13/cobra"

	"github.com/chronicleprotocol/oracle-suite/pkg/config/spire"
	"github.com/chronicleprotocol/oracle-suite/pkg/log/logrus/flag"
)

type options struct {
	flag.LoggerFlag
	ConfigFilePath    []string
	Config            spire.Config
	Version           string
	TransportOverride string
}

func NewRootCommand(opts *options) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "spire",
		Version:       opts.Version,
		Short:         "",
		SilenceErrors: false,
		SilenceUsage:  true,
	}

	rootCmd.PersistentFlags().AddFlagSet(flag.NewLoggerFlagSet(&opts.LoggerFlag))
	rootCmd.PersistentFlags().StringSliceVarP(
		&opts.ConfigFilePath,
		"config",
		"c",
		[]string{"./config.hcl"},
		"spire config file",
	)

	rootCmd.AddCommand(
		NewAgentCmd(opts),
		NewStreamCmd(opts),
		NewPullCmd(opts),
		NewPushCmd(opts),
	)

	return rootCmd
}
