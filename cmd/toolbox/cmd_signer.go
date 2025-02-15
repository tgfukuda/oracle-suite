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
	"encoding/hex"
	"fmt"

	"github.com/defiweb/go-eth/crypto"
	"github.com/defiweb/go-eth/types"

	"github.com/spf13/cobra"
)

type signerOptions struct {
	Hex bool
}

func NewSignerCmd(opts *options) *cobra.Command {
	var signerOpts signerOptions

	cmd := &cobra.Command{
		Use:   "signer",
		Args:  cobra.ExactArgs(0),
		Short: "commands used to sign and verify data",
		Long:  ``,
	}

	cmd.PersistentFlags().BoolVar(
		&signerOpts.Hex,
		"hex",
		false,
		"is input encoded as a string",
	)

	cmd.AddCommand(
		NewSignerSignCmd(opts, &signerOpts),
		NewSignerVerifyCmd(&signerOpts),
	)

	return cmd
}

func NewSignerSignCmd(opts *options, signerOpts *signerOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "sign key [input]",
		Args:  cobra.MinimumNArgs(1),
		Short: "signs given input (stdin is used if input argument is empty)",
		Long:  ``,
		RunE: func(_ *cobra.Command, args []string) error {
			srv, err := PrepareServices(opts)
			if err != nil {
				return err
			}

			// Key:
			key, ok := srv.Keys[args[0]]
			if !ok {
				return fmt.Errorf("unable to find key %s", args[0])
			}

			in, err := readInput(args, 0)
			if err != nil {
				return err
			}

			if signerOpts.Hex {
				in, err = hex.DecodeString(string(in))
				if err != nil {
					return err
				}
			}

			signature, err := key.SignMessage(in)
			if err != nil {
				return err
			}

			fmt.Printf("%x\n", signature.Bytes())

			return nil
		},
	}
}

func NewSignerVerifyCmd(signerOpts *signerOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "verify signature [input]",
		Args:  cobra.MaximumNArgs(1),
		Short: "verifies given signature (stdin is used if input argument is empty)",
		Long:  ``,
		RunE: func(_ *cobra.Command, args []string) error {
			in, err := readInput(args, 1)
			if err != nil {
				return err
			}

			if signerOpts.Hex {
				in, err = hex.DecodeString(string(in))
				if err != nil {
					return err
				}
			}

			signature, err := hex.DecodeString(args[0])
			if err != nil {
				return err
			}

			address, err := crypto.ECRecoverer.RecoverMessage(in, types.MustSignatureFromBytes(signature))
			if err != nil {
				return err
			}

			fmt.Println(address.String())

			return nil
		},
	}
}
