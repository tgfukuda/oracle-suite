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

package messages

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/defiweb/go-eth/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/chronicleprotocol/oracle-suite/pkg/price/median"
)

func TestPrice_Marshalling(t *testing.T) {
	tests := []struct {
		price   *Price
		wantErr bool
	}{
		// Simple message:
		{
			price: &Price{
				messageVersion: 0,
				Price: &median.Price{
					Wat: "AAABBB",
					Val: big.NewInt(10),
					Age: time.Unix(100, 0),
					Sig: types.Signature{
						V: new(big.Int).SetInt64(1),
						R: new(big.Int).SetBytes([]byte{1}),
						S: new(big.Int).SetBytes([]byte{2}),
					},
				},
				Trace:   []byte("{}"),
				Version: "0.0.1",
			},
			wantErr: false,
		},
		// Simple message as V0:
		{
			price: (&Price{
				messageVersion: 0,
				Price: &median.Price{
					Wat: "AAABBB",
					Val: big.NewInt(10),
					Age: time.Unix(100, 0),
					Sig: types.Signature{
						V: new(big.Int).SetInt64(1),
						R: new(big.Int).SetBytes([]byte{1}),
						S: new(big.Int).SetBytes([]byte{2}),
					},
				},
				Trace:   []byte("{}"),
				Version: "0.0.1",
			}).AsV0(),
			wantErr: false,
		},
		// Simple message as V1:
		{
			price: (&Price{
				messageVersion: 0,
				Price: &median.Price{
					Wat: "AAABBB",
					Val: big.NewInt(10),
					Age: time.Unix(100, 0),
					Sig: types.Signature{
						V: new(big.Int).SetInt64(1),
						R: new(big.Int).SetBytes([]byte{1}),
						S: new(big.Int).SetBytes([]byte{2}),
					},
				},
				Trace:   []byte("{}"),
				Version: "0.0.1",
			}).AsV0(),
			wantErr: false,
		},
		// Without trace:
		{
			price: &Price{
				messageVersion: 0,
				Price:          &median.Price{},
				Trace:          nil,
				Version:        "0.0.1",
			},
			wantErr: false,
		},
		// Without trace as V0:
		{
			price: (&Price{
				messageVersion: 0,
				Price:          &median.Price{},
				Trace:          nil,
				Version:        "0.0.1",
			}).AsV0(),
			wantErr: false,
		},
		// Without trace as V1:
		{
			price: (&Price{
				messageVersion: 0,
				Price:          &median.Price{},
				Trace:          nil,
				Version:        "0.0.1",
			}).AsV1(),
			wantErr: false,
		},
		// Too large message:
		{
			price: &Price{
				messageVersion: 0,
				Price:          &median.Price{},
				Trace:          nil,
				Version:        strings.Repeat("a", priceMessageMaxSize+1),
			},
			wantErr: true,
		},
		// Too large V0 message:
		{
			price: (&Price{
				messageVersion: 0,
				Price:          &median.Price{},
				Trace:          nil,
				Version:        strings.Repeat("a", priceMessageMaxSize+1),
			}).AsV0(),
			wantErr: true,
		},
		// Too large V1 message:
		{
			price: (&Price{
				messageVersion: 0,
				Price:          &median.Price{},
				Trace:          nil,
				Version:        strings.Repeat("a", priceMessageMaxSize+1),
			}).AsV1(),
			wantErr: true,
		},
	}
	for n, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", n+1), func(t *testing.T) {
			msg, err := tt.price.MarshallBinary()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				price := &Price{}
				err := price.UnmarshallBinary(msg)

				require.NoError(t, err)
				assert.Equal(t, tt.price.Price.Wat, price.Price.Wat)
				if tt.price.Price.Val != nil {
					assert.Equal(t, tt.price.Price.Val.Bytes(), price.Price.Val.Bytes())
				} else {
					assert.Equal(t, big.NewInt(0), price.Price.Val)
				}
				assert.Equal(t, tt.price.Price.Age.Unix(), price.Price.Age.Unix())
				assert.Equal(t, tt.price.Price.Sig.Bytes(), price.Price.Sig.Bytes())
				assert.Equal(t, tt.price.Version, price.Version)

				if tt.price.messageVersion == 0 && tt.price.Trace == nil {
					assert.Equal(t, json.RawMessage("null"), price.Trace)
				} else {
					assert.Equal(t, tt.price.Trace, price.Trace)
				}
			}
		})
	}
}

func FuzzPrice_UnmarshallBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = (&Price{}).UnmarshallBinary(data)
	})
}
