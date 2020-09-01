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

package exchange

import (
	"fmt"
	"testing"

	"github.com/makerdao/gofer/internal/query"
	"github.com/makerdao/gofer/pkg/model"

	"github.com/stretchr/testify/suite"
)

// Define the suite, and absorb the built-in basic suite
// functionality from testify - including a T() method which
// returns the current testing context
type HuobiSuite struct {
	suite.Suite
	pool     query.WorkerPool
	exchange *Huobi
}

func (suite *HuobiSuite) Exchange() Handler {
	return suite.exchange
}

// Setup exchange
func (suite *HuobiSuite) SetupSuite() {
	suite.exchange = &Huobi{Pool: query.NewMockWorkerPool()}
}

func (suite *HuobiSuite) TearDownTest() {
	// cleanup created pool from prev test
	if suite.pool != nil {
		suite.pool = nil
	}
}

func (suite *HuobiSuite) TestLocalPair() {
	suite.EqualValues("btceth", suite.exchange.localPairName(model.NewPair("BTC", "ETH")))
	suite.EqualValues("btcusd", suite.exchange.localPairName(model.NewPair("BTC", "USD")))
}

func (suite *HuobiSuite) TestFailOnWrongInput() {
	var err error

	// empty pp
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{nil})
	suite.Error(err)

	// wrong pp
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{{}})
	suite.Error(err)

	pp := newPotentialPricePoint("huobi", "BTC", "ETH")
	// nil as response
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{pp})
	suite.Equal(errEmptyExchangeResponse, err)

	// error in response
	ourErr := fmt.Errorf("error")
	resp := &query.HTTPResponse{
		Error: ourErr,
	}
	suite.exchange.Pool.(*query.MockWorkerPool).MockResp(resp)
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{pp})
	suite.Equal(ourErr, err)

	// Error unmarshal
	resp = &query.HTTPResponse{
		Body: []byte(""),
	}
	suite.exchange.Pool.(*query.MockWorkerPool).MockResp(resp)
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{pp})
	suite.Error(err)

	// Error parsing
	resp = &query.HTTPResponse{
		Body: []byte(`{"status":"error"}`),
	}
	suite.exchange.Pool.(*query.MockWorkerPool).MockResp(resp)
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{pp})
	suite.Error(err)

	// Error parsing
	resp = &query.HTTPResponse{
		Body: []byte(`{"status":"success","vol":"abc"}`),
	}
	suite.exchange.Pool.(*query.MockWorkerPool).MockResp(resp)
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{pp})
	suite.Error(err)

	// Error parsing
	resp = &query.HTTPResponse{
		Body: []byte(`{"status":"success","vol":"1","ts":"abc"}`),
	}
	suite.exchange.Pool.(*query.MockWorkerPool).MockResp(resp)
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{pp})
	suite.Error(err)

	// Error parsing
	resp = &query.HTTPResponse{
		Body: []byte(`{"status":"success","vol":"1","ts":2,"tick":{"bid":["abc"]}}`),
	}
	suite.exchange.Pool.(*query.MockWorkerPool).MockResp(resp)
	_, err = suite.exchange.Call([]*model.PotentialPricePoint{pp})
	suite.Error(err)
}

func (suite *HuobiSuite) TestSuccessResponse() {
	pp := newPotentialPricePoint("huobi", "BTC", "ETH")
	resp := &query.HTTPResponse{
		Body: []byte(`{"status":"success","vol":1.3,"ts":2000,"tick":{"bid":[2.1,3.4]}}`),
	}
	suite.exchange.Pool.(*query.MockWorkerPool).MockResp(resp)
	point, err := suite.exchange.Call([]*model.PotentialPricePoint{pp})

	suite.NoError(err)
	suite.Equal(pp.Exchange, point[0].Exchange)
	suite.Equal(pp.Pair, point[0].Pair)
	suite.Equal(1.3, point[0].Volume)
	suite.Equal(2.1, point[0].Price)
	suite.Equal(point[0].Timestamp, int64(2))
}

func (suite *HuobiSuite) TestRealAPICall() {
	testRealAPICall(suite, &Huobi{Pool: query.NewHTTPWorkerPool(1)}, "ETH", "BTC")
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestHuobiSuite(t *testing.T) {
	suite.Run(t, new(HuobiSuite))
}
