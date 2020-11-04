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

package relayer

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/makerdao/gofer/internal/logger"
	"github.com/makerdao/gofer/internal/oracle"
	"github.com/makerdao/gofer/internal/transport"
	"github.com/makerdao/gofer/pkg/messages"
)

const LoggerTag = "RELAYER"

type Relayer struct {
	mu        sync.Mutex
	feeds     []common.Address
	transport transport.Transport
	interval  time.Duration
	logger    logger.Logger
	pairs     map[string]Pair
	verbose   bool
	doneCh    chan struct{}
}

type Config struct {
	// Feeds is the list of Ethereum addresses from which prices will be
	// accepted.
	Feeds []string
	// Transport is a implementation of transport used to fetch prices from
	// feeders.
	Transport transport.Transport
	// Interval describes how often we should try to update Oracles.
	Interval time.Duration
	// Logger is a current logger interface used by the Relayer. The Logger is
	// required to monitor asynchronous processes.
	Logger logger.Logger
	// Pairs is the list supported pairs by Relayer with their configuration.
	Pairs []Pair
}

type Pair struct {
	// AssetPair is the name of asset pair, e.g. ETHUSD.
	AssetPair string
	// OracleSpread is the minimum spread between the Oracle price and new price
	// required to send update.
	OracleSpread float64
	// OracleExpiration is the minimum time difference between the Oracle time
	// and current time required to send an update.
	OracleExpiration time.Duration
	// PriceExpiration is the maximum amount of time before price received
	// from the feeder will be considered as expired.
	PriceExpiration time.Duration
	// Median is the instance of the oracle.Median which is the interface for
	// the Oracle contract.
	Median *oracle.Median
	// store contains list of prices form feeders.
	store *store
}

func NewRelayer(config Config) *Relayer {
	r := &Relayer{
		transport: config.Transport,
		interval:  config.Interval,
		logger:    config.Logger,
		pairs:     make(map[string]Pair, 0),
		doneCh:    make(chan struct{}),
	}

	for _, feed := range config.Feeds {
		r.feeds = append(r.feeds, common.HexToAddress(feed))
	}

	for _, pair := range config.Pairs {
		pair.store = newStore()
		r.pairs[pair.AssetPair] = pair
	}

	return r
}

func (r *Relayer) Start() error {
	r.logger.Info(LoggerTag, "Starting")
	err := r.collectorLoop()
	if err != nil {
		return err
	}

	r.relayerLoop()
	return nil
}

func (r *Relayer) Stop() error {
	defer r.logger.Info(LoggerTag, "Stopped")

	close(r.doneCh)
	err := r.transport.Unsubscribe(messages.PriceMessageName)
	if err != nil {
		return err
	}

	return nil
}

// collect adds a price from a feeder which may be used to update
// Oracle contract. The price will be added only if a feeder is
// allowed to send prices (must be on the r.Feeds list).
func (r *Relayer) collect(price *oracle.Price) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	from, err := price.From()
	if err != nil {
		return fmt.Errorf("recieved price has an invalid signature (pair: %s)", price.AssetPair)
	}
	if !r.isFeedAllowed(*from) {
		return fmt.Errorf("address is not on feed list (pair: %s, from: %s)", price.AssetPair, from.String())
	}
	if price.Val.Cmp(big.NewInt(0)) <= 0 {
		return fmt.Errorf("recieved price is invalid (pair: %s, from: %s)", price.AssetPair, from.String())
	}
	if _, ok := r.pairs[price.AssetPair]; !ok {
		return fmt.Errorf("recieved pair is not configured (pair: %s, from: %s)", price.AssetPair, from.String())
	}

	err = r.pairs[price.AssetPair].store.add(price)
	if err != nil {
		return err
	}

	return nil
}

// relay tries to update an Oracle contract for given pair. It'll return
// transaction hash or nil if there is no need to update Oracle.
func (r *Relayer) relay(assetPair string) (*common.Hash, error) {
	ctx := context.Background()
	pair := r.pairs[assetPair]

	oracleQuorum, err := pair.Median.Bar(ctx)
	if err != nil {
		return nil, err
	}
	oracleTime, err := pair.Median.Age(ctx)
	if err != nil {
		return nil, err
	}
	oraclePrice, err := pair.Median.Price(ctx)
	if err != nil {
		return nil, err
	}

	// Clear expired prices:
	pair.store.clearOlderThan(time.Now().Add(-1 * pair.PriceExpiration))
	pair.store.clearOlderThan(oracleTime)

	// Use only a minimum prices required to achieve a quorum:
	pair.store.truncate(oracleQuorum)

	// Check if there are enough prices to achieve a quorum:
	if pair.store.len() != oracleQuorum {
		return nil, fmt.Errorf(
			"unable to update the %s oracle, there is not enough prices to achieve a quorum (%d/%d)",
			assetPair,
			pair.store.len(),
			oracleQuorum,
		)
	}

	spread := pair.store.spread(oraclePrice)
	isExpired := oracleTime.Add(pair.OracleExpiration).Before(time.Now())
	isStale := spread >= pair.OracleSpread

	r.logger.Debug(LoggerTag, "Updating Oracle for %s", assetPair)
	r.logger.Debug(LoggerTag, "Bar: %d", oracleQuorum)
	r.logger.Debug(LoggerTag, "Age: %s", oracleTime.String())
	r.logger.Debug(LoggerTag, "Val: %s", oraclePrice.String())
	r.logger.Debug(LoggerTag, "Expired: %v (current: %s, min: %s)", isExpired, time.Now().Sub(oracleTime), pair.OracleExpiration.String())
	r.logger.Debug(LoggerTag, "Stale: %v (current: %.1f, min: %.1f)", isStale, spread, pair.OracleSpread)
	for n, price := range pair.store.get() {
		r.logger.Debug(LoggerTag, "Price #%d: %s", n+1, price.String())
	}

	if isExpired || isStale {
		// Send *actual* transaction to the Ethereum network:
		tx, err := pair.Median.Poke(ctx, pair.store.get(), true)
		// There is no point in keeping the prices that have already been sent,
		// so we can safely remove them:
		pair.store.clear()
		return tx, err
	}

	// There is no need to update Oracle:
	return nil, nil
}

// collectorLoop creates a asynchronous loop which fetches prices from feeders.
func (r *Relayer) collectorLoop() error {
	err := r.transport.Subscribe(messages.PriceMessageName)
	if err != nil {
		return err
	}

	go func() {
		for {
			price := &messages.Price{}
			select {
			case <-r.doneCh:
				return
			case status := <-r.transport.WaitFor(messages.PriceMessageName, price):
				if status.Error != nil {
					r.logger.Warn(LoggerTag, "Unable to read prices from the network: %s", status.Error)
					continue
				}
				err := r.collect(price.Price)
				if err != nil {
					r.logger.Warn(LoggerTag, "Received invalid price: %s", err)
				} else {
					from, _ := price.Price.From() // the price was already validated, so an error can't occur here
					r.logger.Info(LoggerTag, "Received price (pair: %s, from: %s, price: %s, age: %s)", price.Price.AssetPair, from.String(), price.Price.Val.String(), price.Price.Age.String())
				}
			}
		}
	}()

	return nil
}

// collectorLoop creates a asynchronous loop which tries to send an update
// to an Oracle contract at a specified interval.
func (r *Relayer) relayerLoop() {
	ticker := time.NewTicker(r.interval)
	go func() {
		for {
			select {
			case <-r.doneCh:
				ticker.Stop()
				return
			case <-ticker.C:
				for assetPair, _ := range r.pairs {
					r.mu.Lock()
					tx, err := r.relay(assetPair)
					if err != nil {
						r.logger.Warn(LoggerTag, "Unable to update Oracle: %s", err)
					} else if tx == nil {
						r.logger.Info(LoggerTag, "Oracle price is still valid (pair: %s)", assetPair)
					} else {
						r.logger.Info(LoggerTag, "Oracle updated (tx: %s, pair: %s)", tx.String(), assetPair)
					}
					r.mu.Unlock()
				}
			}
		}
	}()
}

func (r *Relayer) isFeedAllowed(address common.Address) bool {
	for _, a := range r.feeds {
		if a == address {
			return true
		}
	}
	return false
}
