package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/contract"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	policyv1 "github.com/Relayward/relayward-sdk/policy/v1"
)

const stateVersion = "relayward.agent-policy-state/v1"

var (
	ErrGenerationConflict = errors.New("policy generation conflicts with durable state")
	ErrStaleGeneration    = errors.New("policy generation is older than durable state")

	bucketMeta            = []byte("meta")
	bucketPolicies        = []byte("policies")
	bucketOrphanBindings  = []byte("orphan-bindings")
	bucketCounters        = []byte("counters")
	bucketLedgers         = []byte("ledgers")
	bucketPendingTraffic  = []byte("pending-traffic")
	bucketCursors         = []byte("telemetry-cursors")
	bucketSlots           = []byte("ip-slots")
	bucketBlocks          = []byte("ip-blocks")
	bucketDesiredServices = []byte("desired-services")
	bucketAppliedServices = []byte("applied-services")
	bucketDesiredBlocks   = []byte("desired-blocks")
	bucketAppliedBlocks   = []byte("applied-blocks")
	bucketStatuses        = []byte("policy-statuses")

	keyStateVersion   = []byte("state-version")
	keyGeneration     = []byte("generation")
	keySnapshotDigest = []byte("snapshot-digest")
	keyStateRevision  = []byte("state-revision")
	keyBlockRevision  = []byte("block-revision")
)

type Store struct {
	db *bolt.DB
}

type counterState struct {
	Epoch         string
	UploadBytes   uint64
	DownloadBytes uint64
}

type ledgerState struct {
	AuthorizationID string
	Period          policyv1.Period
	Revision        uint64
	QueuedRevision  uint64
	UploadBytes     uint64
	DownloadBytes   uint64
}

type slotState struct {
	LastSeenAt time.Time
}

type blockState struct {
	ExpiresAt time.Time
}

type telemetryCursorState struct {
	StreamID string
	Sequence uint64
}

var telemetryStreamPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type desiredServiceState struct {
	PluginID         string
	AuthorizationID  string
	ServiceID        string
	PolicyGeneration uint64
	StateRevision    uint64
	Enabled          bool
	Reason           nodepluginv1.ServiceStateReason
	Orphan           bool
}

type appliedServiceState struct {
	InstanceID string
	Desired    desiredServiceState
}

type desiredBlockState struct {
	PluginID         string
	PolicyGeneration uint64
	BlockRevision    uint64
	Digest           string
	Blocks           []*nodepluginv1.DynamicBlock
}

type appliedBlockState struct {
	InstanceID string
	Desired    desiredBlockState
}

type statusState struct {
	Digest string
	Queued bool
	Event  agentv1.PolicyStatusEvent
}

type DesiredService struct {
	PluginID       string
	Key            string
	Request        *nodepluginv1.SetServiceStateRequest
	Orphan         bool
	RequiresSoftIP bool
}

type DesiredBlocks struct {
	PluginID string
	Request  *nodepluginv1.ReplaceDynamicBlocksRequest
}

func Open(path string) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("policy state path must be absolute and clean")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create policy state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("protect policy state directory: %w", err)
	}
	database, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open policy state: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		database.Close()
		return nil, fmt.Errorf("protect policy state: %w", err)
	}
	store := &Store{db: database}
	if err := store.initialize(); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	return store.db.Close()
}

func (store *Store) Reconcile(value agentv1.PolicyReconcileCommand) (bool, error) {
	if err := agentv1.ValidatePolicyReconcileCommand(value); err != nil {
		return false, err
	}
	digestText, err := objectDigest(value)
	if err != nil {
		return false, fmt.Errorf("encode policy snapshot: %w", err)
	}
	changed := false
	err = store.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		generation := readUint64(meta.Get(keyGeneration))
		switch {
		case value.Generation < generation:
			return ErrStaleGeneration
		case value.Generation == generation:
			if string(meta.Get(keySnapshotDigest)) != digestText {
				return ErrGenerationConflict
			}
			return nil
		}
		oldPolicies, err := readPolicies(tx)
		if err != nil {
			return err
		}
		newBindings := make(map[string]struct{})
		for _, policy := range value.Authorizations {
			for _, binding := range policy.Bindings {
				newBindings[serviceKey(binding.PluginID, policy.AuthorizationID, binding.ServiceID)] = struct{}{}
			}
		}
		orphans := tx.Bucket(bucketOrphanBindings)
		for key := range newBindings {
			if err := orphans.Delete([]byte(key)); err != nil {
				return err
			}
		}
		for _, policy := range oldPolicies {
			for _, binding := range policy.Bindings {
				key := serviceKey(binding.PluginID, policy.AuthorizationID, binding.ServiceID)
				if _, retained := newBindings[key]; retained {
					continue
				}
				if err := putJSON(orphans, []byte(key), desiredServiceState{
					PluginID: binding.PluginID, AuthorizationID: policy.AuthorizationID,
					ServiceID: binding.ServiceID, Orphan: true,
				}); err != nil {
					return err
				}
			}
		}
		policies := tx.Bucket(bucketPolicies)
		if err := clearBucket(policies); err != nil {
			return err
		}
		for _, policy := range value.Authorizations {
			if err := putJSON(policies, []byte(policy.AuthorizationID), policy); err != nil {
				return err
			}
		}
		if err := deleteRemovedAuthorizationState(tx, value.Authorizations); err != nil {
			return err
		}
		if err := putUint64(meta, keyGeneration, value.Generation); err != nil {
			return err
		}
		if err := meta.Put(keySnapshotDigest, []byte(digestText)); err != nil {
			return err
		}
		changed = true
		return nil
	})
	return changed, err
}

func (store *Store) Generation() (uint64, error) {
	var value uint64
	err := store.db.View(func(tx *bolt.Tx) error {
		value = readUint64(tx.Bucket(bucketMeta).Get(keyGeneration))
		return nil
	})
	return value, err
}

func (store *Store) BindingKnown(pluginID, authorizationID, serviceID string) (bool, error) {
	if err := contract.ValidatePluginID(pluginID); err != nil {
		return false, err
	}
	if err := policyv1.ValidateIdentifier("authorization_id", authorizationID); err != nil {
		return false, err
	}
	known := false
	err := store.db.View(func(tx *bolt.Tx) error {
		var policy agentv1.AuthorizationPolicy
		exists, err := getJSON(tx.Bucket(bucketPolicies), []byte(authorizationID), &policy)
		if err != nil || !exists {
			return err
		}
		for _, binding := range policy.Bindings {
			if binding.PluginID == pluginID && binding.ServiceID == serviceID {
				known = true
				break
			}
		}
		return nil
	})
	return known, err
}

func (store *Store) TelemetryCursor(pluginID, streamID string) (uint64, error) {
	if err := contract.ValidatePluginID(pluginID); err != nil {
		return 0, err
	}
	if !telemetryStreamPattern.MatchString(streamID) {
		return 0, errors.New("telemetry stream ID is invalid")
	}
	var value uint64
	err := store.db.View(func(tx *bolt.Tx) error {
		var current telemetryCursorState
		exists, err := getJSON(tx.Bucket(bucketCursors), []byte(pluginID), &current)
		if err != nil || !exists || current.StreamID != streamID {
			return err
		}
		value = current.Sequence
		return nil
	})
	return value, err
}

func (store *Store) AdvanceTelemetryCursor(pluginID, streamID string, previous, next uint64) error {
	if err := contract.ValidatePluginID(pluginID); err != nil {
		return err
	}
	if !telemetryStreamPattern.MatchString(streamID) {
		return errors.New("telemetry stream ID is invalid")
	}
	if next < previous || next > math.MaxInt64 {
		return errors.New("telemetry cursor is invalid")
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketCursors)
		var current telemetryCursorState
		exists, err := getJSON(bucket, []byte(pluginID), &current)
		if err != nil {
			return err
		}
		if exists && current.StreamID == streamID && current.Sequence != previous {
			return errors.New("telemetry cursor changed concurrently")
		}
		if exists && current.StreamID != streamID && previous != 0 {
			return errors.New("telemetry stream changed concurrently")
		}
		return putJSON(bucket, []byte(pluginID), telemetryCursorState{StreamID: streamID, Sequence: next})
	})
}

func (store *Store) ApplyCounters(pluginID string, counters []*nodepluginv1.TrafficCounter, now time.Time) error {
	if err := contract.ValidatePluginID(pluginID); err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("counter observation time is required")
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		policies, err := readPolicies(tx)
		if err != nil {
			return err
		}
		byAuthorization := make(map[string]agentv1.AuthorizationPolicy)
		bindings := make(map[string]struct{})
		for _, policy := range policies {
			byAuthorization[policy.AuthorizationID] = policy
			for _, binding := range policy.Bindings {
				bindings[serviceKey(binding.PluginID, policy.AuthorizationID, binding.ServiceID)] = struct{}{}
			}
		}
		type trafficDelta struct{ upload, download uint64 }
		deltas := make(map[string]trafficDelta)
		counterBucket := tx.Bucket(bucketCounters)
		for _, counter := range counters {
			if counter == nil {
				continue
			}
			if counter.UploadBytes > math.MaxInt64 || counter.DownloadBytes > math.MaxInt64 {
				return errors.New("traffic counter exceeds durable ledger capacity")
			}
			key := serviceKey(pluginID, counter.AuthorizationId, counter.ServiceId)
			if _, known := bindings[key]; !known {
				continue
			}
			var previous counterState
			exists, err := getJSON(counterBucket, []byte(key), &previous)
			if err != nil {
				return err
			}
			upload, download := counter.UploadBytes, counter.DownloadBytes
			if exists && previous.Epoch == counter.CounterEpoch && counter.UploadBytes >= previous.UploadBytes && counter.DownloadBytes >= previous.DownloadBytes {
				upload = counter.UploadBytes - previous.UploadBytes
				download = counter.DownloadBytes - previous.DownloadBytes
			}
			if err := putJSON(counterBucket, []byte(key), counterState{
				Epoch: counter.CounterEpoch, UploadBytes: counter.UploadBytes, DownloadBytes: counter.DownloadBytes,
			}); err != nil {
				return err
			}
			current := deltas[counter.AuthorizationId]
			if math.MaxUint64-current.upload < upload || math.MaxUint64-current.download < download {
				return errors.New("traffic delta overflow")
			}
			current.upload += upload
			current.download += download
			deltas[counter.AuthorizationId] = current
		}
		for authorizationID, delta := range deltas {
			if delta.upload == 0 && delta.download == 0 {
				continue
			}
			ledger, err := ensureLedger(tx, byAuthorization[authorizationID], now)
			if err != nil {
				return err
			}
			if uint64(math.MaxInt64)-ledger.UploadBytes < delta.upload || uint64(math.MaxInt64)-ledger.DownloadBytes < delta.download {
				return errors.New("traffic ledger overflow")
			}
			if ledger.Revision >= math.MaxInt64 {
				return errors.New("traffic ledger revision is exhausted")
			}
			ledger.UploadBytes += delta.upload
			ledger.DownloadBytes += delta.download
			ledger.Revision++
			if err := putJSON(tx.Bucket(bucketLedgers), []byte(authorizationID), ledger); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *Store) ObserveActivity(authorizationID, sourceIP string, observedAt time.Time) (bool, error) {
	if err := policyv1.ValidateIdentifier("authorization_id", authorizationID); err != nil {
		return false, err
	}
	parsed := net.ParseIP(sourceIP)
	if parsed == nil || parsed.String() != sourceIP {
		return false, errors.New("source IP must be canonical")
	}
	if observedAt.IsZero() {
		return false, errors.New("activity observation time is required")
	}
	blocked := false
	err := store.db.Update(func(tx *bolt.Tx) error {
		var policy agentv1.AuthorizationPolicy
		exists, err := getJSON(tx.Bucket(bucketPolicies), []byte(authorizationID), &policy)
		if err != nil || !exists || policy.SoftIPLimit == nil {
			return err
		}
		if err := cleanAuthorizationActivity(tx, policy, observedAt); err != nil {
			return err
		}
		key := activityKey(authorizationID, sourceIP)
		var existingBlock blockState
		if exists, err := getJSON(tx.Bucket(bucketBlocks), []byte(key), &existingBlock); err != nil {
			return err
		} else if exists && existingBlock.ExpiresAt.After(observedAt) {
			blocked = true
			return nil
		}
		slots := tx.Bucket(bucketSlots)
		var existingSlot slotState
		if exists, err := getJSON(slots, []byte(key), &existingSlot); err != nil {
			return err
		} else if exists {
			if observedAt.After(existingSlot.LastSeenAt) {
				return putJSON(slots, []byte(key), slotState{LastSeenAt: observedAt.UTC()})
			}
			return nil
		}
		count := 0
		prefix := []byte(authorizationID + "\x00")
		cursor := slots.Cursor()
		for candidate, _ := cursor.Seek(prefix); candidate != nil && bytes.HasPrefix(candidate, prefix); candidate, _ = cursor.Next() {
			count++
		}
		if count < int(*policy.SoftIPLimit) {
			return putJSON(slots, []byte(key), slotState{LastSeenAt: observedAt.UTC()})
		}
		expiresAt := observedAt.UTC().Add(time.Duration(policy.BlockDurationSeconds) * time.Second)
		if err := putJSON(tx.Bucket(bucketBlocks), []byte(key), blockState{ExpiresAt: expiresAt}); err != nil {
			return err
		}
		blocked = true
		return nil
	})
	return blocked, err
}

func (store *Store) PendingTrafficSnapshots(now time.Time) ([]agentv1.TrafficSnapshotEvent, error) {
	if err := store.refresh(now); err != nil {
		return nil, err
	}
	values := make([]agentv1.TrafficSnapshotEvent, 0)
	err := store.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketPendingTraffic).ForEach(func(_, raw []byte) error {
			var value agentv1.TrafficSnapshotEvent
			if err := json.Unmarshal(raw, &value); err != nil {
				return err
			}
			values = append(values, value)
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(bucketLedgers).ForEach(func(_, raw []byte) error {
			var ledger ledgerState
			if err := json.Unmarshal(raw, &ledger); err != nil {
				return err
			}
			if ledger.QueuedRevision < ledger.Revision {
				values = append(values, ledgerEvent(ledger))
			}
			return nil
		})
	})
	sort.Slice(values, func(i, j int) bool {
		if values[i].AuthorizationID != values[j].AuthorizationID {
			return values[i].AuthorizationID < values[j].AuthorizationID
		}
		return values[i].Period.StartsAt.Before(values[j].Period.StartsAt)
	})
	return values, err
}

func (store *Store) MarkTrafficQueued(value agentv1.TrafficSnapshotEvent) error {
	if err := agentv1.ValidateTrafficSnapshotEvent(value); err != nil {
		return err
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		pending := tx.Bucket(bucketPendingTraffic)
		key := trafficKey(value.AuthorizationID, value.Period.ID)
		var pendingValue agentv1.TrafficSnapshotEvent
		if exists, err := getJSON(pending, []byte(key), &pendingValue); err != nil {
			return err
		} else if exists {
			if !sameTrafficSnapshot(pendingValue, value) {
				return errors.New("traffic snapshot no longer matches pending state")
			}
			return pending.Delete([]byte(key))
		}
		bucket := tx.Bucket(bucketLedgers)
		var ledger ledgerState
		exists, err := getJSON(bucket, []byte(value.AuthorizationID), &ledger)
		if err != nil {
			return err
		}
		if !exists || ledger.Period.ID != value.Period.ID || ledger.Revision < value.Revision {
			return errors.New("traffic snapshot no longer matches the ledger")
		}
		if ledger.Revision == value.Revision && ledger.UploadBytes == value.UploadBytes && ledger.DownloadBytes == value.DownloadBytes {
			ledger.QueuedRevision = value.Revision
			return putJSON(bucket, []byte(value.AuthorizationID), ledger)
		}
		return nil
	})
}

func (store *Store) PendingStatuses() ([]agentv1.PolicyStatusEvent, error) {
	values := make([]agentv1.PolicyStatusEvent, 0)
	err := store.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketStatuses).ForEach(func(_, raw []byte) error {
			var state statusState
			if err := json.Unmarshal(raw, &state); err != nil {
				return err
			}
			if !state.Queued {
				values = append(values, state.Event)
			}
			return nil
		})
	})
	sort.Slice(values, func(i, j int) bool { return values[i].AuthorizationID < values[j].AuthorizationID })
	return values, err
}

func (store *Store) MarkStatusQueued(value agentv1.PolicyStatusEvent) error {
	if err := agentv1.ValidatePolicyStatusEvent(value); err != nil {
		return err
	}
	digest, err := objectDigest(value)
	if err != nil {
		return err
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketStatuses)
		var state statusState
		exists, err := getJSON(bucket, []byte(value.AuthorizationID), &state)
		if err != nil {
			return err
		}
		if exists && state.Digest == digest {
			state.Queued = true
			return putJSON(bucket, []byte(value.AuthorizationID), state)
		}
		return nil
	})
}

func (store *Store) refresh(now time.Time) error {
	if now.IsZero() {
		return errors.New("policy evaluation time is required")
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		policies, err := readPolicies(tx)
		if err != nil {
			return err
		}
		bucket := tx.Bucket(bucketPolicies)
		for _, policy := range policies {
			period, err := policyv1.CurrentPeriod(policy.Reset, policy.StartedAt, now)
			if err != nil {
				return err
			}
			if !policyv1.SamePeriod(period, policy.CurrentPeriod) {
				policy.CurrentPeriod = period
				if err := putJSON(bucket, []byte(policy.AuthorizationID), policy); err != nil {
					return err
				}
			}
			if _, err := ensureLedger(tx, policy, now); err != nil {
				return err
			}
			if err := cleanAuthorizationActivity(tx, policy, now); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *Store) initialize() error {
	return store.db.Update(func(tx *bolt.Tx) error {
		names := [][]byte{
			bucketMeta, bucketPolicies, bucketOrphanBindings, bucketCounters, bucketLedgers,
			bucketPendingTraffic, bucketCursors, bucketSlots, bucketBlocks, bucketDesiredServices, bucketAppliedServices,
			bucketDesiredBlocks, bucketAppliedBlocks, bucketStatuses,
		}
		for _, name := range names {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create policy state bucket: %w", err)
			}
		}
		meta := tx.Bucket(bucketMeta)
		version := string(meta.Get(keyStateVersion))
		if version == "" {
			return meta.Put(keyStateVersion, []byte(stateVersion))
		}
		if version != stateVersion {
			return fmt.Errorf("unsupported policy state version %q", version)
		}
		return nil
	})
}

func readPolicies(tx *bolt.Tx) ([]agentv1.AuthorizationPolicy, error) {
	values := make([]agentv1.AuthorizationPolicy, 0)
	err := tx.Bucket(bucketPolicies).ForEach(func(_, raw []byte) error {
		var value agentv1.AuthorizationPolicy
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("decode policy state: %w", err)
		}
		if err := agentv1.ValidateAuthorizationPolicy(value); err != nil {
			return fmt.Errorf("validate policy state: %w", err)
		}
		values = append(values, value)
		return nil
	})
	return values, err
}

func ensureLedger(tx *bolt.Tx, policy agentv1.AuthorizationPolicy, now time.Time) (ledgerState, error) {
	bucket := tx.Bucket(bucketLedgers)
	var ledger ledgerState
	exists, err := getJSON(bucket, []byte(policy.AuthorizationID), &ledger)
	if err != nil {
		return ledgerState{}, err
	}
	period, err := policyv1.CurrentPeriod(policy.Reset, policy.StartedAt, now)
	if err != nil {
		return ledgerState{}, err
	}
	if !exists || ledger.Period.ID != period.ID {
		if exists {
			if err := preservePendingTraffic(tx, ledger); err != nil {
				return ledgerState{}, err
			}
		}
		ledger = ledgerState{AuthorizationID: policy.AuthorizationID, Period: period, Revision: 1}
		if err := putJSON(bucket, []byte(policy.AuthorizationID), ledger); err != nil {
			return ledgerState{}, err
		}
	}
	return ledger, nil
}

func ledgerEvent(value ledgerState) agentv1.TrafficSnapshotEvent {
	return agentv1.TrafficSnapshotEvent{
		AuthorizationID: value.AuthorizationID, Period: value.Period, Revision: value.Revision,
		UploadBytes: value.UploadBytes, DownloadBytes: value.DownloadBytes,
	}
}

func cleanAuthorizationActivity(tx *bolt.Tx, policy agentv1.AuthorizationPolicy, now time.Time) error {
	prefix := []byte(policy.AuthorizationID + "\x00")
	cutoff := now.Add(-time.Duration(policy.ActivityWindowSeconds) * time.Second)
	if err := deleteMatching(tx.Bucket(bucketSlots), prefix, func(raw []byte) (bool, error) {
		var state slotState
		if err := json.Unmarshal(raw, &state); err != nil {
			return false, err
		}
		return !state.LastSeenAt.After(cutoff), nil
	}); err != nil {
		return err
	}
	return deleteMatching(tx.Bucket(bucketBlocks), prefix, func(raw []byte) (bool, error) {
		var state blockState
		if err := json.Unmarshal(raw, &state); err != nil {
			return false, err
		}
		return !state.ExpiresAt.After(now), nil
	})
}

func deleteRemovedAuthorizationState(tx *bolt.Tx, policies []agentv1.AuthorizationPolicy) error {
	retained := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		retained[policy.AuthorizationID] = struct{}{}
	}
	ledgers := tx.Bucket(bucketLedgers)
	ledgerCursor := ledgers.Cursor()
	for key, raw := ledgerCursor.First(); key != nil; key, raw = ledgerCursor.Next() {
		if _, ok := retained[string(key)]; ok {
			continue
		}
		var ledger ledgerState
		if err := json.Unmarshal(raw, &ledger); err != nil {
			return err
		}
		if err := preservePendingTraffic(tx, ledger); err != nil {
			return err
		}
		if err := ledgerCursor.Delete(); err != nil {
			return err
		}
	}
	statuses := tx.Bucket(bucketStatuses)
	statusCursor := statuses.Cursor()
	for key, _ := statusCursor.First(); key != nil; key, _ = statusCursor.Next() {
		if _, ok := retained[string(key)]; !ok {
			if err := statusCursor.Delete(); err != nil {
				return err
			}
		}
	}
	for _, name := range [][]byte{bucketSlots, bucketBlocks} {
		bucket := tx.Bucket(name)
		cursor := bucket.Cursor()
		for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
			authorizationID := string(key)
			if index := strings.IndexByte(authorizationID, 0); index >= 0 {
				authorizationID = authorizationID[:index]
			}
			if _, ok := retained[authorizationID]; !ok {
				if err := cursor.Delete(); err != nil {
					return err
				}
			}
		}
	}
	counterBucket := tx.Bucket(bucketCounters)
	cursor := counterBucket.Cursor()
	for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
		parts := strings.Split(string(key), "\x00")
		if len(parts) != 3 {
			return errors.New("invalid persisted traffic counter key")
		}
		if _, ok := retained[parts[1]]; !ok {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
	}
	return nil
}

func serviceKey(pluginID, authorizationID, serviceID string) string {
	return pluginID + "\x00" + authorizationID + "\x00" + serviceID
}

func activityKey(authorizationID, sourceIP string) string {
	return authorizationID + "\x00" + sourceIP
}

func trafficKey(authorizationID, periodID string) string {
	return authorizationID + "\x00" + periodID
}

func preservePendingTraffic(tx *bolt.Tx, ledger ledgerState) error {
	if ledger.QueuedRevision >= ledger.Revision {
		return nil
	}
	value := ledgerEvent(ledger)
	return putJSON(tx.Bucket(bucketPendingTraffic), []byte(trafficKey(value.AuthorizationID, value.Period.ID)), value)
}

func sameTrafficSnapshot(first, second agentv1.TrafficSnapshotEvent) bool {
	return first.AuthorizationID == second.AuthorizationID && policyv1.SamePeriod(first.Period, second.Period) &&
		first.Revision == second.Revision && first.UploadBytes == second.UploadBytes && first.DownloadBytes == second.DownloadBytes
}

func nextRevision(meta *bolt.Bucket, key []byte) (uint64, error) {
	current := readUint64(meta.Get(key))
	if current >= math.MaxInt64 {
		return 0, errors.New("policy state revision is exhausted")
	}
	current++
	return current, putUint64(meta, key, current)
}

func objectDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func putJSON(bucket *bolt.Bucket, key []byte, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return bucket.Put(key, raw)
}

func getJSON(bucket *bolt.Bucket, key []byte, destination any) (bool, error) {
	raw := bucket.Get(key)
	if raw == nil {
		return false, nil
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return false, err
	}
	return true, nil
}

func clearBucket(bucket *bolt.Bucket) error {
	cursor := bucket.Cursor()
	for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
		if err := cursor.Delete(); err != nil {
			return err
		}
	}
	return nil
}

func deleteMatching(bucket *bolt.Bucket, prefix []byte, predicate func([]byte) (bool, error)) error {
	cursor := bucket.Cursor()
	for key, raw := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, raw = cursor.Next() {
		remove, err := predicate(raw)
		if err != nil {
			return err
		}
		if remove {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
	}
	return nil
}

func readUint64(value []byte) uint64 {
	if len(value) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(value)
}

func putUint64(bucket *bolt.Bucket, key []byte, value uint64) error {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return bucket.Put(key, raw[:])
}
