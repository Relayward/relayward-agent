package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
)

func (store *Store) Desired(now time.Time) ([]DesiredService, []DesiredBlocks, error) {
	if err := store.refresh(now); err != nil {
		return nil, nil, err
	}
	var services []DesiredService
	var blocks []DesiredBlocks
	err := store.db.Update(func(tx *bolt.Tx) error {
		policies, err := readPolicies(tx)
		if err != nil {
			return err
		}
		generation := readUint64(tx.Bucket(bucketMeta).Get(keyGeneration))
		if generation == 0 {
			return nil
		}
		desiredServices := tx.Bucket(bucketDesiredServices)
		pluginBlocks := make(map[string][]*nodepluginv1.DynamicBlock)
		pluginSet := make(map[string]struct{})
		for _, policy := range policies {
			ledger, err := ensureLedger(tx, policy, now)
			if err != nil {
				return err
			}
			enabled, reason := enforcementState(policy, ledger, now)
			for _, binding := range policy.Bindings {
				key := serviceKey(binding.PluginID, policy.AuthorizationID, binding.ServiceID)
				desired, err := ensureDesiredService(tx, desiredServices, key, desiredServiceState{
					PluginID: binding.PluginID, AuthorizationID: policy.AuthorizationID, ServiceID: binding.ServiceID,
					PolicyGeneration: generation, Enabled: enabled, Reason: reason,
				})
				if err != nil {
					return err
				}
				service := publicDesiredService(desired)
				service.RequiresSoftIP = policy.SoftIPLimit != nil
				services = append(services, service)
			}
			if policy.SoftIPLimit != nil {
				for _, binding := range policy.Bindings {
					pluginSet[binding.PluginID] = struct{}{}
				}
				if err := appendPolicyBlocks(tx, policy, pluginBlocks, now); err != nil {
					return err
				}
			}
		}
		orphans := tx.Bucket(bucketOrphanBindings)
		if err := orphans.ForEach(func(key, raw []byte) error {
			var orphan desiredServiceState
			if err := json.Unmarshal(raw, &orphan); err != nil {
				return err
			}
			orphan.PolicyGeneration = generation
			orphan.Enabled = false
			orphan.Reason = nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_ADMINISTRATOR_DISABLED
			desired, err := ensureDesiredService(tx, desiredServices, string(key), orphan)
			if err != nil {
				return err
			}
			services = append(services, publicDesiredService(desired))
			return nil
		}); err != nil {
			return err
		}
		if err := tx.Bucket(bucketDesiredBlocks).ForEach(func(key, _ []byte) error {
			pluginSet[string(key)] = struct{}{}
			return nil
		}); err != nil {
			return err
		}
		for pluginID := range pluginSet {
			request, err := ensureDesiredBlocks(tx, pluginID, generation, pluginBlocks[pluginID])
			if err != nil {
				return err
			}
			blocks = append(blocks, DesiredBlocks{PluginID: pluginID, Request: request})
		}
		return nil
	})
	sort.Slice(services, func(i, j int) bool { return services[i].Key < services[j].Key })
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].PluginID < blocks[j].PluginID })
	return services, blocks, err
}

func (store *Store) ServiceNeedsApply(value DesiredService, instanceID string) (bool, error) {
	var applied appliedServiceState
	err := store.db.View(func(tx *bolt.Tx) error {
		_, err := getJSON(tx.Bucket(bucketAppliedServices), []byte(value.Key), &applied)
		return err
	})
	if err != nil {
		return false, err
	}
	desired := desiredServiceFromRequest(value.PluginID, value.Request, value.Orphan)
	return applied.InstanceID != instanceID || !sameDesiredService(applied.Desired, desired), nil
}

func (store *Store) MarkServiceApplied(value DesiredService, instanceID string) error {
	desired := desiredServiceFromRequest(value.PluginID, value.Request, value.Orphan)
	return store.db.Update(func(tx *bolt.Tx) error {
		var current desiredServiceState
		exists, err := getJSON(tx.Bucket(bucketDesiredServices), []byte(value.Key), &current)
		if err != nil {
			return err
		}
		if !exists || !sameDesiredService(current, desired) {
			return errors.New("desired service state changed while applying")
		}
		if err := putJSON(tx.Bucket(bucketAppliedServices), []byte(value.Key), appliedServiceState{
			InstanceID: instanceID, Desired: desired,
		}); err != nil {
			return err
		}
		if value.Orphan {
			if err := tx.Bucket(bucketOrphanBindings).Delete([]byte(value.Key)); err != nil {
				return err
			}
			if err := tx.Bucket(bucketDesiredServices).Delete([]byte(value.Key)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *Store) BlocksNeedApply(value DesiredBlocks, instanceID string) (bool, error) {
	var applied appliedBlockState
	err := store.db.View(func(tx *bolt.Tx) error {
		_, err := getJSON(tx.Bucket(bucketAppliedBlocks), []byte(value.PluginID), &applied)
		return err
	})
	if err != nil {
		return false, err
	}
	desired := desiredBlockFromRequest(value.PluginID, value.Request)
	return applied.InstanceID != instanceID || !sameDesiredBlocks(applied.Desired, desired), nil
}

func (store *Store) MarkBlocksApplied(value DesiredBlocks, instanceID string) error {
	desired := desiredBlockFromRequest(value.PluginID, value.Request)
	return store.db.Update(func(tx *bolt.Tx) error {
		var current desiredBlockState
		exists, err := getJSON(tx.Bucket(bucketDesiredBlocks), []byte(value.PluginID), &current)
		if err != nil {
			return err
		}
		if !exists || !sameDesiredBlocks(current, desired) {
			return errors.New("desired block state changed while applying")
		}
		return putJSON(tx.Bucket(bucketAppliedBlocks), []byte(value.PluginID), appliedBlockState{
			InstanceID: instanceID, Desired: desired,
		})
	})
}

func (store *Store) RefreshStatuses(now time.Time, instances map[string]string) error {
	if err := store.refresh(now); err != nil {
		return err
	}
	return store.db.Update(func(tx *bolt.Tx) error {
		generation := readUint64(tx.Bucket(bucketMeta).Get(keyGeneration))
		if generation == 0 {
			return nil
		}
		policies, err := readPolicies(tx)
		if err != nil {
			return err
		}
		for _, policy := range policies {
			applied, err := authorizationApplied(tx, policy, instances)
			if err != nil {
				return err
			}
			if !applied {
				continue
			}
			ledger, err := ensureLedger(tx, policy, now)
			if err != nil {
				return err
			}
			enabled, reason := enforcementState(policy, ledger, now)
			activeCount, blockedCount, err := activityCounts(tx, policy)
			if err != nil {
				return err
			}
			if err := updateStatus(tx, generation, policy, ledger, enabled, reason, activeCount, blockedCount); err != nil {
				return err
			}
		}
		return nil
	})
}

func authorizationApplied(tx *bolt.Tx, policy agentv1.AuthorizationPolicy, instances map[string]string) (bool, error) {
	ready := true
	if err := tx.Bucket(bucketOrphanBindings).ForEach(func(_, raw []byte) error {
		var orphan desiredServiceState
		if err := json.Unmarshal(raw, &orphan); err != nil {
			return err
		}
		if orphan.AuthorizationID == policy.AuthorizationID {
			ready = false
		}
		return nil
	}); err != nil || !ready {
		return ready, err
	}
	checkedBlocks := make(map[string]struct{})
	for _, binding := range policy.Bindings {
		instanceID := instances[binding.PluginID]
		if instanceID == "" {
			return false, nil
		}
		key := serviceKey(binding.PluginID, policy.AuthorizationID, binding.ServiceID)
		var desired desiredServiceState
		exists, err := getJSON(tx.Bucket(bucketDesiredServices), []byte(key), &desired)
		if err != nil || !exists {
			return false, err
		}
		var applied appliedServiceState
		exists, err = getJSON(tx.Bucket(bucketAppliedServices), []byte(key), &applied)
		if err != nil || !exists || applied.InstanceID != instanceID || !sameDesiredService(applied.Desired, desired) {
			return false, err
		}
		if _, checked := checkedBlocks[binding.PluginID]; checked {
			continue
		}
		checkedBlocks[binding.PluginID] = struct{}{}
		var desiredBlocks desiredBlockState
		exists, err = getJSON(tx.Bucket(bucketDesiredBlocks), []byte(binding.PluginID), &desiredBlocks)
		if err != nil {
			return false, err
		}
		if !exists {
			continue
		}
		var appliedBlocks appliedBlockState
		exists, err = getJSON(tx.Bucket(bucketAppliedBlocks), []byte(binding.PluginID), &appliedBlocks)
		if err != nil || !exists || appliedBlocks.InstanceID != instanceID || !sameDesiredBlocks(appliedBlocks.Desired, desiredBlocks) {
			return false, err
		}
	}
	return true, nil
}

func enforcementState(policy agentv1.AuthorizationPolicy, ledger ledgerState, now time.Time) (bool, nodepluginv1.ServiceStateReason) {
	if !policy.Enabled {
		return false, nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_ADMINISTRATOR_DISABLED
	}
	if policy.ExpiresAt != nil && !now.Before(*policy.ExpiresAt) {
		return false, nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_EXPIRED
	}
	if policy.TrafficLimitBytes != nil {
		limit := *policy.TrafficLimitBytes
		if ledger.UploadBytes >= limit || ledger.DownloadBytes >= limit-ledger.UploadBytes {
			return false, nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_QUOTA_EXCEEDED
		}
	}
	return true, nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_ACTIVE
}

func ensureDesiredService(tx *bolt.Tx, bucket *bolt.Bucket, key string, value desiredServiceState) (desiredServiceState, error) {
	var current desiredServiceState
	exists, err := getJSON(bucket, []byte(key), &current)
	if err != nil {
		return desiredServiceState{}, err
	}
	if !exists || current.PolicyGeneration != value.PolicyGeneration || current.Enabled != value.Enabled ||
		current.Reason != value.Reason || current.Orphan != value.Orphan {
		revision, err := nextRevision(tx.Bucket(bucketMeta), keyStateRevision)
		if err != nil {
			return desiredServiceState{}, err
		}
		value.StateRevision = revision
		if err := putJSON(bucket, []byte(key), value); err != nil {
			return desiredServiceState{}, err
		}
		return value, nil
	}
	return current, nil
}

func publicDesiredService(value desiredServiceState) DesiredService {
	return DesiredService{
		PluginID: value.PluginID, Key: serviceKey(value.PluginID, value.AuthorizationID, value.ServiceID), Orphan: value.Orphan,
		Request: &nodepluginv1.SetServiceStateRequest{
			PolicyGeneration: value.PolicyGeneration, StateRevision: value.StateRevision,
			AuthorizationId: value.AuthorizationID, ServiceId: value.ServiceID, Enabled: value.Enabled, Reason: value.Reason,
		},
	}
}

func desiredServiceFromRequest(pluginID string, request *nodepluginv1.SetServiceStateRequest, orphan bool) desiredServiceState {
	return desiredServiceState{
		PluginID: pluginID, AuthorizationID: request.AuthorizationId, ServiceID: request.ServiceId,
		PolicyGeneration: request.PolicyGeneration, StateRevision: request.StateRevision,
		Enabled: request.Enabled, Reason: request.Reason, Orphan: orphan,
	}
}

func sameDesiredService(first, second desiredServiceState) bool {
	return first.PluginID == second.PluginID && first.AuthorizationID == second.AuthorizationID &&
		first.ServiceID == second.ServiceID && first.PolicyGeneration == second.PolicyGeneration &&
		first.StateRevision == second.StateRevision && first.Enabled == second.Enabled &&
		first.Reason == second.Reason && first.Orphan == second.Orphan
}

func appendPolicyBlocks(tx *bolt.Tx, policy agentv1.AuthorizationPolicy, destination map[string][]*nodepluginv1.DynamicBlock, now time.Time) error {
	prefix := []byte(policy.AuthorizationID + "\x00")
	cursor := tx.Bucket(bucketBlocks).Cursor()
	for key, raw := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, raw = cursor.Next() {
		var state blockState
		if err := json.Unmarshal(raw, &state); err != nil {
			return err
		}
		if !state.ExpiresAt.After(now) {
			continue
		}
		sourceIP := strings.TrimPrefix(string(key), policy.AuthorizationID+"\x00")
		for _, binding := range policy.Bindings {
			destination[binding.PluginID] = append(destination[binding.PluginID], &nodepluginv1.DynamicBlock{
				AuthorizationId: policy.AuthorizationID, ServiceId: binding.ServiceID, SourceIp: sourceIP,
				ExpiresAtUnixNano: state.ExpiresAt.UnixNano(),
			})
		}
	}
	return nil
}

func ensureDesiredBlocks(tx *bolt.Tx, pluginID string, generation uint64, blocks []*nodepluginv1.DynamicBlock) (*nodepluginv1.ReplaceDynamicBlocksRequest, error) {
	sort.Slice(blocks, func(i, j int) bool {
		first, second := blocks[i], blocks[j]
		if first.AuthorizationId != second.AuthorizationId {
			return first.AuthorizationId < second.AuthorizationId
		}
		if first.ServiceId != second.ServiceId {
			return first.ServiceId < second.ServiceId
		}
		return first.SourceIp < second.SourceIp
	})
	digest, err := objectDigest(blocks)
	if err != nil {
		return nil, err
	}
	bucket := tx.Bucket(bucketDesiredBlocks)
	var current desiredBlockState
	exists, err := getJSON(bucket, []byte(pluginID), &current)
	if err != nil {
		return nil, err
	}
	if !exists || current.PolicyGeneration != generation || current.Digest != digest {
		revision, err := nextRevision(tx.Bucket(bucketMeta), keyBlockRevision)
		if err != nil {
			return nil, err
		}
		current = desiredBlockState{
			PluginID: pluginID, PolicyGeneration: generation, BlockRevision: revision,
			Digest: digest, Blocks: blocks,
		}
		if err := putJSON(bucket, []byte(pluginID), current); err != nil {
			return nil, err
		}
	}
	return &nodepluginv1.ReplaceDynamicBlocksRequest{
		PolicyGeneration: current.PolicyGeneration, BlockRevision: current.BlockRevision, Blocks: current.Blocks,
	}, nil
}

func desiredBlockFromRequest(pluginID string, request *nodepluginv1.ReplaceDynamicBlocksRequest) desiredBlockState {
	digest, _ := objectDigest(request.Blocks)
	return desiredBlockState{
		PluginID: pluginID, PolicyGeneration: request.PolicyGeneration,
		BlockRevision: request.BlockRevision, Digest: digest, Blocks: request.Blocks,
	}
}

func sameDesiredBlocks(first, second desiredBlockState) bool {
	return first.PluginID == second.PluginID && first.PolicyGeneration == second.PolicyGeneration &&
		first.BlockRevision == second.BlockRevision && first.Digest == second.Digest
}

func updateStatus(tx *bolt.Tx, generation uint64, policy agentv1.AuthorizationPolicy, ledger ledgerState,
	enabled bool, reason nodepluginv1.ServiceStateReason, activeCount, blockedCount uint32,
) error {
	event := agentv1.PolicyStatusEvent{
		Generation: generation, AuthorizationID: policy.AuthorizationID, Period: ledger.Period,
		UploadBytes: ledger.UploadBytes, DownloadBytes: ledger.DownloadBytes,
		ServicesEnabled: enabled, Reason: agentPolicyReason(reason),
		ActiveIPCount: activeCount, BlockedIPCount: blockedCount,
	}
	if err := agentv1.ValidatePolicyStatusEvent(event); err != nil {
		return err
	}
	digest, err := objectDigest(event)
	if err != nil {
		return err
	}
	bucket := tx.Bucket(bucketStatuses)
	var current statusState
	exists, err := getJSON(bucket, []byte(policy.AuthorizationID), &current)
	if err != nil {
		return err
	}
	if !exists || current.Digest != digest {
		return putJSON(bucket, []byte(policy.AuthorizationID), statusState{Digest: digest, Event: event})
	}
	return nil
}

func agentPolicyReason(value nodepluginv1.ServiceStateReason) string {
	switch value {
	case nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_ACTIVE:
		return agentv1.PolicyReasonActive
	case nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_ADMINISTRATOR_DISABLED:
		return agentv1.PolicyReasonDisabled
	case nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_EXPIRED:
		return agentv1.PolicyReasonExpired
	default:
		return agentv1.PolicyReasonQuotaExceeded
	}
}

func activityCounts(tx *bolt.Tx, policy agentv1.AuthorizationPolicy) (uint32, uint32, error) {
	if policy.SoftIPLimit == nil {
		return 0, 0, nil
	}
	count := func(bucket *bolt.Bucket) (uint32, error) {
		var result uint32
		prefix := []byte(policy.AuthorizationID + "\x00")
		cursor := bucket.Cursor()
		for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
			if result == math.MaxUint32 {
				return 0, errors.New("activity count overflow")
			}
			result++
		}
		return result, nil
	}
	active, err := count(tx.Bucket(bucketSlots))
	if err != nil {
		return 0, 0, err
	}
	blocked, err := count(tx.Bucket(bucketBlocks))
	return active, blocked, err
}
