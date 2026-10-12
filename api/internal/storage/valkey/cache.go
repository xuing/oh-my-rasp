package valkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
	valkeygo "github.com/valkey-io/valkey-go"
)

const (
	keyRoot            = "ohmyrasp:"
	sessionPrefix      = "session:"
	agentPolicyPrefix  = "agent-policy:"
	policyCacheEpoch   = "agent-policy:epoch"
	rateLimitKeyPrefix = "ratelimit:"
)

type Cache struct {
	client valkeygo.Client
	// keyPrefix is prepended to every key: "ohmyrasp:" by default,
	// "ohmyrasp:<namespace>:" after WithKeyNamespace.
	keyPrefix string
}

func New(addr string, username string, password string) (*Cache, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("valkey address is required")
	}
	client, err := valkeygo.NewClient(valkeygo.ClientOption{
		InitAddress: []string{addr},
		Username:    username,
		Password:    password,
	})
	if err != nil {
		return nil, err
	}
	return &Cache{client: client, keyPrefix: keyRoot}, nil
}

// WithKeyNamespace scopes every key this cache reads or writes (sessions,
// cached agent policies, the policy invalidation epoch and rate-limit
// counters) under "ohmyrasp:<namespace>:", so independent users of one Valkey
// (e.g. concurrently running integration-test packages) cannot observe each
// other's invalidations. An empty namespace keeps the default "ohmyrasp:" keys.
func (c *Cache) WithKeyNamespace(namespace string) *Cache {
	namespace = strings.Trim(strings.TrimSpace(namespace), ":")
	if namespace == "" {
		c.keyPrefix = keyRoot
	} else {
		c.keyPrefix = keyRoot + namespace + ":"
	}
	return c
}

func (c *Cache) key(suffix string) string {
	return c.keyPrefix + suffix
}

func (c *Cache) Close() {
	if c != nil && c.client != nil {
		c.client.Close()
	}
}

func (c *Cache) Ping(ctx context.Context) error {
	return c.client.Do(ctx, c.client.B().Ping().Build()).Error()
}

func (c *Cache) GetSessionUser(ctx context.Context, tokenHash string) (control.User, bool, error) {
	var user control.User
	found, err := c.getJSON(ctx, c.key(sessionPrefix+tokenHash), &user)
	return user, found, err
}

func (c *Cache) SetSessionUser(ctx context.Context, tokenHash string, user control.User, ttl time.Duration) error {
	return c.setJSON(ctx, c.key(sessionPrefix+tokenHash), user, ttl)
}

func (c *Cache) DeleteSession(ctx context.Context, tokenHash string) error {
	return c.client.Do(ctx, c.client.B().Del().Key(c.key(sessionPrefix+tokenHash)).Build()).Error()
}

// GetAgentPolicy looks up the cached policy for agentID under the current
// invalidation epoch and also returns that epoch. On a miss, callers pass the
// epoch back to SetAgentPolicy so a value loaded from the database is stored
// under the epoch observed before the load: if an invalidation lands while the
// load runs, the (possibly stale) value goes to the retired epoch and is never
// served.
func (c *Cache) GetAgentPolicy(ctx context.Context, agentID string) (control.PolicyVersion, string, bool, error) {
	var policy control.PolicyVersion
	epoch, err := c.policyEpoch(ctx)
	if err != nil {
		return control.PolicyVersion{}, "", false, err
	}
	found, err := c.getJSON(ctx, c.agentPolicyKey(epoch, agentID), &policy)
	return policy, epoch, found, err
}

func (c *Cache) SetAgentPolicy(ctx context.Context, agentID string, epoch string, policy control.PolicyVersion, ttl time.Duration) error {
	return c.setJSON(ctx, c.agentPolicyKey(epoch, agentID), policy, ttl)
}

func (c *Cache) InvalidateAgentPolicies(ctx context.Context) error {
	return c.client.Do(ctx, c.client.B().Incr().Key(c.key(policyCacheEpoch)).Build()).Error()
}

func (c *Cache) Allow(ctx context.Context, key string, limit int64, window time.Duration) (control.RateLimitDecision, error) {
	if limit <= 0 || window <= 0 {
		return control.RateLimitDecision{Allowed: true, Limit: limit, Remaining: math.MaxInt64}, nil
	}
	cacheKey := c.key(rateLimitKeyPrefix + key)
	count, err := c.client.Do(ctx, c.client.B().Incr().Key(cacheKey).Build()).ToInt64()
	if err != nil {
		return control.RateLimitDecision{}, err
	}
	if count == 1 {
		_ = c.client.Do(ctx, c.client.B().Expire().Key(cacheKey).Seconds(maxInt64(1, int64(window/time.Second))).Build()).Error()
	}
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	return control.RateLimitDecision{
		Allowed:    count <= limit,
		Limit:      limit,
		Remaining:  remaining,
		RetryAfter: window,
	}, nil
}

func (c *Cache) getJSON(ctx context.Context, key string, out any) (bool, error) {
	value, err := c.client.Do(ctx, c.client.B().Get().Key(key).Build()).ToString()
	if valkeygo.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal([]byte(value), out); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Cache) setJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.client.Do(ctx, c.client.B().Set().Key(key).Value(string(body)).Ex(ttl).Build()).Error()
}

func (c *Cache) policyEpoch(ctx context.Context) (string, error) {
	epoch, err := c.client.Do(ctx, c.client.B().Get().Key(c.key(policyCacheEpoch)).Build()).ToString()
	if valkeygo.IsValkeyNil(err) {
		return "0", nil
	}
	return epoch, err
}

func (c *Cache) agentPolicyKey(epoch string, agentID string) string {
	return fmt.Sprintf("%s%s:%s", c.key(agentPolicyPrefix), epoch, agentID)
}

func maxInt64(left int64, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
