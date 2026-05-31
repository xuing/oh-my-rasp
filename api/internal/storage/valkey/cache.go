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
	sessionPrefix      = "ohmyrasp:session:"
	agentPolicyPrefix  = "ohmyrasp:agent-policy:"
	policyCacheEpoch   = "ohmyrasp:agent-policy:epoch"
	rateLimitKeyPrefix = "ohmyrasp:ratelimit:"
)

type Cache struct {
	client valkeygo.Client
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
	return &Cache{client: client}, nil
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
	found, err := c.getJSON(ctx, sessionPrefix+tokenHash, &user)
	return user, found, err
}

func (c *Cache) SetSessionUser(ctx context.Context, tokenHash string, user control.User, ttl time.Duration) error {
	return c.setJSON(ctx, sessionPrefix+tokenHash, user, ttl)
}

func (c *Cache) DeleteSession(ctx context.Context, tokenHash string) error {
	return c.client.Do(ctx, c.client.B().Del().Key(sessionPrefix+tokenHash).Build()).Error()
}

func (c *Cache) GetAgentPolicy(ctx context.Context, agentID string) (control.PolicyVersion, bool, error) {
	var policy control.PolicyVersion
	epoch, err := c.policyEpoch(ctx)
	if err != nil {
		return control.PolicyVersion{}, false, err
	}
	found, err := c.getJSON(ctx, c.agentPolicyKey(epoch, agentID), &policy)
	return policy, found, err
}

func (c *Cache) SetAgentPolicy(ctx context.Context, agentID string, policy control.PolicyVersion, ttl time.Duration) error {
	epoch, err := c.policyEpoch(ctx)
	if err != nil {
		return err
	}
	return c.setJSON(ctx, c.agentPolicyKey(epoch, agentID), policy, ttl)
}

func (c *Cache) InvalidateAgentPolicies(ctx context.Context) error {
	return c.client.Do(ctx, c.client.B().Incr().Key(policyCacheEpoch).Build()).Error()
}

func (c *Cache) Allow(ctx context.Context, key string, limit int64, window time.Duration) (control.RateLimitDecision, error) {
	if limit <= 0 || window <= 0 {
		return control.RateLimitDecision{Allowed: true, Limit: limit, Remaining: math.MaxInt64}, nil
	}
	cacheKey := rateLimitKeyPrefix + key
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
	epoch, err := c.client.Do(ctx, c.client.B().Get().Key(policyCacheEpoch).Build()).ToString()
	if valkeygo.IsValkeyNil(err) {
		return "0", nil
	}
	return epoch, err
}

func (c *Cache) agentPolicyKey(epoch string, agentID string) string {
	return fmt.Sprintf("%s%s:%s", agentPolicyPrefix, epoch, agentID)
}

func maxInt64(left int64, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
