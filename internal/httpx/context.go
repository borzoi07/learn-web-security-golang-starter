package httpx

import (
	"context"
	"uuid"
)

type contextKey string

const cspNonceContextKey contextKey = "csp-nonce"

func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceContextKey, nonce)
}

func CSPNonce(ctx context.Context) string {
	nonce, _ := ctx.Value(cspNonceContextKey).(string)
	return nonce
}

type UUIDKey string

const keyUUID UUIDKey = "uuid-key"

func WithUUID(ctx context.Context, UUID uuid.UUID) context.Context {
	return context.WithValue(ctx, keyUUID, UUID)
}

func GetCtxUUID(ctx context.Context) uuid.UUID {
	uuid, _ := ctx.Value(keyUUID).(uuid.UUID) // doesn't panic because of second `, _` value. If type doesn't match becomes zero value
	return uuid
}
