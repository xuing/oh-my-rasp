package httpapi

import (
	"context"
	"net/http"

	"github.com/ohmyrasp/control-plane/internal/control"
)

type userContextKey struct{}

func withUser(ctx context.Context, user control.User) context.Context {
	return context.WithValue(ctx, userContextKey{}, user)
}

func userFromRequest(r *http.Request) control.User {
	return userFromContext(r.Context())
}

func userFromContext(ctx context.Context) control.User {
	user, _ := ctx.Value(userContextKey{}).(control.User)
	return user
}
