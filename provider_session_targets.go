package auth

import (
	"fmt"
	"strings"
)

type TokenTargetRegistry struct {
	targets map[string]TokenTarget
}

func NewTokenTargetRegistry(targets ...TokenTarget) (*TokenTargetRegistry, error) {
	registry := &TokenTargetRegistry{targets: make(map[string]TokenTarget, len(targets))}
	for _, target := range targets {
		target.Name = strings.TrimSpace(target.Name)
		target.Provider = strings.TrimSpace(target.Provider)
		target.Issuer = strings.TrimRight(strings.TrimSpace(target.Issuer), "/")
		target.ClientID = strings.TrimSpace(target.ClientID)
		target.Audience = strings.TrimSpace(target.Audience)
		target.Resource = strings.TrimSpace(target.Resource)
		target.TelemetryName = strings.TrimSpace(target.TelemetryName)
		target.RequiredScopes = compactStrings(target.RequiredScopes)
		if target.Name == "" || target.Provider == "" || target.Issuer == "" ||
			target.ClientID == "" || (target.Audience == "" && target.Resource == "") ||
			target.TelemetryName == "" || !target.Capability.valid() {
			return nil, fmt.Errorf("%w: incomplete target %q", ErrProviderTokenTarget, target.Name)
		}
		if _, exists := registry.targets[target.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate target %q", ErrProviderTokenTarget, target.Name)
		}
		registry.targets[target.Name] = cloneTokenTarget(target)
	}
	return registry, nil
}

func (r *TokenTargetRegistry) Resolve(name string, capability TokenTargetCapability) (TokenTarget, error) {
	if r == nil || !capability.valid() {
		return TokenTarget{}, ErrProviderTokenTarget
	}
	target, ok := r.targets[strings.TrimSpace(name)]
	if !ok || target.Capability.id != capability.id {
		return TokenTarget{}, ErrProviderTokenTarget
	}
	return cloneTokenTarget(target), nil
}

func cloneTokenTarget(target TokenTarget) TokenTarget {
	target.RequiredScopes = append([]string(nil), target.RequiredScopes...)
	return target
}
