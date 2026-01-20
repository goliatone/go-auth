package social

import (
	"errors"
	"fmt"

	goerrors "github.com/goliatone/go-errors"
)

// ProviderError captures normalized provider response details.
type ProviderError struct {
	Provider    string
	Operation   string
	Status      int
	Code        string
	Description string
	Err         error
	Raw         map[string]any
}

func (e *ProviderError) Error() string {
	if e == nil {
		return "provider error"
	}

	scope := "provider"
	if e.Provider != "" && e.Operation != "" {
		scope = fmt.Sprintf("%s %s", e.Provider, e.Operation)
	} else if e.Provider != "" {
		scope = e.Provider
	} else if e.Operation != "" {
		scope = e.Operation
	}

	if e.Description != "" {
		return fmt.Sprintf("%s failed: %s", scope, e.Description)
	}
	if e.Code != "" {
		return fmt.Sprintf("%s failed: %s", scope, e.Code)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s failed: %v", scope, e.Err)
	}

	return fmt.Sprintf("%s failed", scope)
}

func (e *ProviderError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ProviderError) Metadata() map[string]any {
	if e == nil {
		return nil
	}

	meta := map[string]any{}
	if e.Provider != "" {
		meta["provider"] = e.Provider
	}
	if e.Operation != "" {
		meta["operation"] = e.Operation
	}
	if e.Status != 0 {
		meta["status"] = e.Status
	}
	if e.Code != "" {
		meta["code"] = e.Code
	}
	if e.Description != "" {
		meta["description"] = e.Description
	}
	if len(e.Raw) > 0 {
		meta["raw"] = e.Raw
	}

	return meta
}

func wrapProviderError(base *goerrors.Error, provider, operation string, err error) error {
	if base == nil {
		return err
	}

	meta := map[string]any{}
	if provider != "" {
		meta["provider"] = provider
	}
	if operation != "" {
		meta["operation"] = operation
	}

	var perr *ProviderError
	if errors.As(err, &perr) && perr != nil {
		for k, v := range perr.Metadata() {
			meta[k] = v
		}
	} else if err != nil {
		meta["error"] = err.Error()
	}

	clone := base.Clone()
	if clone == nil {
		clone = base
	}
	if err != nil {
		clone.Source = err
	}
	if len(meta) > 0 {
		clone.WithMetadata(meta)
	}

	return clone
}
