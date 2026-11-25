package auth

import (
	"errors"
	"fmt"
	"slices"
)

// Intent is one entry of the sync intent registry (api-specs/sync/intents,
// ADR-0005 section 7, ADR-0002 S4), reduced to what the structural checks need.
type Intent struct {
	Name         string
	Permission   string
	DeviceKinds  []string // device kinds allowed to record it
	SessionTypes []TokenType
}

// Structural verdicts for a sync operation (section 7 questions 2).
var (
	// ErrUnknownIntent: no such intent in the table. A strong_only action has no
	// intent, so a hand-crafted operation naming one lands here (IST-18); the
	// caller quarantines a trading fact and voids a configuration change.
	ErrUnknownIntent = errors.New("auth: unknown intent")
	// ErrIntentNotAllowed: the device kind or session type may not record it
	// (a kds cannot change a price).
	ErrIntentNotAllowed = errors.New("auth: intent not allowed for this device kind or session type")
)

// IntentTable is the generated intent registry, validated against the
// catalogue. The gateway and the hub use it for the structural checks.
type IntentTable struct{ byName map[string]Intent }

// NewIntentTable builds the table. It refuses, as the CI gates do, an intent
// with no permission, with an unknown permission, or whose permission is
// strong_only: such an action can never arrive as an operation.
func NewIntentTable(cat *Catalogue, intents ...Intent) (*IntentTable, error) {
	t := &IntentTable{byName: make(map[string]Intent, len(intents))}
	for _, in := range intents {
		if in.Name == "" || in.Permission == "" {
			return nil, fmt.Errorf("auth: intent %q has no permission", in.Name)
		}
		def, ok := cat.Get(in.Permission)
		if !ok {
			return nil, fmt.Errorf("auth: intent %q names unknown permission %q", in.Name, in.Permission)
		}
		if def.StrongOnly {
			return nil, fmt.Errorf("auth: intent %q maps to strong_only permission %q; strong_only actions have no intent", in.Name, in.Permission)
		}
		if _, dup := t.byName[in.Name]; dup {
			return nil, fmt.Errorf("auth: duplicate intent %q", in.Name)
		}
		t.byName[in.Name] = in
	}
	return t, nil
}

// Lookup returns the intent.
func (t *IntentTable) Lookup(name string) (Intent, bool) { in, ok := t.byName[name]; return in, ok }

// Check answers section 7 question 2: may this device kind and session type
// record this intent at all?
func (t *IntentTable) Check(intent, deviceKind string, session TokenType) (Intent, error) {
	in, ok := t.byName[intent]
	if !ok {
		return Intent{}, ErrUnknownIntent
	}
	if len(in.DeviceKinds) > 0 && !slices.Contains(in.DeviceKinds, deviceKind) {
		return in, ErrIntentNotAllowed
	}
	if len(in.SessionTypes) > 0 && !slices.Contains(in.SessionTypes, session) {
		return in, ErrIntentNotAllowed
	}
	return in, nil
}
