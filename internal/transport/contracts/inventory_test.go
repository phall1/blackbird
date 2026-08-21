package contracts

import (
	"slices"
	"testing"
)

// The operation inventories are the catalogue a client asks "what can this
// daemon do", and productAPIOperations is what the daemon actually publishes.
// Nothing in the module reads W1OperationInventory today, so no existing test
// would notice the two drifting apart — an operation added to the API table and
// forgotten in the catalogue, or retired from the table and left in it. These
// tests tie them together so the drift is a build failure rather than a client
// discovering a command that does not exist.

// apiOperationsIn returns the published operations whose names appear in want,
// preserving the API table's order.
func apiOperationsIn(want []string) []string {
	published := make([]string, 0, len(want))
	for _, operation := range productAPIOperations {
		if slices.Contains(want, operation.Operation) {
			published = append(published, operation.Operation)
		}
	}
	return published
}

func TestOperationInventoriesMatchThePublishedAPI(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		inventory []string
	}{
		{name: "W0", inventory: W0OperationInventory()},
		{name: "W1", inventory: W1OperationInventory()},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if len(test.inventory) == 0 {
				t.Fatal("inventory is empty, so this test proves nothing")
			}
			published := apiOperationsIn(test.inventory)
			if len(published) != len(test.inventory) {
				t.Fatalf("inventory has %d operations but the API publishes %d of them:\ninventory=%v\npublished=%v",
					len(test.inventory), len(published), test.inventory, published)
			}
			// Order is part of the contract: both are documented as stable, and
			// a client rendering a catalogue should not see it reshuffle.
			if !slices.Equal(published, test.inventory) {
				t.Fatalf("inventory order = %v, published order = %v", test.inventory, published)
			}
		})
	}
}

// TestOperationInventoriesArePartitioned proves the two catalogues name
// disjoint operations and, together, exactly the command surface the API
// publishes. A command that reaches the API table without joining either
// inventory would otherwise be invisible to both.
func TestOperationInventoriesArePartitioned(t *testing.T) {
	t.Parallel()

	w0, w1 := W0OperationInventory(), W1OperationInventory()
	for _, operation := range w0 {
		if slices.Contains(w1, operation) {
			t.Fatalf("%q appears in both the W0 and W1 inventories", operation)
		}
	}

	catalogued := append(append([]string(nil), w0...), w1...)
	var uncatalogued []string
	for _, operation := range productAPIOperations {
		// Queries are not commands and belong to neither command catalogue.
		if operation.Operation == OperationContextGet || operation.Operation == OperationEventsSync {
			continue
		}
		if !slices.Contains(catalogued, operation.Operation) {
			uncatalogued = append(uncatalogued, operation.Operation)
		}
	}
	if len(uncatalogued) > 0 {
		t.Fatalf("published commands in no inventory: %v", uncatalogued)
	}
}

// TestOperationInventoriesCannotBeMutatedByCallers covers the defensive copy
// both accessors make. They return a package-level slice; handing out the
// backing array would let one caller reorder or blank the catalogue for every
// later caller in the process.
func TestOperationInventoriesCannotBeMutatedByCallers(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		get  func() []string
	}{
		{name: "W0", get: W0OperationInventory},
		{name: "W1", get: W1OperationInventory},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			original := test.get()
			pristine := append([]string(nil), original...)

			original[0] = "tampered"
			slices.Reverse(original)

			if after := test.get(); !slices.Equal(after, pristine) {
				t.Fatalf("mutating a returned inventory changed the next call:\ngot  %v\nwant %v", after, pristine)
			}
		})
	}
}
