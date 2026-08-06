package tier

import "errors"

// CloseAll composes teardown functions into one that runs all of them in order
// and reports every error they produced. Every step runs even if an earlier one
// failed: these are resource releases, and skipping the rest to report a failure
// leaks.
//
// Joined rather than first-wins because one of these errors is not like the
// others. The abandoned-substrate condition changes what the caller does next,
// and it comes from the device teardown, which composes *last* - so keeping only
// the first error would let a routine grumble from a mux close hide the one
// answer the cascade acts on.
func CloseAll(fns ...func() error) func() error {
	return func() error {
		var errs []error
		for _, fn := range fns {
			if fn == nil {
				continue
			}
			if err := fn(); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
}
