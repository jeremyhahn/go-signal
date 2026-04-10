import type { ISignalClient } from './ISignalClient';
import { WailsAdapter } from './WailsAdapter';
import { WebAdapter } from './WebAdapter';

// createSignalClient detects the runtime environment and returns the
// appropriate ISignalClient implementation.
//   - Wails runtime detected: WailsAdapter (desktop app)
//   - Otherwise: WebAdapter (web UI hosted by signald)
export function createSignalClient(webBaseURL?: string): ISignalClient {
  if (typeof window !== 'undefined' && (window as any).runtime) {
    return new WailsAdapter();
  }
  const base = webBaseURL || window.location.origin;
  return new WebAdapter(base);
}
