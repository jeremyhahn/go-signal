import type { ISignalClient } from './ISignalClient';
import { WailsAdapter } from './WailsAdapter';
import { WebAdapter } from './WebAdapter';

// createSignalClient returns WailsAdapter under the Wails runtime, otherwise WebAdapter.
export function createSignalClient(webBaseURL?: string): ISignalClient {
  if (typeof window !== 'undefined' && (window as any).runtime) {
    return new WailsAdapter();
  }
  const base = webBaseURL || window.location.origin;
  return new WebAdapter(base);
}
