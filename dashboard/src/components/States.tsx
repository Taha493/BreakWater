import type { ReactNode } from "react";

export function Loading({ what }: { what: string }) {
  return (
    <div role="status" className="py-10 text-center text-sm text-muted">
      Loading {what}…
    </div>
  );
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div role="alert" className="rounded-lg border border-line bg-surface p-4 text-sm">
      <span className="font-semibold text-critical">Could not load.</span>{" "}
      <span className="text-ink-2">{message}</span>
      {retry && (
        <button onClick={retry} className="ml-3 underline">
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line py-10 text-center text-sm text-muted">
      {children}
    </div>
  );
}

/** Loading, error, or empty state for a request; ``children`` render once data is in. */
export function Guard<T>({
  what,
  state,
  isEmpty,
  empty,
  children,
}: {
  what: string;
  state: { data: T | null; error: string | null; loading: boolean; reload: () => void };
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (state.error) return <ErrorState message={state.error} retry={state.reload} />;
  if (state.data === null) return <Loading what={what} />;
  if (isEmpty?.(state.data)) return <Empty>{empty ?? `No ${what} yet.`}</Empty>;
  return <>{children(state.data)}</>;
}
