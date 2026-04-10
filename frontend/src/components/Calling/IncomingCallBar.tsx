import type { CallType } from '../../sdk/ISignalClient';

interface IncomingCallBarProps {
  callerName: string;
  callType: CallType;
  onAccept: () => void;
  onDecline: () => void;
}

export function IncomingCallBar({
  callerName,
  callType,
  onAccept,
  onDecline,
}: IncomingCallBarProps) {
  return (
    <div className="incoming-call-bar" role="alert" data-testid="incoming-call-bar">
      <div className="incoming-call-bar__info">
        <svg className="incoming-call-bar__icon" viewBox="0 0 20 20" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
          {callType === 'video' ? (
            <>
              <rect x="1" y="4" width="12" height="12" rx="2" />
              <path d="m19 6-5 3.5L19 13V6Z" />
            </>
          ) : (
            <path d="M2 3.5C2 2.67 2.67 2 3.5 2h3.09a1 1 0 0 1 .98.79l.72 3.6a1 1 0 0 1-.27.88l-1.52 1.53a11.04 11.04 0 0 0 4.7 4.7l1.53-1.52a1 1 0 0 1 .88-.27l3.6.72a1 1 0 0 1 .79.98v3.09c0 .83-.67 1.5-1.5 1.5C8.84 18 2 11.16 2 3.5Z" />
          )}
        </svg>
        <span className="incoming-call-bar__text">
          <strong>{callerName}</strong> — {callType === 'video' ? 'Video' : 'Audio'} call
        </span>
      </div>
      <div className="incoming-call-bar__actions">
        <button
          type="button"
          className="incoming-call-bar__button incoming-call-bar__button--decline"
          onClick={onDecline}
          aria-label="Decline call"
          data-testid="call-decline"
        >
          Decline
        </button>
        <button
          type="button"
          className="incoming-call-bar__button incoming-call-bar__button--accept"
          onClick={onAccept}
          aria-label="Accept call"
          data-testid="call-accept"
        >
          Accept
        </button>
      </div>
    </div>
  );
}
