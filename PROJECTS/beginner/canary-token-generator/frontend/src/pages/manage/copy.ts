// ===================
// ©AngelaMos | 2026
// copy.ts
// ===================

export const MANAGE_COPY = {
  HEADLINE_QUIET: 'NO MOVEMENT YET',
  HEADLINE_LIVE: 'TRAP TRIPPED',
  HEADLINE_DISABLED: 'TRAP MUTED',
  PURPOSE_QUIET:
    'The specimen is in place. Nothing has touched it. Keep this page bookmarked — alerts will fire when something does.',
  PURPOSE_LIVE:
    'At least one visitor has tripped the trap. Below are the recorded events, newest first.',
  PURPOSE_DISABLED:
    'This specimen still records events for forensic continuity, but no alerts are dispatched. Re-enable from the operator console if needed.',
  EVENT_LOG_TITLE: 'EVENT LOG',
  EVENT_LOG_EMPTY:
    'No events recorded yet. When something touches the trigger URL, it will appear here.',
  EVENT_LOAD_MORE: 'Load older events',
  EVENT_LOADING: 'Loading next page…',
  DELETE_TITLE: 'TERMINATE SPECIMEN',
  DELETE_BODY:
    'Cascade-deletes this specimen and every event recorded against it. The trigger URL will no longer fire alerts. This action cannot be undone.',
  DELETE_CONFIRM: 'Terminate',
  DELETE_CANCEL: 'Keep alive',
  DELETE_ARM: 'Mark for termination',
  BACK_TO_INTAKE: 'New specimen',
  NOT_FOUND_HEADLINE: 'DOSSIER NOT FOUND',
  NOT_FOUND_BODY:
    'The manage ID does not correspond to an active specimen. It may have been terminated or the URL may be malformed.',
  ERROR_HEADLINE: 'CANNOT REACH ARCHIVE',
  ERROR_BODY: 'Something went wrong fetching this dossier.',
} as const

export const NOTIFY_TONE = {
  sent: 'signal',
  pending: 'paper',
  failed: 'alarm',
  deduped: 'paper',
} as const
