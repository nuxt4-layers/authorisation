import type { AuthorisationErrorBody, AuthorisationPendingChange } from '../../contracts'
import { isAuthorisationErrorCode } from '../../contracts'
import { useAuthorisationText } from './useAuthorisationText'

/** The contract error a failed request carried, if any. */
export function authorisationErrorOf(error: unknown): AuthorisationErrorBody | null {
  const body = (error as { data?: { data?: unknown } } | null)?.data?.data as Partial<AuthorisationErrorBody> | undefined
  if (body && isAuthorisationErrorCode(body.code)) return { code: body.code, messageKey: `authorisation.error.${body.code}`, ...(body.reason ? { reason: body.reason } : {}) }
  return null
}

/**
 * PUBLIC. Shared state for an action on the layer's pages: a pending flag,
 * the error to show and the code behind it, and the words for what became
 * of a requested change. `disabled` is also true until the component has
 * hydrated, so a form never submits natively.
 */
export function useAuthorisationAction() {
  const { t, locale } = useAuthorisationText()
  const pending = ref(false)
  const hydrated = ref(false)
  onMounted(() => { hydrated.value = true })
  const disabled = computed(() => pending.value || !hydrated.value)
  const error = ref<string | null>(null)
  const code = ref<AuthorisationErrorBody['code'] | null>(null)

  /** A message for a contract error: the rule's own wording when there is one, otherwise the code's. */
  function messageFor(body: AuthorisationErrorBody | null): string {
    if (!body) return t('authorisation.error.unavailable')
    if (body.reason) {
      const specific = t(`authorisation.reason.${body.reason}`)
      if (specific !== `authorisation.reason.${body.reason}`) return specific
    }
    return t(`authorisation.error.${body.code}`)
  }

  /** Runs an action, tracking pending state; on failure sets `error` and returns null. */
  async function run<T>(action: () => Promise<T>): Promise<T | null> {
    pending.value = true
    error.value = null
    code.value = null
    try {
      return await action()
    }
    catch (failure) {
      const body = authorisationErrorOf(failure)
      code.value = body?.code ?? 'unavailable'
      error.value = messageFor(body)
      return null
    }
    finally {
      pending.value = false
    }
  }

  /** What became of a requested change, in words. */
  function outcome(change: Pick<AuthorisationPendingChange, 'state' | 'delayEndsAt'>): string {
    const when = change.delayEndsAt ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(change.delayEndsAt)) : ''
    return t(`authorisation.outcome.${change.state}`, { when })
  }

  return { pending, disabled, error, code, run, messageFor, outcome, t }
}
