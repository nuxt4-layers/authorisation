import { useAppConfig, useRuntimeConfig } from '#imports'
import type { AuthorisationMessages } from '../messages'
import { resolveMessage } from '../messages'

/**
 * PUBLIC. Localised text for the layer's pages and components. Hosts change
 * wording or add locales in app.config.ts under `authorisation.messages`,
 * and set the locale with `NUXT_PUBLIC_AUTHORISATION_LOCALE`.
 */
export function useAuthorisationText() {
  const locale = useRuntimeConfig().public.authorisation.locale
  const overrides = (useAppConfig() as { authorisation?: { messages?: Record<string, AuthorisationMessages> } }).authorisation?.messages
  return {
    locale,
    t: (key: string, params?: Record<string, string | number>) => resolveMessage(key, locale, overrides, params),
    /** A role's name: a built-in role's in words, a custom role's as its tenant named it. */
    roleName: (role: { id: string, name: string, builtIn: boolean } | undefined, fallback = '') =>
      (role ? (role.builtIn ? resolveMessage(`authorisation.builtInRole.${role.id}`, locale, overrides) : role.name) : fallback),
    /** An instant as a date and time in the locale. */
    when: (instant: string | null | undefined) => (instant ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(instant)) : ''),
  }
}
