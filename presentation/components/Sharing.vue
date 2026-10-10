<script setup lang="ts">
/**
 * PUBLIC. What a group shares (`authorisation.grants:manage`), with a
 * request to stop each. Sharing itself starts from the item, in the domain
 * capability that owns it (`useAuthorisation().share(...)`).
 */
import type { AuthorisationPendingChange } from '../../contracts'

const props = defineProps<{ groupId: string }>()
const authorisation = useAuthorisation()
const routes = useAuthorisationRoutes()
const { t, when } = useAuthorisationText()
const action = useAuthorisationAction()
const requested = ref<AuthorisationPendingChange | null>(null)
const revoking = ref<string | null>(null)
const reasonCode = ref('')
const reference = ref('')

const { data: grants, error, refresh } = await useAsyncData(`authorisation-grants-${props.groupId}`, () => authorisation.grants(props.groupId))
const failure = computed(() => (error.value ? authorisationErrorOf(error.value)?.code ?? 'unavailable' : null))

async function revoke(grantId: string) {
  const change = await action.run(() => authorisation.requestChange({ type: 'grant.revoke', target: { grantId }, justification: { reasonCode: reasonCode.value.trim(), reference: reference.value.trim() || null } }))
  if (change) {
    revoking.value = null
    reasonCode.value = ''
    reference.value = ''
    requested.value = change
    await refresh()
  }
}
</script>

<template>
  <div :class="authorisationClasses.stack">
    <AuthorisationUnavailable v-if="failure" :code="failure" />
    <template v-else-if="grants">
      <AuthorisationChangeNotice v-if="requested" :change="requested" />
      <AuthorisationAlert v-if="action.error.value" tone="error">{{ action.error.value }}</AuthorisationAlert>
      <p :class="authorisationClasses.muted">{{ t('authorisation.sharing.intro') }}</p>
      <p v-if="grants.length === 0" :class="authorisationClasses.text">{{ t('authorisation.sharing.empty') }}</p>
      <ul v-else :class="authorisationClasses.list">
        <li v-for="grant in grants" :key="grant.grantId" :class="authorisationClasses.listItem">
          <div :class="authorisationClasses.stack">
            <p :class="authorisationClasses.text">
              <code :class="authorisationClasses.code">{{ t('authorisation.sharing.resource', { type: grant.resource.type, id: grant.resource.id }) }}</code>
            </p>
            <p :class="authorisationClasses.muted">
              <template v-if="grant.subject.kind === 'principal'">{{ t('authorisation.sharing.withPerson') }}: <AuthorisationPersonName :principal-id="grant.subject.principalId" /></template>
              <template v-else>{{ t('authorisation.sharing.withGroup', { group: grant.subject.groupId }) }}</template>
              · <code :class="authorisationClasses.code">{{ grant.permissions.join(', ') }}</code>
              · {{ grant.expiresAt ? t('authorisation.assignments.until', { date: when(grant.expiresAt) }) : t('authorisation.common.never') }}
            </p>
          </div>
          <form v-if="revoking === grant.grantId" :class="authorisationClasses.stack" novalidate @submit.prevent="revoke(grant.grantId)">
            <AuthorisationJustification v-model:reason-code="reasonCode" v-model:reference="reference" :id-prefix="`authorisation-revoke-${grant.grantId}`" :invalid="action.code.value === 'validation-failed'" />
            <div :class="authorisationClasses.row">
              <button type="submit" :class="authorisationClasses.dangerButton" :disabled="action.disabled.value || !reasonCode.trim()">{{ t('authorisation.sharing.revoke') }}</button>
              <button type="button" :class="authorisationClasses.secondaryButton" @click="revoking = null">{{ t('authorisation.common.cancel') }}</button>
            </div>
          </form>
          <button v-else type="button" :class="authorisationClasses.secondaryButton" :aria-label="t('authorisation.sharing.revokeLabel', { type: grant.resource.type, id: grant.resource.id })" @click="revoking = grant.grantId">
            {{ t('authorisation.sharing.revoke') }}
          </button>
        </li>
      </ul>
      <p><NuxtLink :to="routes.groupAccess(groupId)" :class="authorisationClasses.actionLink">{{ t('authorisation.sharing.accessLink') }}</NuxtLink></p>
    </template>
  </div>
</template>
