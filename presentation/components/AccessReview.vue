<script setup lang="ts">
/**
 * PUBLIC. A group's access review (`authorisation.role-assignments:manage`):
 * every role, when and by whom it was given, its end date, when it was last
 * confirmed, and whether it is overdue, with a request to confirm it.
 * Nobody confirms their own; the server refuses that. Nothing shows when
 * refused.
 */
import type { AuthorisationPendingChange, AuthorisationRoleView } from '../../contracts'

const props = defineProps<{ groupId: string, roles: AuthorisationRoleView[] }>()
const emit = defineEmits<{ requested: [change: AuthorisationPendingChange] }>()
const authorisation = useAuthorisation()
const textOf = useAuthorisationText()
const { t, when } = textOf
const action = useAuthorisationAction()

const { data: review, error } = await useAsyncData(`authorisation-review-${props.groupId}`, () => authorisation.accessReview(props.groupId))
const roleName = (roleId: string) => textOf.roleName(props.roles.find(role => role.id === roleId), roleId)
const confirming = ref<string | null>(null)
const reasonCode = ref('')
const reference = ref('')
const keyOf = (a: { principalId: string, roleId: string }) => `${a.principalId}|${a.roleId}`

async function confirm(principalId: string, roleId: string) {
  const change = await action.run(() => authorisation.requestChange({
    type: 'assignment.confirm',
    target: { principalId, groupId: props.groupId, roleId },
    justification: { reasonCode: reasonCode.value.trim(), reference: reference.value.trim() || null },
  }))
  if (change) {
    confirming.value = null
    reasonCode.value = ''
    reference.value = ''
    emit('requested', change)
  }
}
</script>

<template>
  <section v-if="!error && review" :class="authorisationClasses.section" aria-labelledby="authorisation-review-title">
    <h2 id="authorisation-review-title" :class="authorisationClasses.sectionTitle">{{ t('authorisation.review.title') }}</h2>
    <p :class="authorisationClasses.muted">{{ t('authorisation.review.intro') }}</p>
    <AuthorisationAlert v-if="action.error.value" tone="error">{{ action.error.value }}</AuthorisationAlert>
    <p v-if="review.entries.length === 0" :class="authorisationClasses.muted">{{ t('authorisation.review.empty') }}</p>
    <ul v-else :class="authorisationClasses.list">
      <li v-for="entry in review.entries" :key="keyOf(entry)" :class="authorisationClasses.listItem">
        <div :class="authorisationClasses.stack">
          <p :class="authorisationClasses.text">
            <AuthorisationPersonName :principal-id="entry.principalId" />
            <span :class="authorisationClasses.badge" class="ml-2">{{ roleName(entry.roleId) }}</span>
            <span v-if="entry.overdue" :class="authorisationClasses.badge" class="ml-2">{{ t('authorisation.review.overdue') }}</span>
          </p>
          <p :class="authorisationClasses.muted">
            {{ t('authorisation.review.assigned', { date: when(entry.assignedAt) }) }}<template v-if="entry.assignedBy"> {{ t('authorisation.review.by') }} <AuthorisationPersonName :principal-id="entry.assignedBy" /></template>.
            {{ entry.confirmedAt ? t('authorisation.review.confirmed', { date: when(entry.confirmedAt) }) : t('authorisation.review.neverConfirmed') }}.
            <template v-if="entry.expiresAt">{{ t('authorisation.assignments.until', { date: when(entry.expiresAt) }) }}.</template>
          </p>
        </div>
        <form v-if="confirming === keyOf(entry)" :class="authorisationClasses.stack" novalidate @submit.prevent="confirm(entry.principalId, entry.roleId)">
          <AuthorisationJustification v-model:reason-code="reasonCode" v-model:reference="reference" :id-prefix="`authorisation-confirm-${keyOf(entry).replace(/[^A-Za-z0-9-]/g, '-')}`" :invalid="action.code.value === 'validation-failed'" />
          <div :class="authorisationClasses.row">
            <button type="submit" :class="authorisationClasses.primaryButton" :disabled="action.disabled.value || !reasonCode.trim()">{{ t('authorisation.review.confirm') }}</button>
            <button type="button" :class="authorisationClasses.secondaryButton" @click="confirming = null">{{ t('authorisation.common.cancel') }}</button>
          </div>
        </form>
        <button v-else type="button" :class="authorisationClasses.secondaryButton" :aria-label="t('authorisation.review.confirmLabel', { role: roleName(entry.roleId) })" @click="confirming = keyOf(entry)">
          {{ t('authorisation.review.confirm') }}
        </button>
      </li>
    </ul>
  </section>
</template>
