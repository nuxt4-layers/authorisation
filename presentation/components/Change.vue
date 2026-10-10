<script setup lang="ts">
/**
 * PUBLIC. A change to access, for whoever may see it: what it does, why,
 * how it is approved, and the actions open to the signed-in person (approve
 * or reject, or withdraw their own). The approval carries the fingerprint
 * of the change as shown, so an altered change is refused.
 */
import type { AuthorisationChangeTarget, AuthorisationPendingChange } from '../../contracts'

const props = defineProps<{ changeId: string }>()
const authorisation = useAuthorisation()
const routes = useAuthorisationRoutes()
const { t, when } = useAuthorisationText()
const action = useAuthorisationAction()
const notice = ref<string | null>(null)

const { data: change, error, refresh } = await useAsyncData(`authorisation-change-${props.changeId}`, () => authorisation.change(props.changeId))
const failure = computed(() => (error.value ? authorisationErrorOf(error.value)?.code ?? 'unavailable' : null))
const open = computed(() => change.value?.state === 'awaiting-approval' || change.value?.state === 'delayed')

/** The change's target in words; identifiers stay identifiers. */
function describe(c: AuthorisationPendingChange): string {
  const target = c.target as Record<string, unknown>
  switch (c.type) {
    case 'role.assign': {
      const a = target as AuthorisationChangeTarget<'role.assign'>
      return [t('authorisation.change.target.role', { role: a.roleId }), t('authorisation.change.target.scope', { scope: t(`authorisation.scope.${a.scope ?? 'group'}`) }), ...(a.expiresAt ? [t('authorisation.change.target.until', { date: when(a.expiresAt) })] : [])].join(', ')
    }
    case 'role.unassign':
    case 'assignment.confirm':
      return t('authorisation.change.target.role', { role: String(target.roleId) })
    case 'grant.create': {
      const { grant } = target as AuthorisationChangeTarget<'grant.create'>
      return t('authorisation.change.target.share', { permissions: grant.permissions.join(', '), type: grant.resource.type, id: grant.resource.id })
    }
    case 'grant.revoke':
      return t('authorisation.change.target.grant', { grant: String(target.grantId) })
    case 'role.define':
      return t('authorisation.change.target.tenantRole', { role: (target as AuthorisationChangeTarget<'role.define'>).role.id })
    case 'role.delete':
      return t('authorisation.change.target.tenantRole', { role: String(target.roleId) })
    case 'group.change-default-roles': {
      const { defaultRoles } = target as AuthorisationChangeTarget<'group.change-default-roles'>
      return t('authorisation.change.target.defaults', { member: defaultRoles.member ?? t('authorisation.common.none'), guest: defaultRoles.guest ?? t('authorisation.common.none') })
    }
    case 'group.change-review-interval': {
      const { intervalDays } = target as AuthorisationChangeTarget<'group.change-review-interval'>
      return intervalDays === null ? t('authorisation.change.target.noInterval') : t('authorisation.change.target.interval', { days: intervalDays })
    }
  }
}

async function act(run: () => Promise<unknown>, done: string) {
  notice.value = null
  if (await action.run(run)) {
    notice.value = t(done)
    await refresh()
  }
}
</script>

<template>
  <div :class="authorisationClasses.stack">
    <AuthorisationUnavailable v-if="failure" :code="failure" />
    <template v-else-if="change">
      <AuthorisationAlert v-if="action.error.value" tone="error">{{ action.error.value }}</AuthorisationAlert>
      <AuthorisationAlert v-if="notice" tone="success" :focus-on-mount="false">{{ notice }}</AuthorisationAlert>
      <h2 :class="authorisationClasses.sectionTitle">{{ t(`authorisation.changeType.${change.type}`) }}</h2>
      <dl :class="authorisationClasses.definitions">
        <dt :class="authorisationClasses.term">{{ t('authorisation.change.state') }}</dt>
        <dd :class="authorisationClasses.definition"><span :class="authorisationClasses.badge">{{ t(`authorisation.changeState.${change.state}`) }}</span></dd>
        <dt :class="authorisationClasses.term">{{ t('authorisation.change.what') }}</dt>
        <dd :class="authorisationClasses.definition">{{ describe(change) }}</dd>
        <dt :class="authorisationClasses.term">{{ t('authorisation.change.group') }}</dt>
        <dd :class="authorisationClasses.definition"><NuxtLink :to="routes.groupAccess(change.groupId)" :class="authorisationClasses.link">{{ t('authorisation.change.groupLink') }}</NuxtLink></dd>
        <dt :class="authorisationClasses.term">{{ t('authorisation.change.requester') }}</dt>
        <dd :class="authorisationClasses.definition"><AuthorisationPersonName :principal-id="change.requesterId" /></dd>
        <template v-if="change.beneficiaryId">
          <dt :class="authorisationClasses.term">{{ t('authorisation.change.beneficiary') }}</dt>
          <dd :class="authorisationClasses.definition"><AuthorisationPersonName :principal-id="change.beneficiaryId" /></dd>
        </template>
        <dt :class="authorisationClasses.term">{{ t('authorisation.change.risk') }}</dt>
        <dd :class="authorisationClasses.definition">{{ t(`authorisation.risk.${change.risk}`) }}</dd>
        <dt :class="authorisationClasses.term">{{ t('authorisation.change.reason') }}</dt>
        <dd :class="authorisationClasses.definition"><code :class="authorisationClasses.code">{{ change.justification.reasonCode }}</code><template v-if="change.justification.reference"> · <code :class="authorisationClasses.code">{{ change.justification.reference }}</code></template></dd>
        <dt :class="authorisationClasses.term">{{ t('authorisation.change.route') }}</dt>
        <dd :class="authorisationClasses.definition">{{ t(`authorisation.route.${change.route}`, { count: change.requiredApprovals }) }}</dd>
        <template v-if="change.delayEndsAt && change.state === 'delayed'">
          <dt :class="authorisationClasses.term">{{ t('authorisation.change.appliesAt') }}</dt>
          <dd :class="authorisationClasses.definition">{{ when(change.delayEndsAt) }}</dd>
        </template>
        <template v-if="change.heldUntil && open">
          <dt :class="authorisationClasses.term">{{ t('authorisation.change.heldUntil') }}</dt>
          <dd :class="authorisationClasses.definition">{{ when(change.heldUntil) }}</dd>
        </template>
        <template v-if="change.expiresAt && change.state === 'awaiting-approval'">
          <dt :class="authorisationClasses.term">{{ t('authorisation.change.expiresAt') }}</dt>
          <dd :class="authorisationClasses.definition">{{ when(change.expiresAt) }}</dd>
        </template>
        <dt :class="authorisationClasses.term">{{ t('authorisation.change.digest') }}</dt>
        <dd :class="authorisationClasses.definition"><code :class="authorisationClasses.code">{{ change.changeDigest }}</code></dd>
      </dl>
      <div :class="authorisationClasses.row" class="mt-4">
        <template v-if="change.state === 'awaiting-approval'">
          <button type="button" :class="authorisationClasses.primaryButton" :disabled="action.disabled.value" @click="act(() => authorisation.decideChange(change!, 'approve'), 'authorisation.change.approved')">{{ t('authorisation.change.approve') }}</button>
          <button type="button" :class="authorisationClasses.dangerButton" :disabled="action.disabled.value" @click="act(() => authorisation.decideChange(change!, 'reject'), 'authorisation.change.rejected')">{{ t('authorisation.change.reject') }}</button>
        </template>
        <button v-if="open" type="button" :class="authorisationClasses.secondaryButton" :disabled="action.disabled.value" @click="act(() => authorisation.cancelChange(change!.changeId), 'authorisation.change.cancelled')">
          {{ t('authorisation.change.cancel') }}
        </button>
      </div>
      <p :class="authorisationClasses.muted">{{ t('authorisation.common.serverDecides') }}</p>
    </template>
  </div>
</template>
