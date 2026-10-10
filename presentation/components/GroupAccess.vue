<script setup lang="ts">
/**
 * PUBLIC. Access to a group: who holds which role, the group's default roles
 * and review interval, its access review and the changes waiting. Each
 * section asks the server and shows nothing it is refused; every action is
 * a change request the server decides.
 */
import type { AuthorisationPendingChange } from '../../contracts'

const props = defineProps<{ groupId: string }>()
const authorisation = useAuthorisation()
const routes = useAuthorisationRoutes()
const { t } = useAuthorisationText()
const requested = ref<AuthorisationPendingChange | null>(null)

const { data: access, error } = await useAsyncData(`authorisation-group-access-${props.groupId}`, () => authorisation.groupAccess(props.groupId))
const failure = computed(() => (error.value ? authorisationErrorOf(error.value)?.code ?? 'unavailable' : null))
const tenantId = computed(() => access.value?.tenantId ?? null)
const { data: tenantRoles } = await useAsyncData(`authorisation-tenant-roles-${props.groupId}`, () => (tenantId.value ? authorisation.tenantRoles(tenantId.value) : Promise.resolve(null)), { watch: [tenantId] })
const roles = computed(() => tenantRoles.value?.roles ?? [])

async function onRequested(change: AuthorisationPendingChange) {
  requested.value = change
  await refreshNuxtData([
    `authorisation-group-access-${props.groupId}`,
    `authorisation-assignments-${props.groupId}`,
    `authorisation-review-${props.groupId}`,
    `authorisation-changes-${props.groupId}`,
  ])
}
</script>

<template>
  <div :class="authorisationClasses.stack">
    <AuthorisationUnavailable v-if="failure" :code="failure" />
    <template v-else-if="access">
      <AuthorisationChangeNotice v-if="requested" :change="requested" />
      <nav :aria-label="t('authorisation.access.title')" :class="authorisationClasses.row">
        <NuxtLink :to="routes.sharing(groupId)" :class="authorisationClasses.actionLink">{{ t('authorisation.access.sharingLink') }}</NuxtLink>
        <NuxtLink :to="routes.tenantRoles(access.tenantId)" :class="authorisationClasses.actionLink">{{ t('authorisation.access.rolesLink') }}</NuxtLink>
      </nav>
      <AuthorisationAssignments :group-id="groupId" :roles="roles" @requested="onRequested" />
      <AuthorisationDefaultRoles :access="access" :roles="roles" @requested="onRequested" />
      <AuthorisationAccessReview :group-id="groupId" :roles="roles" @requested="onRequested" />
      <AuthorisationChanges :group-id="groupId" />
      <p :class="authorisationClasses.muted">{{ t('authorisation.common.serverDecides') }}</p>
    </template>
  </div>
</template>
