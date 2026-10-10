<script setup lang="ts">
/**
 * PUBLIC. A group's default roles and review interval, with requests to
 * change them (`authorisation.group-access:manage`, high risk). A guest's
 * default role cannot hold a high-risk or critical permission; the server
 * decides that and everything else.
 */
import type { AuthorisationGroupAccess, AuthorisationPendingChange, AuthorisationRoleView } from '../../contracts'

const props = defineProps<{ access: AuthorisationGroupAccess, roles: AuthorisationRoleView[] }>()
const emit = defineEmits<{ requested: [change: AuthorisationPendingChange] }>()
const authorisation = useAuthorisation()
const textOf = useAuthorisationText()
const { t } = textOf
const action = useAuthorisationAction()

const editing = ref<'roles' | 'interval' | null>(null)
const member = ref('')
const guest = ref('')
const days = ref<string | number>('')
const reasonCode = ref('')
const reference = ref('')
const choices = computed(() => props.roles.filter(role => role.id !== 'owner'))
const guestChoices = computed(() => choices.value.filter(role => role.risk === 'low' || role.risk === 'medium'))
const roleName = (roleId: string | null) => (roleId ? textOf.roleName(props.roles.find(role => role.id === roleId), roleId) : t('authorisation.common.none'))

function edit(what: 'roles' | 'interval') {
  member.value = props.access.defaultRoles.member ?? ''
  guest.value = props.access.defaultRoles.guest ?? ''
  days.value = props.access.reviewIntervalDays === null ? '' : String(props.access.reviewIntervalDays)
  reasonCode.value = ''
  reference.value = ''
  editing.value = what
}

async function submit() {
  const justification = { reasonCode: reasonCode.value.trim(), reference: reference.value.trim() || null }
  const change = await action.run(() => authorisation.requestChange(editing.value === 'roles'
    ? { type: 'group.change-default-roles', target: { groupId: props.access.groupId, defaultRoles: { member: member.value || null, guest: guest.value || null } }, justification }
    : { type: 'group.change-review-interval', target: { groupId: props.access.groupId, intervalDays: String(days.value).trim() === '' ? null : Number(days.value) }, justification }))
  if (change) {
    editing.value = null
    emit('requested', change)
  }
}
</script>

<template>
  <section :class="authorisationClasses.section" aria-labelledby="authorisation-defaults-title">
    <h2 id="authorisation-defaults-title" :class="authorisationClasses.sectionTitle">{{ t('authorisation.defaults.title') }}</h2>
    <dl :class="authorisationClasses.definitions">
      <dt :class="authorisationClasses.term">{{ t('authorisation.defaults.member') }}</dt>
      <dd :class="authorisationClasses.definition">{{ roleName(access.defaultRoles.member) }}</dd>
      <dt :class="authorisationClasses.term">{{ t('authorisation.defaults.guest') }}</dt>
      <dd :class="authorisationClasses.definition">{{ roleName(access.defaultRoles.guest) }}</dd>
      <dt :class="authorisationClasses.term">{{ t('authorisation.defaults.interval') }}</dt>
      <dd :class="authorisationClasses.definition">{{ access.reviewIntervalDays === null ? t('authorisation.defaults.noInterval') : t('authorisation.defaults.intervalDays', { days: access.reviewIntervalDays }) }}</dd>
    </dl>
    <AuthorisationAlert v-if="editing && action.error.value" tone="error">{{ action.error.value }}</AuthorisationAlert>
    <form v-if="editing" :class="authorisationClasses.stack" class="mt-4" novalidate @submit.prevent="submit">
      <template v-if="editing === 'roles'">
        <div>
          <label for="authorisation-default-member" :class="authorisationClasses.label">{{ t('authorisation.defaults.member') }}</label>
          <select id="authorisation-default-member" v-model="member" :class="authorisationClasses.input">
            <option value="">{{ t('authorisation.common.none') }}</option>
            <option v-for="role in choices" :key="role.id" :value="role.id">{{ textOf.roleName(role) }} ({{ t(`authorisation.risk.${role.risk}`) }})</option>
          </select>
        </div>
        <div>
          <label for="authorisation-default-guest" :class="authorisationClasses.label">{{ t('authorisation.defaults.guest') }}</label>
          <select id="authorisation-default-guest" v-model="guest" :class="authorisationClasses.input" aria-describedby="authorisation-default-guest-hint">
            <option value="">{{ t('authorisation.common.none') }}</option>
            <option v-for="role in guestChoices" :key="role.id" :value="role.id">{{ textOf.roleName(role) }} ({{ t(`authorisation.risk.${role.risk}`) }})</option>
          </select>
          <p id="authorisation-default-guest-hint" :class="authorisationClasses.hint">{{ t('authorisation.defaults.guestHint') }}</p>
        </div>
      </template>
      <div v-else>
        <label for="authorisation-review-days" :class="authorisationClasses.label">{{ t('authorisation.defaults.intervalLabel') }}</label>
        <input id="authorisation-review-days" v-model="days" type="number" inputmode="numeric" min="1" max="3650" step="1" autocomplete="off" :class="authorisationClasses.input" :aria-invalid="action.code.value === 'validation-failed'">
      </div>
      <AuthorisationJustification v-model:reason-code="reasonCode" v-model:reference="reference" id-prefix="authorisation-defaults" :invalid="action.code.value === 'validation-failed'" />
      <div :class="authorisationClasses.row">
        <button type="submit" :class="authorisationClasses.primaryButton" :disabled="action.disabled.value || !reasonCode.trim()">{{ t('authorisation.defaults.submit') }}</button>
        <button type="button" :class="authorisationClasses.secondaryButton" @click="editing = null">{{ t('authorisation.common.cancel') }}</button>
      </div>
    </form>
    <div v-else :class="authorisationClasses.row" class="mt-4">
      <button type="button" :class="authorisationClasses.secondaryButton" @click="edit('roles')">{{ t('authorisation.defaults.change') }}</button>
      <button type="button" :class="authorisationClasses.secondaryButton" @click="edit('interval')">{{ t('authorisation.defaults.changeInterval') }}</button>
    </div>
  </section>
</template>
