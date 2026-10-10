<script setup lang="ts">
/**
 * PUBLIC. Who holds which role in a group (`authorisation.roles:view`), with
 * requests to take a role away and to give one. Owners follow Identity, so
 * `owner` is neither offered nor removable here. Nothing shows when refused.
 */
import type { AuthorisationPendingChange, AuthorisationRoleView } from '../../contracts'

const props = defineProps<{ groupId: string, roles: AuthorisationRoleView[] }>()
const emit = defineEmits<{ requested: [change: AuthorisationPendingChange] }>()
const authorisation = useAuthorisation()
const textOf = useAuthorisationText()
const { t, when } = textOf
const action = useAuthorisationAction()

const { data: assignments, error } = await useAsyncData(`authorisation-assignments-${props.groupId}`, () => authorisation.assignments(props.groupId))
const assignable = computed(() => props.roles.filter(role => role.id !== 'owner'))
const roleName = (roleId: string) => textOf.roleName(props.roles.find(role => role.id === roleId), roleId)

const removing = ref<string | null>(null)
const reasonCode = ref('')
const reference = ref('')
const principalId = ref('')
const roleId = ref('')
const endDate = ref('')
const descendants = ref(false)
const keyOf = (a: { principalId: string, roleId: string }) => `${a.principalId}|${a.roleId}`
watchEffect(() => {
  if (!roleId.value && assignable.value.length > 0) roleId.value = assignable.value.find(role => role.id === 'member')?.id ?? assignable.value[0]!.id
})

function reset() {
  removing.value = null
  reasonCode.value = ''
  reference.value = ''
  principalId.value = ''
  endDate.value = ''
  descendants.value = false
}

const justification = () => ({ reasonCode: reasonCode.value.trim(), reference: reference.value.trim() || null })

async function remove(principal: string, role: string) {
  const change = await action.run(() => authorisation.requestChange({ type: 'role.unassign', target: { principalId: principal, groupId: props.groupId, roleId: role }, justification: justification() }))
  if (change) {
    reset()
    emit('requested', change)
  }
}

async function assign() {
  const expiresAt = endDate.value ? new Date(`${endDate.value}T00:00:00Z`).toISOString() : null
  const change = await action.run(() => authorisation.requestChange({
    type: 'role.assign',
    target: { principalId: principalId.value.trim(), groupId: props.groupId, roleId: roleId.value, scope: descendants.value ? 'group-and-descendants' : 'group', expiresAt },
    justification: justification(),
  }))
  if (change) {
    reset()
    emit('requested', change)
  }
}
</script>

<template>
  <section v-if="!error && assignments" :class="authorisationClasses.section" aria-labelledby="authorisation-assignments-title">
    <h2 id="authorisation-assignments-title" :class="authorisationClasses.sectionTitle">{{ t('authorisation.assignments.title') }}</h2>
    <AuthorisationAlert v-if="action.error.value" tone="error">{{ action.error.value }}</AuthorisationAlert>
    <p v-if="assignments.length === 0" :class="authorisationClasses.muted">{{ t('authorisation.assignments.empty') }}</p>
    <ul v-else :class="authorisationClasses.list">
      <li v-for="assignment in assignments" :key="keyOf(assignment)" :class="authorisationClasses.listItem">
        <div>
          <AuthorisationPersonName :principal-id="assignment.principalId" />
          <span :class="authorisationClasses.badge" class="ml-2">{{ roleName(assignment.roleId) }}</span>
          <span v-if="assignment.scope === 'group-and-descendants'" :class="authorisationClasses.badge" class="ml-2">{{ t('authorisation.scope.group-and-descendants') }}</span>
          <span v-if="assignment.expiresAt" :class="authorisationClasses.muted" class="ml-2">{{ t('authorisation.assignments.until', { date: when(assignment.expiresAt) }) }}</span>
        </div>
        <div v-if="assignment.roleId !== 'owner'" :class="authorisationClasses.row">
          <form v-if="removing === keyOf(assignment)" :class="authorisationClasses.stack" novalidate @submit.prevent="remove(assignment.principalId, assignment.roleId)">
            <AuthorisationJustification v-model:reason-code="reasonCode" v-model:reference="reference" :id-prefix="`authorisation-remove-${keyOf(assignment).replace(/[^A-Za-z0-9-]/g, '-')}`" :invalid="action.code.value === 'validation-failed'" />
            <div :class="authorisationClasses.row">
              <button type="submit" :class="authorisationClasses.dangerButton" :disabled="action.disabled.value || !reasonCode.trim()">{{ t('authorisation.assignments.remove') }}</button>
              <button type="button" :class="authorisationClasses.secondaryButton" @click="reset">{{ t('authorisation.common.cancel') }}</button>
            </div>
          </form>
          <button v-else type="button" :class="authorisationClasses.secondaryButton" :aria-label="t('authorisation.assignments.removeLabel', { role: roleName(assignment.roleId) })" @click="reset(); removing = keyOf(assignment)">
            {{ t('authorisation.assignments.remove') }}
          </button>
        </div>
      </li>
    </ul>

    <form :class="authorisationClasses.stack" class="mt-6" novalidate aria-labelledby="authorisation-assign-title" @submit.prevent="assign">
      <h3 id="authorisation-assign-title" :class="authorisationClasses.label">{{ t('authorisation.assignments.assignTitle') }}</h3>
      <div>
        <label for="authorisation-assign-principal" :class="authorisationClasses.label">{{ t('authorisation.assignments.principal') }}</label>
        <input id="authorisation-assign-principal" v-model="principalId" type="text" maxlength="128" autocomplete="off" spellcheck="false" :class="authorisationClasses.input" aria-describedby="authorisation-assign-principal-hint" :aria-invalid="action.code.value === 'validation-failed'">
        <p id="authorisation-assign-principal-hint" :class="authorisationClasses.hint">{{ t('authorisation.assignments.principalHint') }}</p>
      </div>
      <div>
        <label for="authorisation-assign-role" :class="authorisationClasses.label">{{ t('authorisation.assignments.role') }}</label>
        <select id="authorisation-assign-role" v-model="roleId" :class="authorisationClasses.input">
          <option v-for="role in assignable" :key="role.id" :value="role.id">{{ textOf.roleName(role) }} ({{ t(`authorisation.risk.${role.risk}`) }})</option>
        </select>
      </div>
      <div>
        <label for="authorisation-assign-end" :class="authorisationClasses.label">{{ t('authorisation.assignments.expiresAt') }}</label>
        <input id="authorisation-assign-end" v-model="endDate" type="date" :class="authorisationClasses.input" aria-describedby="authorisation-assign-end-hint">
        <p id="authorisation-assign-end-hint" :class="authorisationClasses.hint">{{ t('authorisation.assignments.expiresHint') }}</p>
      </div>
      <div :class="authorisationClasses.row">
        <input id="authorisation-assign-descendants" v-model="descendants" type="checkbox" :class="authorisationClasses.checkbox" aria-describedby="authorisation-assign-descendants-hint">
        <label for="authorisation-assign-descendants" :class="authorisationClasses.label">{{ t('authorisation.assignments.descendants') }}</label>
        <p id="authorisation-assign-descendants-hint" :class="authorisationClasses.hint">{{ t('authorisation.assignments.descendantsHint') }}</p>
      </div>
      <AuthorisationJustification v-if="!removing" v-model:reason-code="reasonCode" v-model:reference="reference" id-prefix="authorisation-assign" :invalid="action.code.value === 'validation-failed'" />
      <div>
        <button type="submit" :class="authorisationClasses.primaryButton" :disabled="action.disabled.value || !principalId.trim() || !roleId || !reasonCode.trim() || !!removing">{{ t('authorisation.assignments.submit') }}</button>
      </div>
    </form>
  </section>
</template>
