<script setup lang="ts">
/**
 * PUBLIC. The roles an organisation's groups may give: built in, and its
 * own, with requests to define, change and delete its own. Those are
 * critical changes that only an owner of the top-level group may request,
 * with an approval; the server decides.
 */
import type { AuthorisationPendingChange, AuthorisationRoleView } from '../../contracts'

const props = defineProps<{ tenantId: string }>()
const authorisation = useAuthorisation()
const textOf = useAuthorisationText()
const { t } = textOf
const action = useAuthorisationAction()
const requested = ref<AuthorisationPendingChange | null>(null)

const { data: view, error } = await useAsyncData(`authorisation-roles-${props.tenantId}`, () => authorisation.tenantRoles(props.tenantId))
const failure = computed(() => (error.value ? authorisationErrorOf(error.value)?.code ?? 'unavailable' : null))

const editing = ref<'new' | string | null>(null)
const deleting = ref<string | null>(null)
const id = ref('')
const name = ref('')
const description = ref('')
const patterns = ref('')
const reasonCode = ref('')
const reference = ref('')
const justification = () => ({ reasonCode: reasonCode.value.trim(), reference: reference.value.trim() || null })

function start(role: AuthorisationRoleView | null) {
  deleting.value = null
  id.value = role?.id ?? ''
  name.value = role?.name ?? ''
  description.value = role?.description ?? ''
  patterns.value = role?.permissions.map(p => p.pattern).join('\n') ?? ''
  reasonCode.value = ''
  reference.value = ''
  editing.value = role ? role.id : 'new'
}

async function define() {
  const permissions = patterns.value.split('\n').map(line => line.trim()).filter(Boolean).map(pattern => ({ pattern }))
  const role = { id: id.value.trim(), name: name.value.trim(), ...(description.value.trim() ? { description: description.value.trim() } : {}), permissions }
  const change = await action.run(() => authorisation.requestChange({ type: 'role.define', target: { tenantId: props.tenantId, role }, justification: justification() }))
  if (change) {
    editing.value = null
    requested.value = change
  }
}

async function remove(roleId: string) {
  const change = await action.run(() => authorisation.requestChange({ type: 'role.delete', target: { tenantId: props.tenantId, roleId }, justification: justification() }))
  if (change) {
    deleting.value = null
    requested.value = change
  }
}
</script>

<template>
  <div :class="authorisationClasses.stack">
    <AuthorisationUnavailable v-if="failure" :code="failure" />
    <template v-else-if="view">
      <AuthorisationChangeNotice v-if="requested" :change="requested" />
      <AuthorisationAlert v-if="action.error.value" tone="error">{{ action.error.value }}</AuthorisationAlert>
      <p :class="authorisationClasses.muted">{{ t('authorisation.roles.critical') }}</p>
      <ul :class="authorisationClasses.list">
        <li v-for="role in view.roles" :key="role.id" :class="authorisationClasses.listItem">
          <div :class="authorisationClasses.stack">
            <h2 :class="authorisationClasses.sectionTitle">{{ textOf.roleName(role) }}</h2>
            <p :class="authorisationClasses.muted">
              <code :class="authorisationClasses.code">{{ role.id }}</code>
              · {{ role.builtIn ? t('authorisation.roles.builtIn') : t('authorisation.roles.custom') }}
              · {{ t(`authorisation.risk.${role.risk}`) }}
            </p>
            <p v-if="role.description" :class="authorisationClasses.text">{{ role.description }}</p>
            <p :class="authorisationClasses.text">{{ t('authorisation.roles.permissions') }}: <code :class="authorisationClasses.code">{{ role.permissions.map(p => p.pattern).join(', ') || t('authorisation.common.none') }}</code></p>
          </div>
          <div v-if="!role.builtIn" :class="authorisationClasses.row">
            <form v-if="deleting === role.id" :class="authorisationClasses.stack" novalidate @submit.prevent="remove(role.id)">
              <AuthorisationJustification v-model:reason-code="reasonCode" v-model:reference="reference" :id-prefix="`authorisation-delete-${role.id}`" :invalid="action.code.value === 'validation-failed'" />
              <div :class="authorisationClasses.row">
                <button type="submit" :class="authorisationClasses.dangerButton" :disabled="action.disabled.value || !reasonCode.trim()">{{ t('authorisation.roles.delete') }}</button>
                <button type="button" :class="authorisationClasses.secondaryButton" @click="deleting = null">{{ t('authorisation.common.cancel') }}</button>
              </div>
            </form>
            <template v-else>
              <button type="button" :class="authorisationClasses.secondaryButton" :aria-label="t('authorisation.roles.editLabel', { role: textOf.roleName(role) })" @click="start(role)">{{ t('authorisation.roles.edit') }}</button>
              <button type="button" :class="authorisationClasses.secondaryButton" :aria-label="t('authorisation.roles.deleteLabel', { role: textOf.roleName(role) })" @click="editing = null; reasonCode = ''; reference = ''; deleting = role.id">{{ t('authorisation.roles.delete') }}</button>
            </template>
          </div>
        </li>
      </ul>

      <section :class="authorisationClasses.section" aria-labelledby="authorisation-define-title">
        <h2 id="authorisation-define-title" :class="authorisationClasses.sectionTitle">{{ editing && editing !== 'new' ? t('authorisation.roles.editTitle', { role: name }) : t('authorisation.roles.defineTitle') }}</h2>
        <form v-if="editing" :class="authorisationClasses.stack" novalidate @submit.prevent="define">
          <div>
            <label for="authorisation-role-id" :class="authorisationClasses.label">{{ t('authorisation.roles.id') }}</label>
            <input id="authorisation-role-id" v-model="id" type="text" maxlength="64" autocomplete="off" spellcheck="false" :readonly="editing !== 'new'" :class="authorisationClasses.input" aria-describedby="authorisation-role-id-hint" :aria-invalid="action.code.value === 'validation-failed' || action.code.value === 'conflict'">
            <p id="authorisation-role-id-hint" :class="authorisationClasses.hint">{{ t('authorisation.roles.idHint') }}</p>
          </div>
          <div>
            <label for="authorisation-role-name" :class="authorisationClasses.label">{{ t('authorisation.roles.name') }}</label>
            <input id="authorisation-role-name" v-model="name" type="text" maxlength="100" autocomplete="off" :class="authorisationClasses.input">
          </div>
          <div>
            <label for="authorisation-role-description" :class="authorisationClasses.label">{{ t('authorisation.roles.description') }}</label>
            <input id="authorisation-role-description" v-model="description" type="text" maxlength="500" autocomplete="off" :class="authorisationClasses.input">
          </div>
          <div>
            <label for="authorisation-role-patterns" :class="authorisationClasses.label">{{ t('authorisation.roles.patterns') }}</label>
            <textarea id="authorisation-role-patterns" v-model="patterns" rows="4" spellcheck="false" :class="authorisationClasses.input" aria-describedby="authorisation-role-patterns-hint" :aria-invalid="action.code.value === 'validation-failed' || action.code.value === 'conflict'" />
            <p id="authorisation-role-patterns-hint" :class="authorisationClasses.hint">{{ t('authorisation.roles.patternsHint') }}</p>
          </div>
          <AuthorisationJustification v-model:reason-code="reasonCode" v-model:reference="reference" id-prefix="authorisation-define" :invalid="action.code.value === 'validation-failed'" />
          <div :class="authorisationClasses.row">
            <button type="submit" :class="authorisationClasses.primaryButton" :disabled="action.disabled.value || !id.trim() || !name.trim() || !reasonCode.trim()">{{ t('authorisation.roles.submit') }}</button>
            <button type="button" :class="authorisationClasses.secondaryButton" @click="editing = null">{{ t('authorisation.common.cancel') }}</button>
          </div>
        </form>
        <div v-else>
          <button type="button" :class="authorisationClasses.secondaryButton" @click="start(null)">{{ t('authorisation.roles.defineTitle') }}</button>
        </div>
      </section>
    </template>
  </div>
</template>
