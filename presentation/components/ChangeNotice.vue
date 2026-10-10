<script setup lang="ts">
/** PUBLIC. What became of a change just requested, with a link to it when it still waits. */
import type { AuthorisationPendingChange } from '../../contracts'

const props = defineProps<{ change: AuthorisationPendingChange }>()
const routes = useAuthorisationRoutes()
const action = useAuthorisationAction()
const { t } = useAuthorisationText()
const tone = computed(() => (props.change.state === 'rejected' ? 'warning' : 'success'))
</script>

<template>
  <AuthorisationAlert :tone="tone" :focus-on-mount="false">
    <p>{{ action.outcome(change) }}</p>
    <p v-if="change.state !== 'applied'" class="mt-2">
      <NuxtLink :to="routes.change(change.changeId)" :class="authorisationClasses.actionLink">{{ t('authorisation.common.seeChange') }}</NuxtLink>
    </p>
  </AuthorisationAlert>
</template>
