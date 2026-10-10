<script setup lang="ts">
/** PUBLIC. What a section shows when it cannot load: signed out, not allowed (or not there: the server does not say which), or a failure. */
const props = defineProps<{ code: string }>()
const { t } = useAuthorisationText()
const known = computed(() => ['forbidden', 'unavailable', 'insufficient-assurance'].includes(props.code) ? props.code : 'unavailable')
</script>

<template>
  <AuthorisationSignedOut v-if="code === 'unauthenticated'" />
  <AuthorisationAlert v-else :tone="known === 'forbidden' ? 'info' : 'error'" :focus-on-mount="false">
    <p>{{ t(`authorisation.error.${known}`) }}</p>
  </AuthorisationAlert>
</template>
