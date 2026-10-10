<script setup lang="ts">
/**
 * PUBLIC. How the pages name a person. Authorisation holds no names (Profile
 * does), so by default this shows only an opaque placeholder made from the
 * end of the identifier. A host replaces it with its own component named
 * `AuthorisationPersonName`, taking the same `principalId` prop, that asks
 * Profile through its disclosure rules.
 */
const props = defineProps<{ principalId: string }>()
const { t } = useAuthorisationText()
const label = computed(() => t('authorisation.person.label', { short: props.principalId.slice(-6) }))
</script>

<template>
  <span :title="principalId">{{ label }}</span>
</template>
