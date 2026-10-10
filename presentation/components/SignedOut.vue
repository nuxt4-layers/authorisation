<script setup lang="ts">
/** PUBLIC. Shown when nobody is signed in: a link to the host's sign-in page that returns here. */
const { t } = useAuthorisationText()
const routes = useAuthorisationRoutes()
const route = useRoute()
const href = computed(() => `${routes.signIn()}?redirect=${encodeURIComponent(route.fullPath)}`)
</script>

<template>
  <AuthorisationAlert tone="info" :focus-on-mount="false">
    <p>{{ t('authorisation.common.signInRequired') }}</p>
    <p class="mt-2">
      <a :href="href" :class="authorisationClasses.actionLink">{{ t('authorisation.common.signIn') }}</a>
    </p>
  </AuthorisationAlert>
</template>
