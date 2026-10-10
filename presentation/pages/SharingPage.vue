<script setup lang="ts">
/** Default page provided by @nuxt4-layers/authorisation. Disable with authorisation.pages.enabled = false. */
const route = useRoute()
const groupId = computed(() => String(route.params.groupId))
const { t, locale } = useAuthorisationText()
useHead({ title: t('authorisation.sharing.title'), htmlAttrs: { lang: locale } })
</script>

<template>
  <div :class="authorisationClasses.page">
    <main :class="authorisationClasses.card" aria-labelledby="authorisation-page-title">
      <h1 id="authorisation-page-title" :class="authorisationClasses.title">{{ t('authorisation.sharing.title') }}</h1>
      <AuthorisationSharing :key="groupId" :group-id="groupId" />
    </main>
  </div>
</template>
