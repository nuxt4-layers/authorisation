<script setup lang="ts">
/** Default page provided by @nuxt4-layers/authorisation. Disable with authorisation.pages.enabled = false. */
const route = useRoute()
const changeId = computed(() => String(route.params.changeId))
const { t, locale } = useAuthorisationText()
useHead({ title: t('authorisation.change.title'), htmlAttrs: { lang: locale } })
</script>

<template>
  <div :class="authorisationClasses.page">
    <main :class="authorisationClasses.card" aria-labelledby="authorisation-page-title">
      <h1 id="authorisation-page-title" :class="authorisationClasses.title">{{ t('authorisation.change.title') }}</h1>
      <AuthorisationChange :key="changeId" :change-id="changeId" />
    </main>
  </div>
</template>
