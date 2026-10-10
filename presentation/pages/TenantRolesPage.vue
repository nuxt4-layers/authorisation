<script setup lang="ts">
/** Default page provided by @nuxt4-layers/authorisation. Disable with authorisation.pages.enabled = false. */
const route = useRoute()
const tenantId = computed(() => String(route.params.tenantId))
const { t, locale } = useAuthorisationText()
useHead({ title: t('authorisation.roles.title'), htmlAttrs: { lang: locale } })
</script>

<template>
  <div :class="authorisationClasses.page">
    <main :class="authorisationClasses.card" aria-labelledby="authorisation-page-title">
      <h1 id="authorisation-page-title" :class="authorisationClasses.title">{{ t('authorisation.roles.title') }}</h1>
      <AuthorisationTenantRoles :key="tenantId" :tenant-id="tenantId" />
    </main>
  </div>
</template>
