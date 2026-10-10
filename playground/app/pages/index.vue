<script setup lang="ts">
useHead({ title: 'Authorisation playground', htmlAttrs: { lang: 'en-GB' } })
</script>

<template>
  <div :class="authorisationClasses.page">
    <main :class="authorisationClasses.card">
      <h1 :class="authorisationClasses.title">Authorisation playground</h1>
      <p :class="authorisationClasses.text">Composition harness for the authorisation layer.</p>
    </main>
  </div>
</template>
