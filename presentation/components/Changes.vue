<script setup lang="ts">
/** PUBLIC. A group's changes not yet in effect, each linking to its own page; nothing when refused or empty. */
const props = defineProps<{ groupId: string }>()
const authorisation = useAuthorisation()
const routes = useAuthorisationRoutes()
const { t } = useAuthorisationText()
const { data: changes, error } = await useAsyncData(`authorisation-changes-${props.groupId}`, () => authorisation.changes(props.groupId))
</script>

<template>
  <section v-if="!error && changes && changes.length > 0" :class="authorisationClasses.section" aria-labelledby="authorisation-changes-title">
    <h2 id="authorisation-changes-title" :class="authorisationClasses.sectionTitle">{{ t('authorisation.changes.title') }}</h2>
    <ul :class="authorisationClasses.list">
      <li v-for="change in changes" :key="change.changeId" :class="authorisationClasses.listItem">
        <NuxtLink :to="routes.change(change.changeId)" :class="authorisationClasses.link">{{ t(`authorisation.changeType.${change.type}`) }}</NuxtLink>
        <span :class="authorisationClasses.badge">{{ t(`authorisation.changeState.${change.state}`) }}</span>
      </li>
    </ul>
  </section>
</template>
