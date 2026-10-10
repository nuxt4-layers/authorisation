<script setup lang="ts">
/**
 * PUBLIC. A message box. Errors are announced assertively and take focus so
 * keyboard and screen-reader users land on them; other tones are polite.
 */
const props = withDefaults(defineProps<{ tone?: 'error' | 'success' | 'info' | 'warning', title?: string, focusOnMount?: boolean }>(), { tone: 'info', focusOnMount: true })
const element = ref<HTMLElement | null>(null)
const classes = computed(() => ({
  error: authorisationClasses.alertError,
  success: authorisationClasses.alertSuccess,
  info: authorisationClasses.alertInfo,
  warning: authorisationClasses.alertWarning,
})[props.tone])
onMounted(() => {
  if (props.tone === 'error' && props.focusOnMount) element.value?.focus()
})
</script>

<template>
  <div
    ref="element"
    :class="classes"
    :role="tone === 'error' ? 'alert' : 'status'"
    :tabindex="tone === 'error' ? -1 : undefined"
  >
    <p v-if="title" class="font-semibold">{{ title }}</p>
    <slot />
  </div>
</template>
