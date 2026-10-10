<script setup lang="ts">
/**
 * PUBLIC. The justification every change carries: a reason code and, where
 * the group asks for one, a reference. Never free text.
 */
defineProps<{ idPrefix: string, invalid?: boolean }>()
const reasonCode = defineModel<string>('reasonCode', { required: true })
const reference = defineModel<string>('reference', { required: true })
const { t } = useAuthorisationText()
</script>

<template>
  <fieldset :class="authorisationClasses.stack">
    <legend :class="authorisationClasses.label">{{ t('authorisation.justification.legend') }}</legend>
    <div>
      <label :for="`${idPrefix}-reason`" :class="authorisationClasses.label">{{ t('authorisation.justification.reasonCode') }}</label>
      <input :id="`${idPrefix}-reason`" v-model="reasonCode" type="text" maxlength="64" required autocomplete="off" :class="authorisationClasses.input" :aria-describedby="`${idPrefix}-reason-hint`" :aria-invalid="invalid">
      <p :id="`${idPrefix}-reason-hint`" :class="authorisationClasses.hint">{{ t('authorisation.justification.reasonHint') }}</p>
    </div>
    <div>
      <label :for="`${idPrefix}-reference`" :class="authorisationClasses.label">{{ t('authorisation.justification.reference') }}</label>
      <input :id="`${idPrefix}-reference`" v-model="reference" type="text" maxlength="64" autocomplete="off" :class="authorisationClasses.input" :aria-describedby="`${idPrefix}-reference-hint`">
      <p :id="`${idPrefix}-reference-hint`" :class="authorisationClasses.hint">{{ t('authorisation.justification.referenceHint') }}</p>
    </div>
  </fieldset>
</template>
