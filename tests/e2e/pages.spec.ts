import AxeBuilder from '@axe-core/playwright'
import { expect, test, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test'
import { ORIGIN } from './constants'

/**
 * The default pages in a real browser, against the built playground with
 * Theme Manager's real styles: the journeys, keyboard-only use, reflow, and
 * axe checks against the WCAG 2.2 AA rules in light and dark mode.
 */

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

interface Scenario {
  tenantId: string
  company: string
  sales: string
  olive: string
  otto: string
  sam: string
  adam: string
  amy: string
  mia: string
  outsider: string
  changeId: string
}

async function seed(request: APIRequestContext): Promise<Scenario> {
  const response = await request.post('/api/__playground/seed')
  expect(response.ok()).toBe(true)
  return response.json()
}

/** Stands in for Authentication: the playground reads the signed-in principal from this cookie in test mode. */
async function signInAs(context: BrowserContext, principalId: string) {
  await context.clearCookies()
  await context.addCookies([{ name: 'authorisation_playground_principal', value: principalId, url: ORIGIN }])
}

async function expectAccessible(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze()
  expect(results.violations.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`)).toEqual([])
}

/** Axe in light mode, then in dark mode (Theme Manager's `dark` class), then back. */
async function expectAccessibleInBothModes(page: Page) {
  for (const dark of [false, true]) {
    await page.evaluate(on => document.documentElement.classList.toggle('dark', on), dark)
    await expectAccessible(page)
  }
  await page.evaluate(() => document.documentElement.classList.remove('dark'))
}

/**
 * WCAG 1.4.11 (non-text contrast), which axe does not check: a text field's
 * border and the keyboard focus indicator need 3:1 against their surface.
 */
async function expectNonTextContrast(page: Page, selector: string) {
  const ratios = await page.evaluate((target) => {
    const parse = (value: string) => (value.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number)
    const luminance = (value: string) => {
      const [r, g, b] = parse(value).map((c) => {
        const v = c / 255
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
      })
      return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!
    }
    const ratio = (a: string, b: string) => {
      const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p)
      return (x! + 0.05) / (y! + 0.05)
    }
    const surface = (element: Element) => {
      for (let node = element.parentElement; node; node = node.parentElement) {
        const colour = getComputedStyle(node).backgroundColor
        if (colour !== 'rgba(0, 0, 0, 0)') return colour
      }
      return 'rgb(255, 255, 255)'
    }
    const input = document.querySelector(target) as HTMLInputElement
    input.focus()
    const style = getComputedStyle(input)
    return {
      border: ratio(style.borderTopColor, surface(input)),
      focus: ratio(style.outlineColor, surface(input)),
      focusVisible: style.outlineStyle !== 'none' && Number.parseFloat(style.outlineWidth) >= 2,
    }
  }, selector)
  expect(ratios.focusVisible).toBe(true)
  expect(ratios.border).toBeGreaterThanOrEqual(3)
  expect(ratios.focus).toBeGreaterThanOrEqual(3)
}

async function expectNoHorizontalScroll(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
}

test('asks a signed-out visitor to sign in, and returns them afterwards', async ({ page, context }) => {
  await context.clearCookies()
  await page.goto('/groups/some-group/access')
  const link = page.getByRole('link', { name: 'Sign in' })
  await expect(link).toHaveAttribute('href', '/sign-in?redirect=%2Fgroups%2Fsome-group%2Faccess')
  await expectAccessibleInBothModes(page)
})

test('protects every page from framing, caching and referrer leaks', async ({ request }) => {
  for (const path of ['/groups/g/access', '/groups/g/sharing', '/tenants/t/roles', '/access-changes/01a120c9-2cd1-784a-a3d6-f725b2cb2eab']) {
    const response = await request.get(path)
    expect(response.headers()['x-frame-options'], path).toBe('DENY')
    expect(response.headers()['cache-control'], path).toBe('no-store')
    expect(response.headers()['referrer-policy'], path).toBe('no-referrer')
    expect(response.headers()['content-security-policy'], path).toContain("frame-ancestors 'none'")
  }
})

test('refuses a state-changing request from another origin', async ({ request }) => {
  const response = await request.post('/api/authorisation/changes', { data: { request: {} }, headers: { origin: 'https://evil.example' } })
  expect(response.status()).toBe(403)
})

test('shows an administrator the group\'s roles, defaults, review and waiting changes, and gives a role by keyboard', async ({ page, context, request }) => {
  const scenario = await seed(request)
  await signInAs(context, scenario.adam)
  await page.goto(`/groups/${scenario.sales}/access`)
  await expect(page.getByRole('heading', { level: 1, name: 'Access to this group' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Who holds which role' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Default roles and reviews' })).toBeVisible()
  await expect(page.getByText('Every 30 days')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Access review' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Give a role' })).toHaveAttribute('href', `/access-changes/${scenario.changeId}`)
  // Owners follow Identity: no button takes the owner role away.
  await expect(page.getByRole('button', { name: 'Take away the role Owner' })).toHaveCount(0)
  await expectAccessibleInBothModes(page)
  for (const dark of [false, true]) {
    await page.evaluate(on => document.documentElement.classList.toggle('dark', on), dark)
    await expectNonTextContrast(page, '#authorisation-assign-principal')
  }
  await page.evaluate(() => document.documentElement.classList.remove('dark'))

  // Someone outside the group: the rule, in words, and focus on it.
  await page.getByLabel('Person\'s identifier').fill(scenario.outsider)
  await page.getByLabel('Role', { exact: true }).selectOption({ label: 'Viewer (Low)' })
  await page.getByLabel('Reason code').fill('new-starter')
  await page.getByRole('button', { name: 'Request' }).first().click()
  const alert = page.getByRole('alert')
  await expect(alert).toHaveText('That person is not a member of the group.')
  await expect(alert).toBeFocused()
  await expectAccessible(page)

  await page.getByLabel('Person\'s identifier').fill(scenario.mia)
  await page.getByLabel('Reason code').focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('status').filter({ hasText: 'Done.' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Who holds which role' }).locator('..').getByText('Viewer', { exact: true })).toBeVisible()
  await expectAccessibleInBothModes(page)
})

test('marks a role unconfirmed within the review interval as overdue, and confirms it', async ({ page, context, request }) => {
  const scenario = await seed(request)
  await signInAs(context, scenario.adam)
  await page.goto(`/groups/${scenario.sales}/access`)
  const review = page.getByRole('region', { name: 'Access review' })
  const miaEntry = review.getByRole('listitem').filter({ hasText: scenario.mia.slice(-6) })
  await expect(miaEntry.getByText('Overdue')).toBeVisible()
  await miaEntry.getByRole('button', { name: 'Confirm the role Member is still needed' }).click()
  await miaEntry.getByLabel('Reason code').fill('still-needed')
  await expectAccessible(page)
  await miaEntry.getByRole('button', { name: 'Confirm', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Done.' })).toBeVisible()
  await expect(review.getByRole('listitem').filter({ hasText: scenario.mia.slice(-6) }).getByText('Overdue')).toHaveCount(0)
  // Nobody confirms their own role.
  const ownEntry = review.getByRole('listitem').filter({ hasText: scenario.adam.slice(-6) }).first()
  await ownEntry.getByRole('button', { name: /Confirm the role/ }).click()
  await ownEntry.getByLabel('Reason code').fill('still-needed')
  await ownEntry.getByRole('button', { name: 'Confirm', exact: true }).click()
  await expect(page.getByRole('alert')).toHaveText('You cannot give this to yourself. Someone else must request it.')
})

test('lets the approver approve a change, showing what they approve, and the requester withdraw one', async ({ page, context, request }) => {
  const scenario = await seed(request)
  await signInAs(context, scenario.outsider)
  await page.goto(`/access-changes/${scenario.changeId}`)
  await expect(page.getByText('This is not available to you.')).toBeVisible()

  await signInAs(context, scenario.amy)
  await page.goto(`/access-changes/${scenario.changeId}`)
  await expect(page.getByRole('heading', { level: 2, name: 'Give a role' })).toBeVisible()
  await expect(page.getByText('Waiting for approval')).toBeVisible()
  await expect(page.getByText('Role administrator, reaching This group')).toBeVisible()
  await expectAccessibleInBothModes(page)
  await page.getByRole('button', { name: 'Approve' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Your approval is recorded.' })).toBeVisible()
  await expect(page.getByText('Done', { exact: true })).toBeVisible()
  await expectAccessible(page)

  await signInAs(context, scenario.adam)
  await page.goto(`/groups/${scenario.sales}/access`)
  await page.getByLabel('Person\'s identifier').fill(scenario.mia)
  await page.getByLabel('Role', { exact: true }).selectOption({ label: 'Refund clerk (High)' })
  await page.getByLabel('Reason code').fill('cover')
  await page.getByRole('button', { name: 'Request' }).first().click()
  await expect(page.getByRole('status').filter({ hasText: 'Requested. It takes effect once it is approved.' })).toBeVisible()
  await page.getByRole('link', { name: 'See the change' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Change to access' })).toBeVisible()
  await page.getByRole('button', { name: 'Withdraw' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Withdrawn.' })).toBeVisible()
})

test('shows what a group shares and stops sharing it', async ({ page, context, request }) => {
  const scenario = await seed(request)
  await signInAs(context, scenario.mia)
  await page.goto(`/groups/${scenario.sales}/sharing`)
  await expect(page.getByText('This is not available to you.')).toBeVisible()

  await signInAs(context, scenario.sam)
  await page.goto(`/groups/${scenario.sales}/sharing`)
  await expect(page.getByRole('heading', { level: 1, name: 'What this group shares' })).toBeVisible()
  await expect(page.getByText(`orders ${scenario.sales.slice(0, 8)}-order`)).toBeVisible()
  await expectAccessibleInBothModes(page)
  await page.getByRole('button', { name: /^Stop sharing orders/ }).click()
  await page.getByLabel('Reason code').fill('no-longer-needed')
  await page.getByRole('button', { name: 'Stop sharing', exact: true }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Done.' })).toBeVisible()
  await expect(page.getByText('This group shares nothing.')).toBeVisible()
  await expectAccessible(page)
})

test('lists the organisation\'s roles and lets an owner of the top-level group request a new one', async ({ page, context, request }) => {
  const scenario = await seed(request)
  await signInAs(context, scenario.olive)
  await page.goto(`/tenants/${scenario.tenantId}/roles`)
  await expect(page.getByRole('heading', { level: 1, name: 'Roles' })).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Refund clerk' })).toBeVisible()
  await expect(page.getByRole('heading', { level: 2, name: 'Administrator' })).toBeVisible()
  await expectAccessibleInBothModes(page)
  await page.getByRole('button', { name: 'Define a role' }).click()
  await page.getByLabel('Identifier', { exact: true }).fill('auditor')
  await page.getByLabel('Name', { exact: true }).fill('Auditor')
  await page.getByLabel('Permissions, one per line').fill('*:view')
  await page.getByLabel('Reason code').fill('annual-audit')
  await expectAccessibleInBothModes(page)
  await page.getByRole('button', { name: 'Request' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Requested. It takes effect once it is approved.' })).toBeVisible()

  // An administrator of a group below may see the roles, but not define one.
  await signInAs(context, scenario.adam)
  await page.goto(`/tenants/${scenario.tenantId}/roles`)
  await page.getByRole('button', { name: 'Define a role' }).click()
  await page.getByLabel('Identifier', { exact: true }).fill('sneaky')
  await page.getByLabel('Name', { exact: true }).fill('Sneaky')
  await page.getByLabel('Reason code').fill('because')
  await page.getByRole('button', { name: 'Request' }).click()
  await expect(page.getByRole('alert')).toHaveText('This is not available to you.')
})

test('reflows to 320 CSS pixels without scrolling sideways', async ({ page, context, request }) => {
  const scenario = await seed(request)
  await page.setViewportSize({ width: 320, height: 800 })
  await signInAs(context, scenario.olive)
  for (const path of [`/groups/${scenario.sales}/access`, `/tenants/${scenario.tenantId}/roles`, `/access-changes/${scenario.changeId}`]) {
    await page.goto(path)
    await expect(page.locator('h1')).toBeVisible()
    await expectNoHorizontalScroll(page)
  }
  await signInAs(context, scenario.sam)
  await page.goto(`/groups/${scenario.sales}/sharing`)
  await expectNoHorizontalScroll(page)
})
