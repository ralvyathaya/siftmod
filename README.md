# SiftMod

SiftMod is a Reddit Devvit moderation app for triaging report abuse and report floods. It listens for post and comment report triggers, stores clustered incidents in Redis, masks abusive report text when configured, and gives moderators a short evidence packet from the post/comment overflow menu.

## MVP Features

- Listens to `onPostReport` and `onCommentReport` Devvit triggers.
- Stores report incidents in Redis with a 60 day TTL.
- Clusters by target thing ID, normalized report reason fingerprint, and configurable time window.
- Detects high-severity incidents from configured abusive keyword/regex matches, repeated identical reports, and target-level report floods.
- Masks abusive report text in moderator-facing summaries when masking is enabled.
- Adds a moderator menu action on posts and comments: **View SiftMod report summary**.
- Adds a hackathon-friendly **Seed SiftMod demo incident** action for reliable judge demos.
- Adds a subreddit-level **View SiftMod incident queue** action for recent incident triage.
- Adds **Run SiftMod diagnostics** to verify Redis and settings from a private dev subreddit.
- Lets moderators mark the latest incident reviewed and save a short internal review note in Redis.
- Lets moderators optionally call Reddit `ignoreReports()` from the incident summary after review.
- Can optionally send a modmail notification for high-severity incidents.
- Validates keyword regex settings before saving.

## Devvit APIs Used

This project uses the Devvit web server style from `@devvit/web/server`:

- `redis` for incident persistence and target indexes.
- `settings` for subreddit install settings.
- `reddit.modMail.createModNotification` for optional high-severity notifications.
- `Post.ignoreReports()` and `Comment.ignoreReports()` for opt-in report noise suppression.
- Hono internal endpoints configured in `devvit.json`.
- Trigger request types from `@devvit/web/shared`.
- Settings validation request/response types from `@devvit/web/shared`.

The installed Devvit report trigger payloads expose `reason`, reported `post` or `comment`, and `subreddit` metadata. They do not expose reporter identity. SiftMod never claims to identify anonymous reporters.

## Install Settings

Configured in `devvit.json` under `settings.subreddit`:

- `abusiveReportMasking`: mask matching abusive report text in summaries.
- `keywordList`: newline or comma separated keyword/regex rules. Prefixes supported: `slur:`, `threat:`, `harassment:`, `doxxing:`, `keyword:`.
- `floodThresholdCount`: report count that escalates an incident to high severity.
- `floodWindowMinutes`: clustering and flood detection time window.
- `notifyHighSeverity`: send modmail notification for high-severity incidents.
- `demoSeedEnabled`: enable the clearly labeled demo seed action.

Regex entries can use `/pattern/flags`, for example `threat:/\\bthreat phrase\\b/i`.

## Project Structure

```text
src/
  index.ts                 Hono server setup
  core/
    incidents.ts           SiftMod settings, clustering, Redis, evidence packets
  routes/
    api.ts                 Reserved public API route
    forms.ts               Mark reviewed and save internal notes
    menu.ts                Summary, demo seed, queue, and diagnostics actions
    settings.ts            Keyword regex settings validation
    triggers.ts            App install, post report, comment report triggers
```

## Local Commands

```bash
npm install
npm run type-check
npm run lint
npm run build
npm run dev
```

`npm run dev` maps to `devvit playtest` and requires a logged-in Devvit CLI plus a configured development subreddit.

## Demo Script

1. Install or playtest SiftMod on a development subreddit.
2. Open the app settings and confirm:
   - Mask abusive report text: enabled.
   - Flood threshold count: `3`.
   - Flood time window minutes: `30`.
   - Enable demo seed action: enabled.
3. Create a test post or comment.
4. As a moderator, open the post/comment menu and select **Seed SiftMod demo incident**.
5. Open the same target menu and select **View SiftMod report summary**.
6. Show the evidence packet:
   - high severity headline
   - why SiftMod flagged it
   - recommended moderator action
   - masked reason preview
   - report counts and fingerprint
   - demo seed label
   - explicit limitation that reporter identity is not exposed
7. Add a short internal note and submit the form to mark the incident reviewed.
8. Reopen the summary, check **Ignore reports on this target**, and submit.
9. Reopen the summary to show reviewed status, the internal note, and the `Reddit action` audit line.
10. Open the subreddit menu and select **View SiftMod incident queue**.
11. Show high severity, reviewed/unreviewed, and demo incident counts.
12. If menu behavior is unclear during setup, select **Run SiftMod diagnostics** from the subreddit menu to verify Redis and settings.

For an end-to-end live trigger demo, use a non-moderator account to report the test post/comment with a reason matching the keyword list, then open the same report summary action.

## Limitations

- Devvit report triggers in the installed package expose a `reason` string but no reporter identity.
- SiftMod cannot prove coordinated abuse by specific users; it only clusters report metadata that Devvit exposes.
- If Reddit does not expose exact custom report text in a future runtime or context, SiftMod degrades to available report reason/metadata.
- Internal notes are stored in SiftMod Redis, not Reddit mod notes, because Reddit mod notes require a user target and anonymous reporter identity is not available.
- Ignoring reports is opt-in and requires Reddit moderator permissions for posts.
- SiftMod does not call `snoozeReports(reason)` because that would require storing or reusing exact free-form report text.
- The target summary shows the latest incident for that target. The subreddit queue shows the latest 5 incidents across the community.
- Demo seed incidents are clearly labeled as demo data and can be disabled in settings.

## Hackathon Submission Draft

**SiftMod** helps subreddit moderators triage report abuse without forcing them to repeatedly read abusive custom report text. It listens to Devvit post/comment report triggers, clusters repeated reports in Redis, detects high-severity report floods or abusive patterns with configurable keyword/regex rules, and generates a concise evidence packet from the post/comment moderator menu.

The app is intentionally explainable and actionable: every summary shows why the incident was flagged, recommended moderator action, clustering method, report counts, masking status, and API limitations. After review, moderators can optionally ignore reports on the target from the same workflow. A subreddit incident queue gives teams a fast triage view, and a clearly labeled demo seed action makes the workflow reliable to judge. SiftMod does not claim to identify anonymous reporters.
