# SiftMod

SiftMod is a Reddit Devvit moderation app for triaging report abuse and report floods. It listens for post and comment report triggers, stores clustered incidents in Redis, masks abusive report text when configured, and gives moderators a short evidence packet from the post/comment overflow menu.

## MVP Features

- Listens to `onPostReport` and `onCommentReport` Devvit triggers.
- Stores report incidents in Redis with a 60 day TTL.
- Clusters by target thing ID, normalized report reason fingerprint, and configurable time window.
- Detects high-severity incidents from configured abusive keyword/regex matches, repeated identical reports, and target-level report floods.
- Masks abusive report text in moderator-facing summaries when masking is enabled.
- Adds a moderator menu action on posts and comments: **View SiftMod report summary**.
- Lets moderators mark the latest incident reviewed and save a short internal review note in Redis.
- Can optionally send a modmail notification for high-severity incidents.

## Devvit APIs Used

This project uses the Devvit web server style from `@devvit/web/server`:

- `redis` for incident persistence and target indexes.
- `settings` for subreddit install settings.
- `reddit.modMail.createModNotification` for optional high-severity notifications.
- Hono internal endpoints configured in `devvit.json`.
- Trigger request types from `@devvit/web/shared`.

The installed Devvit report trigger payloads expose `reason`, reported `post` or `comment`, and `subreddit` metadata. They do not expose reporter identity. SiftMod never claims to identify anonymous reporters.

## Install Settings

Configured in `devvit.json` under `settings.subreddit`:

- `abusiveReportMasking`: mask matching abusive report text in summaries.
- `keywordList`: newline or comma separated keyword/regex rules. Prefixes supported: `slur:`, `threat:`, `harassment:`, `doxxing:`, `keyword:`.
- `floodThresholdCount`: report count that escalates an incident to high severity.
- `floodWindowMinutes`: clustering and flood detection time window.
- `notifyHighSeverity`: send modmail notification for high-severity incidents.

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
    menu.ts                Moderator menu summary action
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
3. Create a test post or comment.
4. Submit repeated reports against that target with the same reason, or a reason that matches a configured keyword/regex.
5. As a moderator, open the post/comment menu and select **View SiftMod report summary**.
6. Show the evidence packet:
   - severity
   - report count for the identical-reason cluster
   - report count for the target within the time window
   - reason fingerprint
   - matched categories
   - masking status
   - clustering method
   - explicit limitation that reporter identity is not exposed
7. Add a short internal note and submit the form to mark the incident reviewed.
8. Reopen the summary to show reviewed status and the internal note.

## Limitations

- Devvit report triggers in the installed package expose a `reason` string but no reporter identity.
- SiftMod cannot prove coordinated abuse by specific users; it only clusters report metadata that Devvit exposes.
- If Reddit does not expose exact custom report text in a future runtime or context, SiftMod degrades to available report reason/metadata.
- Internal notes are stored in SiftMod Redis, not Reddit mod notes, because Reddit mod notes require a user target and anonymous reporter identity is not available.
- The MVP summarizes the latest incident for a target from the menu action. A future version could add a full incident history view.

## Hackathon Submission Draft

**SiftMod** helps subreddit moderators triage report abuse without forcing them to repeatedly read abusive custom report text. It listens to Devvit post/comment report triggers, clusters repeated reports in Redis, detects high-severity report floods or abusive patterns with configurable keyword/regex rules, and generates a concise evidence packet from the post/comment moderator menu.

The app is intentionally explainable: every summary shows the clustering method, severity signals, report counts, masking status, and API limitations. SiftMod does not claim to identify anonymous reporters. It focuses on reducing moderator exposure, preserving incident context, and giving mod teams a fast review workflow during report floods.
