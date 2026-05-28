import { reddit, redis, settings } from '@devvit/web/server';
import { isT1, isT3, isT5 } from '@devvit/shared-types/tid.js';

const KEY_PREFIX = 'siftmod';
const INCIDENT_TTL_SECONDS = 60 * 60 * 24 * 60;
const DEMO_REPORT_REASON = 'kys mass report';
const DEMO_SEED_REPORTS = 3;
const QUEUE_SCAN_LIMIT = 50;

const DEFAULT_KEYWORDS = [
  'threat:kill yourself',
  'threat:kys',
  'threat:i will kill',
  'threat:death threat',
  'harassment:harass',
  'harassment:stalk',
  'harassment:mass report',
  'doxxing:dox',
  'doxxing:doxx',
  'doxxing:address',
  'doxxing:phone number',
  'doxxing:ip address',
  'doxxing:swat',
].join('\n');

type Severity = 'low' | 'medium' | 'high';
type TargetKind = 'post' | 'comment';
type IncidentSource = 'real' | 'demo';

export type SiftModSettings = {
  abusiveReportMasking: boolean;
  keywordList: string;
  floodThresholdCount: number;
  floodWindowMinutes: number;
  notifyHighSeverity: boolean;
  demoSeedEnabled: boolean;
};

export type InternalNote = {
  body: string;
  createdAt: number;
  moderator?: string;
};

export type ReportIncident = {
  redisKey: string;
  targetId: string;
  targetKind: TargetKind;
  source?: IncidentSource;
  subredditId?: string;
  subredditName?: string;
  reasonFingerprint: string;
  reasonPreview: string;
  reasonMasked: boolean;
  count: number;
  targetReportCountInWindow: number;
  firstReportedAt: number;
  lastReportedAt: number;
  windowMinutes: number;
  bucket: number;
  severity: Severity;
  signals: string[];
  matchedCategories: string[];
  targetPermalink?: string;
  targetTitle?: string;
  targetExcerpt?: string;
  reviewedAt?: number;
  reviewedBy?: string;
  ignoredReportsAt?: number;
  ignoredReportsBy?: string;
  internalNotes: InternalNote[];
  notificationSentAt?: number;
};

export type ReportEventInput = {
  targetId: string;
  targetKind: TargetKind;
  reason: string;
  source?: IncidentSource;
  subredditId?: string;
  subredditName?: string;
  targetPermalink?: string;
  targetTitle?: string;
  targetExcerpt?: string;
};

type PatternMatch = {
  category: string;
};

type ParsedPattern = {
  category: string;
  raw: string;
  regex?: RegExp;
  text?: string;
};

type ReviewResult =
  | { ok: true; incident: ReportIncident }
  | { ok: false; message: string };

type ActionResult =
  | { ok: true; incident: ReportIncident; message: string }
  | { ok: false; message: string };

type SeedDemoIncidentResult =
  | { ok: true; incident: ReportIncident }
  | { ok: false; message: string };

export type IncidentQueueSummary = {
  incidents: ReportIncident[];
  totalCount: number;
  highSeverityCount: number;
  unreviewedCount: number;
  reviewedCount: number;
  demoCount: number;
};

const safeJsonParse = (value: string): ReportIncident | undefined => {
  try {
    return JSON.parse(value) as ReportIncident;
  } catch (error) {
    console.error('Failed to parse SiftMod incident JSON', error);
    return undefined;
  }
};

const normalizeReason = (reason: string) =>
  reason.trim().replace(/\s+/g, ' ').toLocaleLowerCase();

const stableHash = (value: string) => {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }

  return (hash >>> 0).toString(36);
};

const truncate = (value: string, maxLength: number) => {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength - 3)}...`;
};

const asBoolean = (value: unknown, fallback: boolean) =>
  typeof value === 'boolean' ? value : fallback;

const asNumber = (
  value: unknown,
  fallback: number,
  minimum: number,
  maximum: number
) => {
  const numberValue = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numberValue)) {
    return fallback;
  }

  return Math.min(Math.max(Math.floor(numberValue), minimum), maximum);
};

const incidentKey = (
  subredditId: string | undefined,
  targetId: string,
  reasonFingerprint: string,
  bucket: number
) =>
  [
    KEY_PREFIX,
    'incident',
    subredditId ?? 'unknown-subreddit',
    targetId,
    bucket.toString(),
    reasonFingerprint,
  ].join(':');

const targetIndexKey = (targetId: string) =>
  [KEY_PREFIX, 'target', targetId, 'incidents'].join(':');

const subredditIndexKey = (subredditId: string | undefined) =>
  [KEY_PREFIX, 'subreddit', subredditId ?? 'unknown-subreddit', 'incidents'].join(
    ':'
  );

const splitKeywordList = (keywordList: string) =>
  keywordList
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

const getPatternParts = (entry: string) => {
  const categorized = entry.match(
    /^(slur|threat|harassment|doxxing|keyword)\s*:\s*(.+)$/i
  );

  return {
    category: categorized?.[1]?.toLocaleLowerCase() ?? 'keyword',
    raw: categorized?.[2]?.trim() ?? entry,
  };
};

export const validateKeywordList = (keywordList: string) => {
  for (const entry of splitKeywordList(keywordList)) {
    const { raw } = getPatternParts(entry);
    if (!raw.startsWith('/')) {
      continue;
    }

    const regexMatch = raw.match(/^\/(.+)\/([dgimsuvy]*)$/);
    if (!regexMatch?.[1]) {
      return `Invalid regex entry: ${entry}`;
    }

    try {
      new RegExp(regexMatch[1], regexMatch[2] ?? 'i');
    } catch {
      return `Invalid regex entry: ${entry}`;
    }
  }

  return undefined;
};

const parsePattern = (entry: string): ParsedPattern | undefined => {
  const { category, raw } = getPatternParts(entry);

  if (!raw) {
    return undefined;
  }

  const regexMatch = raw.match(/^\/(.+)\/([dgimsuvy]*)$/);
  if (regexMatch?.[1]) {
    try {
      return {
        category,
        raw,
        regex: new RegExp(regexMatch[1], regexMatch[2] ?? 'i'),
      };
    } catch (error) {
      console.warn(`Skipping invalid SiftMod regex setting: ${raw}`, error);
      return undefined;
    }
  }

  return {
    category,
    raw,
    text: raw.toLocaleLowerCase(),
  };
};

const getPatterns = (keywordList: string) =>
  splitKeywordList(keywordList)
    .map(parsePattern)
    .filter((pattern): pattern is ParsedPattern => Boolean(pattern));

const matchReason = (reason: string, keywordList: string): PatternMatch[] => {
  const lowerReason = reason.toLocaleLowerCase();
  const matches: PatternMatch[] = [];

  for (const pattern of getPatterns(keywordList)) {
    const matched = pattern.regex
      ? pattern.regex.test(reason)
      : pattern.text
        ? lowerReason.includes(pattern.text)
        : false;

    if (matched) {
      matches.push({ category: pattern.category });
    }
  }

  return matches;
};

const unique = (values: string[]) => Array.from(new Set(values)).sort();

const severityForSignals = (signals: string[], count: number): Severity => {
  if (
    signals.includes('abusive-report-text') ||
    signals.includes('report-flood') ||
    signals.includes('repeated-identical-report')
  ) {
    return 'high';
  }

  if (count > 1) {
    return 'medium';
  }

  return 'low';
};

export async function getSiftModSettings(): Promise<SiftModSettings> {
  const values = await settings.getAll<Record<string, unknown>>();

  return {
    abusiveReportMasking: asBoolean(values.abusiveReportMasking, true),
    keywordList:
      typeof values.keywordList === 'string' && values.keywordList.trim()
        ? values.keywordList
        : DEFAULT_KEYWORDS,
    floodThresholdCount: asNumber(values.floodThresholdCount, 3, 2, 100),
    floodWindowMinutes: asNumber(values.floodWindowMinutes, 30, 1, 1440),
    notifyHighSeverity: asBoolean(values.notifyHighSeverity, false),
    demoSeedEnabled: asBoolean(values.demoSeedEnabled, true),
  };
}

export async function loadIncident(
  key: string
): Promise<ReportIncident | undefined> {
  const raw = await redis.get(key);
  return raw ? safeJsonParse(raw) : undefined;
}

const saveIncident = async (incident: ReportIncident) => {
  await redis.set(incident.redisKey, JSON.stringify(incident));
  await redis.expire(incident.redisKey, INCIDENT_TTL_SECONDS);
};

const indexIncident = async (incident: ReportIncident) => {
  const targetKey = targetIndexKey(incident.targetId);
  const subredditKey = subredditIndexKey(incident.subredditId);

  await redis.zAdd(targetKey, {
    member: incident.redisKey,
    score: incident.lastReportedAt,
  });
  await redis.expire(targetKey, INCIDENT_TTL_SECONDS);
  await redis.zAdd(subredditKey, {
    member: incident.redisKey,
    score: incident.lastReportedAt,
  });
  await redis.expire(subredditKey, INCIDENT_TTL_SECONDS);
};

const listRecentIncidentKeys = async (
  targetId: string,
  since: number,
  until: number
) => {
  const indexKey = targetIndexKey(targetId);
  const members = await redis.zRange(indexKey, since, until, { by: 'score' });
  return members.map((member) => member.member);
};

const countReportsForTargetWindow = async (
  targetId: string,
  since: number,
  until: number
) => {
  const keys = await listRecentIncidentKeys(targetId, since, until);
  let count = 0;

  for (const key of keys) {
    const incident = await loadIncident(key);
    count += incident?.count ?? 0;
  }

  return count;
};

const buildReasonPreview = (
  reason: string,
  shouldMask: boolean,
  matches: PatternMatch[]
) => {
  if (!reason.trim()) {
    return '[no report reason text exposed]';
  }

  if (shouldMask && matches.length > 0) {
    const categories = unique(matches.map((match) => match.category)).join(
      ', '
    );
    return `[masked abusive report text: ${categories}]`;
  }

  return truncate(reason.trim(), 240);
};

const sendHighSeverityNotification = async (incident: ReportIncident) => {
  if (!isT5(incident.subredditId)) {
    return false;
  }

  const subject = truncate(
    `SiftMod high severity report flood on ${incident.targetKind}`,
    100
  );

  await reddit.modMail.createModNotification({
    subredditId: incident.subredditId,
    subject,
    bodyMarkdown: createEvidencePacket(incident),
  });

  return true;
};

export async function recordReportIncident(
  input: ReportEventInput
): Promise<ReportIncident> {
  const config = await getSiftModSettings();
  const now = Date.now();
  const normalizedReason = normalizeReason(input.reason);
  const reasonFingerprint = stableHash(normalizedReason || 'no-reason');
  const windowMs = config.floodWindowMinutes * 60 * 1000;
  const bucket = Math.floor(now / windowMs);
  const matches = matchReason(input.reason, config.keywordList);
  const matchedCategories = unique(matches.map((match) => match.category));
  const key = incidentKey(
    input.subredditId,
    input.targetId,
    reasonFingerprint,
    bucket
  );
  const existingIncident = await loadIncident(key);
  const reasonMasked = config.abusiveReportMasking && matches.length > 0;
  const reasonPreview = buildReasonPreview(
    input.reason,
    config.abusiveReportMasking,
    matches
  );

  const incident: ReportIncident = {
    redisKey: key,
    targetId: input.targetId,
    targetKind: input.targetKind,
    source: existingIncident?.source ?? input.source ?? 'real',
    reasonFingerprint,
    reasonPreview,
    reasonMasked,
    count: (existingIncident?.count ?? 0) + 1,
    targetReportCountInWindow: existingIncident?.targetReportCountInWindow ?? 1,
    firstReportedAt: existingIncident?.firstReportedAt ?? now,
    lastReportedAt: now,
    windowMinutes: config.floodWindowMinutes,
    bucket,
    severity: existingIncident?.severity ?? 'low',
    signals: existingIncident?.signals ?? [],
    matchedCategories,
    internalNotes: existingIncident?.internalNotes ?? [],
    ...(input.subredditId ? { subredditId: input.subredditId } : {}),
    ...(input.subredditName ? { subredditName: input.subredditName } : {}),
    ...(input.targetPermalink
      ? { targetPermalink: input.targetPermalink }
      : {}),
    ...(input.targetTitle ? { targetTitle: truncate(input.targetTitle, 180) } : {}),
    ...(input.targetExcerpt
      ? { targetExcerpt: truncate(input.targetExcerpt, 500) }
      : {}),
    ...(existingIncident?.reviewedAt
      ? { reviewedAt: existingIncident.reviewedAt }
      : {}),
    ...(existingIncident?.reviewedBy
      ? { reviewedBy: existingIncident.reviewedBy }
      : {}),
    ...(existingIncident?.ignoredReportsAt
      ? { ignoredReportsAt: existingIncident.ignoredReportsAt }
      : {}),
    ...(existingIncident?.ignoredReportsBy
      ? { ignoredReportsBy: existingIncident.ignoredReportsBy }
      : {}),
    ...(existingIncident?.notificationSentAt
      ? { notificationSentAt: existingIncident.notificationSentAt }
      : {}),
  };

  const initialSignals = [
    ...incident.signals,
    ...(matches.length > 0 ? ['abusive-report-text'] : []),
    ...(incident.count >= config.floodThresholdCount
      ? ['repeated-identical-report']
      : []),
  ];

  incident.signals = unique(initialSignals);
  await saveIncident(incident);

  await indexIncident(incident);
  await Promise.all([
    redis.zRemRangeByScore(targetIndexKey(input.targetId), 0, now - windowMs * 4),
    redis.zRemRangeByScore(
      subredditIndexKey(input.subredditId),
      0,
      now - windowMs * 4
    ),
  ]);

  const targetReportCountInWindow = await countReportsForTargetWindow(
    input.targetId,
    now - windowMs,
    now
  );
  incident.targetReportCountInWindow = targetReportCountInWindow;

  if (targetReportCountInWindow >= config.floodThresholdCount) {
    incident.signals = unique([...incident.signals, 'report-flood']);
  }

  incident.severity = severityForSignals(incident.signals, incident.count);
  await saveIncident(incident);
  await indexIncident(incident);

  if (
    incident.severity === 'high' &&
    config.notifyHighSeverity &&
    !incident.notificationSentAt
  ) {
    try {
      const notificationSent = await sendHighSeverityNotification(incident);
      if (notificationSent) {
        incident.notificationSentAt = Date.now();
        await saveIncident(incident);
      }
    } catch (error) {
      console.error('Failed to send SiftMod high severity notification', error);
    }
  }

  return incident;
}

export async function getLatestIncidentForTarget(
  targetId: string
): Promise<ReportIncident | undefined> {
  const members = await redis.zRange(targetIndexKey(targetId), 0, 0, {
    by: 'rank',
    reverse: true,
  });
  const key = members[0]?.member;
  return key ? loadIncident(key) : undefined;
}

export async function getIncidentQueueForSubreddit(
  subredditId: string,
  limit = 5
): Promise<IncidentQueueSummary> {
  const members = await redis.zRange(
    subredditIndexKey(subredditId),
    0,
    QUEUE_SCAN_LIMIT - 1,
    {
      by: 'rank',
      reverse: true,
    }
  );
  const incidents: ReportIncident[] = [];

  for (const member of members) {
    const incident = await loadIncident(member.member);
    if (incident) {
      incidents.push(incident);
    }
  }

  return {
    incidents: incidents.slice(0, limit),
    totalCount: incidents.length,
    highSeverityCount: incidents.filter(
      (incident) => incident.severity === 'high'
    ).length,
    unreviewedCount: incidents.filter((incident) => !incident.reviewedAt)
      .length,
    reviewedCount: incidents.filter((incident) => Boolean(incident.reviewedAt))
      .length,
    demoCount: incidents.filter((incident) => incident.source === 'demo')
      .length,
  };
}

export async function seedDemoIncidentForTarget(
  targetId: string,
  fallbackSubredditId?: string
): Promise<SeedDemoIncidentResult> {
  const config = await getSiftModSettings();
  if (!config.demoSeedEnabled) {
    return {
      ok: false,
      message: 'SiftMod demo seeding is disabled in app settings.',
    };
  }

  if (!isT1(targetId) && !isT3(targetId)) {
    return {
      ok: false,
      message: 'SiftMod demo seeding only supports posts and comments.',
    };
  }

  const baseInput: Omit<ReportEventInput, 'reason'> = {
    targetId,
    targetKind: isT3(targetId) ? 'post' : 'comment',
    source: 'demo',
    ...(fallbackSubredditId ? { subredditId: fallbackSubredditId } : {}),
  };
  let input = baseInput;

  try {
    if (isT3(targetId)) {
      const post = await reddit.getPostById(targetId);
      input = {
        ...baseInput,
        ...(post.subredditId ? { subredditId: post.subredditId } : {}),
        ...(post.subredditName ? { subredditName: post.subredditName } : {}),
        ...(post.permalink ? { targetPermalink: post.permalink } : {}),
        ...(post.title ? { targetTitle: post.title } : {}),
        ...(post.body ? { targetExcerpt: post.body } : {}),
      };
    } else {
      const comment = await reddit.getCommentById(targetId);
      input = {
        ...baseInput,
        ...(comment.subredditId ? { subredditId: comment.subredditId } : {}),
        ...(comment.subredditName
          ? { subredditName: comment.subredditName }
          : {}),
        ...(comment.permalink ? { targetPermalink: comment.permalink } : {}),
        ...(comment.body ? { targetExcerpt: comment.body } : {}),
      };
    }
  } catch (error) {
    console.warn('SiftMod demo seed used fallback target metadata', error);
  }

  let incident: ReportIncident | undefined;
  for (let index = 0; index < DEMO_SEED_REPORTS; index += 1) {
    incident = await recordReportIncident({
      ...input,
      reason: DEMO_REPORT_REASON,
    });
  }

  if (!incident) {
    return {
      ok: false,
      message: 'SiftMod could not seed a demo incident.',
    };
  }

  return { ok: true, incident };
}

export async function reviewIncident(
  incidentKeyValue: string,
  note?: string
): Promise<ReviewResult> {
  if (!incidentKeyValue.startsWith(`${KEY_PREFIX}:incident:`)) {
    return {
      ok: false,
      message: 'Invalid SiftMod incident key.',
    };
  }

  const incident = await loadIncident(incidentKeyValue);
  if (!incident) {
    return {
      ok: false,
      message: 'SiftMod incident was not found.',
    };
  }

  const moderator = await reddit.getCurrentUsername();
  const now = Date.now();
  const trimmedNote = note?.trim();

  incident.reviewedAt = now;
  if (moderator) {
    incident.reviewedBy = moderator;
  }

  if (trimmedNote) {
    incident.internalNotes = [
      ...incident.internalNotes,
      {
        body: truncate(trimmedNote, 1000),
        createdAt: now,
        ...(moderator ? { moderator } : {}),
      },
    ];
  }

  await saveIncident(incident);

  return { ok: true, incident };
}

export async function ignoreReportsForIncident(
  incidentKeyValue: string
): Promise<ActionResult> {
  if (!incidentKeyValue.startsWith(`${KEY_PREFIX}:incident:`)) {
    return {
      ok: false,
      message: 'Invalid SiftMod incident key.',
    };
  }

  const incident = await loadIncident(incidentKeyValue);
  if (!incident) {
    return {
      ok: false,
      message: 'SiftMod incident was not found.',
    };
  }

  const user = await reddit.getCurrentUser();
  if (!user) {
    return {
      ok: false,
      message: "Couldn't confirm the current moderator.",
    };
  }

  try {
    if (isT3(incident.targetId)) {
      const post = await reddit.getPostById(incident.targetId);
      const permissions = await user.getModPermissionsForSubreddit(
        post.subredditName
      );
      const canIgnoreReports =
        permissions.includes('all') || permissions.includes('posts');

      if (!canIgnoreReports) {
        return {
          ok: false,
          message: 'You need posts or all moderator permission to ignore reports.',
        };
      }

      await post.ignoreReports();
      incident.subredditName = post.subredditName;
      incident.subredditId = post.subredditId;
    } else if (isT1(incident.targetId)) {
      const comment = await reddit.getCommentById(incident.targetId);
      const permissions = await user.getModPermissionsForSubreddit(
        comment.subredditName
      );
      const canIgnoreReports =
        permissions.includes('all') || permissions.includes('posts');

      if (!canIgnoreReports) {
        return {
          ok: false,
          message: 'You need posts or all moderator permission to ignore reports.',
        };
      }

      await comment.ignoreReports();
      incident.subredditName = comment.subredditName;
      incident.subredditId = comment.subredditId;
    } else {
      return {
        ok: false,
        message: 'SiftMod can only ignore reports on posts or comments.',
      };
    }
  } catch (error) {
    console.error('Failed to ignore reports for SiftMod incident', error);
    return {
      ok: false,
      message: 'Reddit did not accept the ignore reports action.',
    };
  }

  incident.ignoredReportsAt = Date.now();
  incident.ignoredReportsBy = user.username;
  await saveIncident(incident);
  await indexIncident(incident);

  return {
    ok: true,
    incident,
    message: 'Reports ignored on this target.',
  };
}

const formatDate = (timestamp: number | undefined) => {
  if (!timestamp) {
    return 'unknown';
  }

  return new Date(timestamp).toISOString();
};

const statusLine = (incident: ReportIncident) => {
  if (!incident.reviewedAt) {
    return 'Unreviewed';
  }

  return `Reviewed by ${incident.reviewedBy ?? 'a moderator'} at ${formatDate(
    incident.reviewedAt
  )}`;
};

const sourceLine = (incident: ReportIncident) =>
  incident.source === 'demo' ? 'DEMO seed data' : 'Live report trigger';

const recommendedActions = (incident: ReportIncident) => {
  if (incident.severity === 'high') {
    return [
      'Review the target content before taking action.',
      'If reports are abusive or flooding, optionally ignore reports from this summary.',
      'Notify the mod team if this pattern is active or repeated.',
    ];
  }

  if (incident.severity === 'medium') {
    return [
      'Review the target normally.',
      'Check whether the same reason keeps repeating on this target.',
    ];
  }

  return [
    'Review the target normally.',
    'No flood or abusive-report pattern has crossed the configured threshold yet.',
  ];
};

const whyFlagged = (incident: ReportIncident) => {
  const reasons: string[] = [];

  if (incident.source === 'demo') {
    reasons.push('Seed incident for development and QA review.');
  }

  if (incident.reasonMasked) {
    reasons.push('Report reason matched configured abusive patterns and was masked.');
  }

  if (incident.signals.includes('repeated-identical-report')) {
    reasons.push(`${incident.count} matching reports used the same reason.`);
  }

  if (incident.signals.includes('report-flood')) {
    reasons.push(
      `${incident.targetReportCountInWindow} reports hit this target within ${incident.windowMinutes} minutes.`
    );
  }

  if (reasons.length === 0) {
    reasons.push('Stored for moderator review; no high-risk pattern crossed threshold.');
  }

  return reasons;
};

const formatBullets = (values: string[]) =>
  values.map((value) => `- ${value}`).join('\n');

const redditActionLine = (incident: ReportIncident) => {
  if (!incident.ignoredReportsAt) {
    return 'No Reddit action applied from SiftMod yet.';
  }

  const moderator = incident.ignoredReportsBy
    ? `u/${incident.ignoredReportsBy}`
    : 'a moderator';

  return `Reports ignored by ${moderator} at ${formatDate(
    incident.ignoredReportsAt
  )}`;
};

export function createEvidencePacket(incident: ReportIncident): string {
  const signalText =
    incident.signals.length > 0 ? incident.signals.join(', ') : 'none';
  const categoryText =
    incident.matchedCategories.length > 0
      ? incident.matchedCategories.join(', ')
      : 'none';
  const noteText =
    incident.internalNotes.length > 0
      ? incident.internalNotes
          .map(
            (note) =>
              `- ${formatDate(note.createdAt)} ${
                note.moderator ? `u/${note.moderator}: ` : ''
              }${note.body}`
          )
          .join('\n')
      : '- none';

  const lines = [
    `SiftMod found a ${incident.severity.toUpperCase()} severity report incident`,
    '',
    'Why flagged:',
    formatBullets(whyFlagged(incident)),
    '',
    'Recommended mod action:',
    formatBullets(recommendedActions(incident)),
    '',
    'Evidence:',
    `- Target: ${incident.targetKind} ${incident.targetId}`,
    `- Source: ${sourceLine(incident)}`,
    `- Status: ${statusLine(incident)}`,
    `- Reddit action: ${redditActionLine(incident)}`,
    `- Reports in identical-reason cluster: ${incident.count}`,
    `- Reports on same target in ${incident.windowMinutes} minute window: ${incident.targetReportCountInWindow}`,
    `- First report seen: ${formatDate(incident.firstReportedAt)}`,
    `- Last report seen: ${formatDate(incident.lastReportedAt)}`,
    `- Reason preview: ${incident.reasonPreview}`,
    `- Reason fingerprint: ${incident.reasonFingerprint}`,
    `- Matched categories: ${categoryText}`,
    `- Signals: ${signalText}`,
  ];

  if (incident.targetPermalink) {
    lines.push(`- Permalink: ${incident.targetPermalink}`);
  }

  if (incident.targetTitle) {
    lines.push(`- Target title: ${incident.targetTitle}`);
  }

  if (incident.targetExcerpt) {
    lines.push(`- Target excerpt: ${incident.targetExcerpt}`);
  }

  lines.push(
    '',
    'Clustering method:',
    `- Same target thing ID: ${incident.targetId}`,
    '- Same normalized report reason fingerprint',
    `- Same ${incident.windowMinutes} minute time bucket`,
    '',
    'Limitations:',
    '- Reddit report triggers do not expose reporter identity to this app.',
    '- SiftMod only summarizes report metadata and reason text exposed by Devvit.',
    '- If abusive masking is enabled, matched report text is masked in moderator-facing output.',
    '',
    'Internal notes:',
    noteText
  );

  return lines.join('\n');
}

export function createIncidentQueuePacket(summary: IncidentQueueSummary): string {
  const lines = [
    'SiftMod incident queue',
    '',
    `Recent incidents scanned: ${summary.totalCount}`,
    `High severity: ${summary.highSeverityCount}`,
    `Unreviewed: ${summary.unreviewedCount}`,
    `Reviewed: ${summary.reviewedCount}`,
    `Demo incidents: ${summary.demoCount}`,
    '',
    'Top incidents:',
  ];

  if (summary.incidents.length === 0) {
    lines.push('- No SiftMod incidents have been stored for this subreddit yet.');
    return lines.join('\n');
  }

  summary.incidents.forEach((incident, index) => {
    const reviewStatus = incident.reviewedAt ? 'reviewed' : 'unreviewed';
    const demoLabel = incident.source === 'demo' ? 'DEMO' : 'LIVE';

    lines.push(
      `${index + 1}. [${incident.severity.toUpperCase()}] [${demoLabel}] ${reviewStatus}`,
      `   Target: ${incident.targetKind} ${incident.targetId}`,
      `   Reports: ${incident.count} identical / ${incident.targetReportCountInWindow} target-window`,
      `   Reason: ${incident.reasonPreview}`,
      `   Last seen: ${formatDate(incident.lastReportedAt)}`
    );

    if (incident.targetPermalink) {
      lines.push(`   Permalink: ${incident.targetPermalink}`);
    }
  });

  return lines.join('\n');
}

export async function createDiagnosticsPacket(subredditId?: string) {
  const config = await getSiftModSettings();
  const key = [
    KEY_PREFIX,
    'diagnostics',
    subredditId ?? 'unknown-subreddit',
    Date.now().toString(),
  ].join(':');
  const value = 'ok';
  let redisStatus: string;

  try {
    await redis.set(key, value);
    await redis.expire(key, 60);
    redisStatus = (await redis.get(key)) === value ? 'ok' : 'read mismatch';
    await redis.del(key);
  } catch (error) {
    redisStatus = `failed: ${String(error)}`;
  }

  return [
    'SiftMod diagnostics',
    '',
    `Subreddit ID: ${subredditId ?? 'unknown'}`,
    `Redis write/read/delete: ${redisStatus}`,
    `Demo seed enabled: ${config.demoSeedEnabled ? 'yes' : 'no'}`,
    `Mask abusive report text: ${config.abusiveReportMasking ? 'yes' : 'no'}`,
    `Flood threshold count: ${config.floodThresholdCount}`,
    `Flood window minutes: ${config.floodWindowMinutes}`,
    `High severity modmail notification: ${
      config.notifyHighSeverity ? 'yes' : 'no'
    }`,
    '',
    'Operational notes:',
    '- Mods usually cannot produce realistic self-report flows alone.',
    '- Use Seed SiftMod demo incident on a post/comment for development testing.',
    '- Use a non-mod account for true end-to-end report trigger testing.',
    '- SiftMod never identifies anonymous reporters.',
  ].join('\n');
}

export function createEmptyEvidencePacket(targetId: string): string {
  return [
    `SiftMod report summary for ${targetId}`,
    '',
    'No SiftMod report incident has been stored for this target yet.',
    '',
    'Possible reasons:',
    '- The app was installed after the report was created.',
    '- The target has not received a post/comment report trigger yet.',
    '- Reddit did not expose enough report metadata for this app to cluster.',
    '',
    'SiftMod does not identify anonymous reporters.',
  ].join('\n');
}
