import { reddit, redis, settings } from '@devvit/web/server';
import { isT5 } from '@devvit/shared-types/tid.js';

const KEY_PREFIX = 'siftmod';
const INCIDENT_TTL_SECONDS = 60 * 60 * 24 * 60;

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

export type SiftModSettings = {
  abusiveReportMasking: boolean;
  keywordList: string;
  floodThresholdCount: number;
  floodWindowMinutes: number;
  notifyHighSeverity: boolean;
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
  internalNotes: InternalNote[];
  notificationSentAt?: number;
};

export type ReportEventInput = {
  targetId: string;
  targetKind: TargetKind;
  reason: string;
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

const splitKeywordList = (keywordList: string) =>
  keywordList
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

const parsePattern = (entry: string): ParsedPattern | undefined => {
  const categorized = entry.match(
    /^(slur|threat|harassment|doxxing|keyword)\s*:\s*(.+)$/i
  );
  const category = categorized?.[1]?.toLocaleLowerCase() ?? 'keyword';
  const raw = categorized?.[2]?.trim() ?? entry;

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

  const indexKey = targetIndexKey(input.targetId);
  await redis.zAdd(indexKey, { member: key, score: now });
  await redis.expire(indexKey, INCIDENT_TTL_SECONDS);
  await redis.zRemRangeByScore(indexKey, 0, now - windowMs * 4);

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
    `SiftMod evidence packet for ${incident.targetKind} ${incident.targetId}`,
    '',
    `Severity: ${incident.severity}`,
    `Status: ${statusLine(incident)}`,
    `Reports in this identical-reason cluster: ${incident.count}`,
    `Reports on same target in ${incident.windowMinutes} minute window: ${incident.targetReportCountInWindow}`,
    `First report seen: ${formatDate(incident.firstReportedAt)}`,
    `Last report seen: ${formatDate(incident.lastReportedAt)}`,
    `Reason preview: ${incident.reasonPreview}`,
    `Reason fingerprint: ${incident.reasonFingerprint}`,
    `Matched categories: ${categoryText}`,
    `Signals: ${signalText}`,
  ];

  if (incident.targetPermalink) {
    lines.push(`Permalink: ${incident.targetPermalink}`);
  }

  if (incident.targetTitle) {
    lines.push(`Target title: ${incident.targetTitle}`);
  }

  if (incident.targetExcerpt) {
    lines.push(`Target excerpt: ${incident.targetExcerpt}`);
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
