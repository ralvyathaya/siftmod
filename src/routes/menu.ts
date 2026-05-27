import { Hono } from 'hono';
import { context } from '@devvit/web/server';
import type { MenuItemRequest, UiResponse } from '@devvit/web/shared';
import type { FormField } from '@devvit/shared-types/shared/form.js';
import {
  createIncidentQueuePacket,
  createDiagnosticsPacket,
  createEmptyEvidencePacket,
  createEvidencePacket,
  getIncidentQueueForSubreddit,
  getLatestIncidentForTarget,
  seedDemoIncidentForTarget,
} from '../core/incidents';

export const menu = new Hono();

const buildSummaryForm = (targetId: string, incidentKey: string, body: string) => {
  const fields: FormField[] = [
    {
      name: 'summary',
      label: 'Evidence packet',
      type: 'paragraph' as const,
      defaultValue: body,
      disabled: true,
    },
    {
      name: 'incidentKey',
      label: 'Incident key',
      type: 'string' as const,
      defaultValue: incidentKey,
      required: true,
      helpText: 'Leave unchanged to mark this SiftMod incident reviewed.',
    },
    {
      name: 'targetId',
      label: 'Target ID',
      type: 'string' as const,
      defaultValue: targetId,
      required: true,
      disabled: true,
    },
  ];

  if (incidentKey !== 'none') {
    fields.push({
      name: 'ignoreReports',
      label: 'Ignore reports on this target',
      type: 'boolean',
      defaultValue: false,
      helpText: 'Calls Reddit ignoreReports() for this post/comment after review.',
    });
  }

  fields.push(
    {
      name: 'note',
      label: 'Internal review note',
      type: 'paragraph' as const,
      helpText: 'Optional. Saved only in SiftMod Redis.',
    }
  );

  return {
    title: 'SiftMod Report Summary',
    fields,
    acceptLabel: incidentKey === 'none' ? 'Close' : 'Mark reviewed',
    cancelLabel: 'Cancel',
  };
};

const buildQueueForm = (body: string) => ({
  title: 'SiftMod Incident Queue',
  fields: [
    {
      name: 'queue',
      label: 'Incident queue',
      type: 'paragraph' as const,
      defaultValue: body,
      disabled: true,
    },
  ],
  acceptLabel: 'Close',
  cancelLabel: 'Cancel',
});

const buildDiagnosticsForm = (body: string) => ({
  title: 'SiftMod Diagnostics',
  fields: [
    {
      name: 'diagnostics',
      label: 'Diagnostics',
      type: 'paragraph' as const,
      defaultValue: body,
      disabled: true,
    },
  ],
  acceptLabel: 'Close',
  cancelLabel: 'Cancel',
});

menu.post('/report-summary', async (c) => {
  const request = await c.req.json<MenuItemRequest>();
  const incident = await getLatestIncidentForTarget(request.targetId);
  const body = incident
    ? createEvidencePacket(incident)
    : createEmptyEvidencePacket(request.targetId);

  return c.json<UiResponse>(
    {
      showForm: {
        name: 'reportIncidentSummary',
        form: buildSummaryForm(
          request.targetId,
          incident?.redisKey ?? 'none',
          body
        ),
      },
    },
    200
  );
});

menu.post('/seed-demo-incident', async (c) => {
  const request = await c.req.json<MenuItemRequest>();
  const result = await seedDemoIncidentForTarget(
    request.targetId,
    context.subredditId
  );

  return c.json<UiResponse>(
    {
      showToast: result.ok
        ? {
            text: `Seeded demo ${result.incident.severity} SiftMod incident.`,
            appearance: 'success',
          }
        : result.message,
    },
    200
  );
});

menu.post('/incident-queue', async (c) => {
  const request = await c.req.json<MenuItemRequest>();
  const subredditId = request.targetId || context.subredditId;

  if (!subredditId) {
    return c.json<UiResponse>(
      {
        showToast: 'SiftMod could not determine this subreddit.',
      },
      200
    );
  }

  const summary = await getIncidentQueueForSubreddit(subredditId);

  return c.json<UiResponse>(
    {
      showForm: {
        name: 'incidentQueue',
        form: buildQueueForm(createIncidentQueuePacket(summary)),
      },
    },
    200
  );
});

menu.post('/diagnostics', async (c) => {
  const request = await c.req.json<MenuItemRequest>();
  const subredditId = request.targetId || context.subredditId;
  const body = await createDiagnosticsPacket(subredditId);

  return c.json<UiResponse>(
    {
      showForm: {
        name: 'siftModDiagnostics',
        form: buildDiagnosticsForm(body),
      },
    },
    200
  );
});
