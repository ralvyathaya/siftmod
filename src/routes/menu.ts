import { Hono } from 'hono';
import type { MenuItemRequest, UiResponse } from '@devvit/web/shared';
import {
  createEmptyEvidencePacket,
  createEvidencePacket,
  getLatestIncidentForTarget,
} from '../core/incidents';

export const menu = new Hono();

const buildSummaryForm = (targetId: string, incidentKey: string, body: string) => ({
  title: 'SiftMod Report Summary',
  fields: [
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
    {
      name: 'note',
      label: 'Internal review note',
      type: 'paragraph' as const,
      helpText: 'Optional. Saved only in SiftMod Redis.',
    },
  ],
  acceptLabel: incidentKey === 'none' ? 'Close' : 'Mark reviewed',
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
