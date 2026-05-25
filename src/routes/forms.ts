import { Hono } from 'hono';
import type { UiResponse } from '@devvit/web/shared';
import { reviewIncident } from '../core/incidents';

type ReportSummaryValues = {
  incidentKey?: string;
  note?: string;
};

export const forms = new Hono();

forms.post('/report-incident-summary-submit', async (c) => {
  const values = await c.req.json<ReportSummaryValues>();

  if (!values.incidentKey || values.incidentKey === 'none') {
    return c.json<UiResponse>(
      {
        showToast: 'No SiftMod incident was available to review.',
      },
      200
    );
  }

  const result = await reviewIncident(values.incidentKey, values.note);

  return c.json<UiResponse>(
    {
      showToast: result.ok
        ? {
            text: 'SiftMod incident marked reviewed.',
            appearance: 'success',
          }
        : result.message,
    },
    200
  );
});
