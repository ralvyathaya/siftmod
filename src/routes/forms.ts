import { Hono } from 'hono';
import type { UiResponse } from '@devvit/web/shared';
import { ignoreReportsForIncident, reviewIncident } from '../core/incidents';

type ReportSummaryValues = {
  ignoreReports?: boolean;
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
  if (!result.ok) {
    return c.json<UiResponse>(
      {
        showToast: result.message,
      },
      200
    );
  }

  if (values.ignoreReports) {
    const actionResult = await ignoreReportsForIncident(values.incidentKey);

    return c.json<UiResponse>(
      {
        showToast: actionResult.ok
          ? {
              text: 'SiftMod incident reviewed and reports ignored.',
              appearance: 'success',
            }
          : `Incident reviewed, but ${actionResult.message}`,
      },
      200
    );
  }

  return c.json<UiResponse>(
    {
      showToast: {
        text: 'SiftMod incident marked reviewed.',
        appearance: 'success',
      },
    },
    200
  );
});

forms.post('/incident-queue-submit', (c) =>
  c.json<UiResponse>(
    {
      showToast: 'SiftMod incident queue closed.',
    },
    200
  )
);

forms.post('/diagnostics-submit', (c) =>
  c.json<UiResponse>(
    {
      showToast: 'SiftMod diagnostics closed.',
    },
    200
  )
);
