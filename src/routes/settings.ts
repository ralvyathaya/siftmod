import { Hono } from 'hono';
import type {
  SettingsValidationRequest,
  SettingsValidationResponse,
} from '@devvit/web/shared';
import { validateKeywordList } from '../core/incidents';

export const settingRoutes = new Hono();

settingRoutes.post('/validate-keywords', async (c) => {
  const request = await c.req.json<SettingsValidationRequest<string>>();
  const error = validateKeywordList(request.value ?? '');

  return c.json<SettingsValidationResponse>(
    error
      ? {
          success: false,
          error,
        }
      : {
          success: true,
        },
    200
  );
});
