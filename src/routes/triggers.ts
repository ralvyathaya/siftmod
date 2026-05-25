import { Hono } from 'hono';
import type {
  OnAppInstallRequest,
  OnCommentReportRequest,
  OnPostReportRequest,
  TriggerResponse,
} from '@devvit/web/shared';
import { recordReportIncident } from '../core/incidents';

export const triggers = new Hono();

triggers.post('/on-app-install', async (c) => {
  const input = await c.req.json<OnAppInstallRequest>();
  console.log('SiftMod installed to subreddit: r/' + input.subreddit?.name);

  return c.json<TriggerResponse>({}, 200);
});

triggers.post('/on-post-report', async (c) => {
  const input = await c.req.json<OnPostReportRequest>();
  const post = input.post;

  if (!post?.id) {
    console.warn('SiftMod post report trigger did not include a post ID.');
    return c.json<TriggerResponse>({}, 200);
  }

  const incident = await recordReportIncident({
    targetId: post.id,
    targetKind: 'post',
    reason: input.reason,
    ...(input.subreddit?.id ? { subredditId: input.subreddit.id } : {}),
    ...(input.subreddit?.name ? { subredditName: input.subreddit.name } : {}),
    ...(post.permalink ? { targetPermalink: post.permalink } : {}),
    ...(post.title ? { targetTitle: post.title } : {}),
    ...(post.selftext ? { targetExcerpt: post.selftext } : {}),
  });

  console.log(
    `SiftMod stored ${incident.severity} post report incident ${incident.redisKey}`
  );

  return c.json<TriggerResponse>({}, 200);
});

triggers.post('/on-comment-report', async (c) => {
  const input = await c.req.json<OnCommentReportRequest>();
  const comment = input.comment;

  if (!comment?.id) {
    console.warn('SiftMod comment report trigger did not include a comment ID.');
    return c.json<TriggerResponse>({}, 200);
  }

  const incident = await recordReportIncident({
    targetId: comment.id,
    targetKind: 'comment',
    reason: input.reason,
    ...(input.subreddit?.id ? { subredditId: input.subreddit.id } : {}),
    ...(input.subreddit?.name ? { subredditName: input.subreddit.name } : {}),
    ...(comment.permalink ? { targetPermalink: comment.permalink } : {}),
    ...(comment.body ? { targetExcerpt: comment.body } : {}),
  });

  console.log(
    `SiftMod stored ${incident.severity} comment report incident ${incident.redisKey}`
  );

  return c.json<TriggerResponse>({}, 200);
});
