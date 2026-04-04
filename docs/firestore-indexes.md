# Firestore Indexes

This repo manages Firestore composite indexes in code.

Files:

- `firebase.json`
- `firestore.indexes.json`

Current index set covers the ordered multi-field queries used by the API:

- `progress_events`: `uid` + `utc desc`
- `progress_events`: `uid` + `module_id` + `utc desc`
- `progress_events`: `uid` + `module_id` + `event_type` + `utc desc`
- `lessons`: `module_id` + `sequence`
- `lessons`: `moduleId` + `order`

## Local deploy

From the `apip-api` directory:

```bash
npx firebase-tools@14.22.0 deploy --only firestore:indexes --project YOUR_PROJECT_ID --config firebase.json --non-interactive
```

The command uses your active Google credentials. If you rely on Application Default Credentials locally, make sure they are already configured before running the deploy.

## CI deploy

Both Cloud Run deploy workflows apply `firestore.indexes.json` before deploying the API service.

If CI lacks permission to manage indexes, the workflow records a warning in the job summary and continues with the API deploy.

Grant the deploy service account Firestore index administration permissions in the target project to re-enable automatic index rollout from CI.

## When adding a new query

If you introduce a Firestore query that combines equality filters with `order_by`, add the matching composite index here in the same pull request so production does not fall back to unordered scans.
