---
"@phantom/auth2": patch
---

Include the RPC method name, and the edge-block `id` or `cf-ray` when no `requestId` is returned, in `KMS HTTP <status>` errors so a 403 can be traced to a specific call. Only plain identifier values are included; headers, tokens and stamps are never added.
