#!/usr/bin/env node
import { createApp } from '../src/server.js';

const port = parseInt(process.env.PORT || '8787', 10);
const host = process.env.HOST || '127.0.0.1';

const app = createApp();
app.listen(port, host, () => {
  console.log(`autosec-server listening on http://${host}:${port}`);
});
