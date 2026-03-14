# OpenAPI Export

When the testbed is running, OpenAPI JSON is available at:

- `http://127.0.0.1:8000/openapi.json`

You can export it to sample path:

```bash
curl http://127.0.0.1:8000/openapi.json -o samples/openapi/vulnerable_api.json
```
