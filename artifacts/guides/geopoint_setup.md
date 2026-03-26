# GeoPoint Setup for Map Visualizations

This guide adds a processor to Wazuh's ingest pipeline that converts 1Password location coordinates into the `GeoLocation.location` geo_point field, enabling map visualizations in Wazuh dashboards.

---

## How It Works

1Password events arrive with location data at `data.op.location`. The processor converts this into Wazuh's `GeoLocation` format:

```
data.op.location.latitude / longitude  →  GeoLocation.location (geo_point)
data.op.location.city                  →  GeoLocation.city_name
data.op.location.country               →  GeoLocation.country_name
data.op.location.region                →  GeoLocation.region_name
```

The processor only runs on 1Password events and skips any events missing location data.

---

## Installation

### Step 1: Find Your Pipeline Name

The pipeline name includes the Filebeat version and varies across installations. In **Wazuh Dashboard > Indexer Management > Dev Tools**, run:

```
GET _ingest/pipeline/*wazuh*
```

Look for the pipeline ending in `-wazuh-alerts-pipeline` (e.g., `filebeat-7.10.2-wazuh-alerts-pipeline`). This is referred to as `<YOUR-PIPELINE-NAME>` throughout this guide.

### Step 2: Get the Current Pipeline

```
GET _ingest/pipeline/<YOUR-PIPELINE-NAME>
```

Copy the response — you'll need the existing `processors` array.

### Step 3: Add the Processor

Add the following processor to the **end** of the existing `processors` array. Do not remove any existing processors.

```json
{
  "script": {
    "description": "Convert 1Password lat/lon to GeoLocation.location geo_point",
    "if": "ctx?.data?.integration == '1password' && ctx?.data?.op?.location?.latitude != null && ctx?.data?.op?.location?.longitude != null",
    "lang": "painless",
    "source": "ctx.GeoLocation = new HashMap(); ctx.GeoLocation.location = ['lat': ctx.data.op.location.latitude, 'lon': ctx.data.op.location.longitude]; if (ctx.data.op.location.city != null) { ctx.GeoLocation.city_name = ctx.data.op.location.city; } if (ctx.data.op.location.country != null) { ctx.GeoLocation.country_name = ctx.data.op.location.country; } if (ctx.data.op.location.region != null) { ctx.GeoLocation.region_name = ctx.data.op.location.region; }"
  }
}
```

### Step 4: Update the Pipeline

PUT the updated pipeline back with the new processor appended:

```
PUT _ingest/pipeline/<YOUR-PIPELINE-NAME>
{
  "description": "Wazuh alerts pipeline",
  "processors": [
    ... existing processors (keep all of them) ...,
    {
      "script": {
        "description": "Convert 1Password lat/lon to GeoLocation.location geo_point",
        "if": "ctx?.data?.integration == '1password' && ctx?.data?.op?.location?.latitude != null && ctx?.data?.op?.location?.longitude != null",
        "lang": "painless",
        "source": "ctx.GeoLocation = new HashMap(); ctx.GeoLocation.location = ['lat': ctx.data.op.location.latitude, 'lon': ctx.data.op.location.longitude]; if (ctx.data.op.location.city != null) { ctx.GeoLocation.city_name = ctx.data.op.location.city; } if (ctx.data.op.location.country != null) { ctx.GeoLocation.country_name = ctx.data.op.location.country; } if (ctx.data.op.location.region != null) { ctx.GeoLocation.region_name = ctx.data.op.location.region; }"
      }
    }
  ]
}
```

### Step 5: Verify

Test the processor in isolation using an inline pipeline — this avoids failures from other Wazuh processors that expect fields not present in the test document:

```
POST _ingest/pipeline/_simulate
{
  "pipeline": {
    "description": "Test geopoint processor",
    "processors": [
      {
        "script": {
          "description": "Convert 1Password lat/lon to GeoLocation.location geo_point",
          "if": "ctx?.data?.integration == '1password' && ctx?.data?.op?.location?.latitude != null && ctx?.data?.op?.location?.longitude != null",
          "lang": "painless",
          "source": "ctx.GeoLocation = new HashMap(); ctx.GeoLocation.location = ['lat': ctx.data.op.location.latitude, 'lon': ctx.data.op.location.longitude]; if (ctx.data.op.location.city != null) { ctx.GeoLocation.city_name = ctx.data.op.location.city; } if (ctx.data.op.location.country != null) { ctx.GeoLocation.country_name = ctx.data.op.location.country; } if (ctx.data.op.location.region != null) { ctx.GeoLocation.region_name = ctx.data.op.location.region; }"
        }
      }
    ]
  },
  "docs": [
    {
      "_source": {
        "data": {
          "integration": "1password",
          "op": {
            "event_type": "signin_attempt",
            "location": {
              "latitude": 37.7749,
              "longitude": -122.4194,
              "city": "San Francisco",
              "region": "California",
              "country": "US"
            }
          }
        }
      }
    }
  ]
}
```

The response should include `GeoLocation.location` with lat/lon values.

---

## Tips

- Only **new events** after the pipeline update will have the geo_point field. Existing indexed events are not affected.
- If the simulate returns `"docs": [null]`, double-check the pipeline name from Step 1.
- Events without location data (e.g., error events, run summaries) are automatically skipped by the `if` condition.
