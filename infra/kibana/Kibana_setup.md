# Kibana Setup

## What is the purpose of Kibana?

Kibana is the web interface used to view, search, and visualize the logs collected from the system.

In this project, application, proxy, analyzer, security, admin, authentication and file activity logs are sent to Elasticsearch through Fluent Bit. Kibana connects to Elasticsearch and displays those logs through data views, dashboards, and visualizations.

## How it works

The logging flow is:

```text
Containers → Docker fluentd logging driver → Fluent Bit → Elasticsearch → Kibana

```

The main log indices are:

```text
app-logs-*
proxy-logs-*
analyzer-logs-*
docker-logs-*
```

Kibana reads these Elasticsearch indices and uses saved dashboards and visualizations to make the logs easier to inspect.

Kibana saved objects were exported and stored under:

```text
infra/kibana/saved_objects
```

they can be automatically imported when the stack starts, so dashboards can be restored even if Docker volumes are deleted.

## Accessing Kibana

Kibana is exposed locally at:

```text
https://127.0.0.1:5601
```

## Login credentials

Use the Elasticsearch superuser account:

```text
Username: elastic
Password: value of ELASTIC_PASSWORD from the .env file
```
