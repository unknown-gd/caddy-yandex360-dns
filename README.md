# Yandex 360 DNS module for Caddy

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy).
It manages DNS records of domains connected to a [Yandex 360](https://360.yandex.ru) organization
via the [Yandex 360 Directory API](https://yandex.ru/dev/api360/doc/ref/DomainDNSService/),
and can be used to solve the ACME DNS-01 challenge.

## Caddy module name

```
dns.providers.yandex360
```

## Build

```sh
xcaddy build --with github.com/unknown-gd/caddy-yandex360-dns
```

### Docker

Build a Caddy image that includes the module, using the official `builder` image:

```dockerfile
FROM caddy:2.11-builder AS builder

RUN xcaddy build \
    --with github.com/unknown-gd/caddy-yandex360-dns

FROM caddy:2.11

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

To build from a local checkout instead (for example, before the module is published), put the
Dockerfile in the repository root and copy the source in:

```dockerfile
FROM caddy:2.11-builder AS builder

COPY . /src/caddy-yandex360
RUN xcaddy build \
    --with github.com/unknown-gd/caddy-yandex360-dns=/src/caddy-yandex360

FROM caddy:2.11

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

Run it with the credentials passed as environment variables:

```sh
docker build -t caddy-yandex360 .
docker run -d --name caddy \
    -p 80:80 -p 443:443 -p 443:443/udp \
    -e YANDEX360_OAUTH_TOKEN=<your OAuth token> \
    -e YANDEX360_ORG_ID=<your organization ID> \
    -v $PWD/Caddyfile:/etc/caddy/Caddyfile \
    -v caddy_data:/data \
    caddy-yandex360
```

Check that the module is included:

```sh
docker run --rm caddy-yandex360 caddy list-modules | grep yandex360
```

## Credentials

- `oauth_token` — OAuth token of a Yandex 360 organization administrator with the
  `directory:read_organization`, `directory:read_domains`, `directory:manage_dns`, `directory:write_domains` permissions.
- `org_id` — Yandex 360 organization ID.

### 1. Create an OAuth app

1. Open <https://oauth.yandex.ru/client/new> (signed in to any Yandex account; it doesn't have to
   be the organization admin).
2. Enter a service name, for example `caddy-dns`.
3. Under **Платформы приложения** (Application platforms), choose **Веб-сервисы** (Web services).
4. In the **Redirect URI** field, click **Подставить URL для отладки** (Use URL for debugging).
   This fills in `https://oauth.yandex.ru/verification_code`.
5. Under **Доступ к данным** (Data access), add the `directory:read_organization`, `directory:read_domains`, `directory:manage_dns`, `directory:write_domains` permissions
   (**Управление DNS-записями**, Manage DNS records). Nothing else is needed.
6. Enter a contact email and click **Создать приложение** (Create app).
7. Copy the **ClientID** from the app page.

### 2. Get an OAuth token

1. Sign in to Yandex as an **administrator of the Yandex 360 organization** that owns the domain.
2. Open this link, replacing `<ClientID>` with the value from the previous step:

   ```
   https://oauth.yandex.ru/authorize?response_type=token&client_id=<ClientID>
   ```

3. Allow access. The page then shows the token (it starts with `y0_`). Save it as `oauth_token`.

Tokens expire. To renew one, open the same link again. You'll also need a new token if you change
the app's permissions.

### 3. Find the organization ID

1. Open the admin panel at <https://admin.yandex.ru> as the organization administrator.
2. Click the organization name/profile in the top-left corner. The menu shows the organization
   **ID**, a number such as `1234567`. Save it as `org_id`.

### 4. Check the credentials

List the domain's DNS records with the same API the plugin uses:

```sh
curl -H "Authorization: OAuth $YANDEX360_OAUTH_TOKEN" \
    "https://api360.yandex.net/directory/v1/org/$YANDEX360_ORG_ID/domains/example.com/dns"
```

A JSON response with `"records": [...]` means everything is set up. If you get `401`, the token is
wrong or has expired. If you get `403`, the token is missing `directory:read_organization`,
`directory:read_domains`, `directory:manage_dns`, `directory:write_domains` or its user isn't an admin
of the organization. If you get `404`, check `org_id` and make sure the domain is
connected to the organization.

## Config examples

Caddyfile, global:

```caddyfile
{
	acme_dns yandex360 {
		oauth_token {env.YANDEX360_OAUTH_TOKEN}
		org_id {env.YANDEX360_ORG_ID}
	}
}
```

Caddyfile, per site (short form `yandex360 <oauth_token> <org_id>` is also accepted):

```caddyfile
example.com {
	tls {
		dns yandex360 {env.YANDEX360_OAUTH_TOKEN} {env.YANDEX360_ORG_ID}
	}
}
```

JSON:

```json
{
  "module": "acme",
  "challenges": {
    "dns": {
      "provider": {
        "name": "yandex360",
        "oauth_token": "{env.YANDEX360_OAUTH_TOKEN}",
        "org_id": "{env.YANDEX360_ORG_ID}"
      }
    }
  }
}
```

Records created without a TTL use 21600 seconds, the same default as lego's `yandex360` provider.

## Propagation check

Yandex 360 DNS can be slow to propagate. Caddy's built-in check gives up after 2 minutes and
polls every 2 seconds. It also follows CNAMEs, so a wildcard CNAME that covers `_acme-challenge`
can send it to the wrong zone. To handle this, the plugin runs its own check after creating each
challenge record. It queries the zone's authoritative nameservers for the exact record name and
never follows CNAMEs, which matches lego's `LEGO_DISABLE_CNAME_SUPPORT=true`.

| Option                | Default | lego equivalent                 |
| --------------------- | ------- | ------------------------------- |
| `propagation_timeout` | `600s`  | `YANDEX360_PROPAGATION_TIMEOUT` |
| `polling_interval`    | `15s`   | `YANDEX360_POLLING_INTERVAL`    |

```caddyfile
dns yandex360 {
	oauth_token {env.YANDEX360_OAUTH_TOKEN}
	org_id {env.YANDEX360_ORG_ID}
	propagation_timeout 10m   # -1 disables the plugin's check
	polling_interval 15s
}
```

Caddy still runs its own check afterwards. It normally passes right away, but if a wildcard
CNAME still sends it to the wrong zone, turn it off in the issuer and rely on the plugin's
check instead:

```caddyfile
tls {
	dns yandex360 ...
	propagation_timeout -1
}
```
