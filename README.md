# Traefik Conditional Header IP Allowlist

Repository template taken from [traefik/plugindemo](https://github.com/traefik/plugindemo/tree/master).

## Rationale

This traefik middleware plugin was explicitly built for the use case where there are certain API keys that can only be used from specific IP addresses. This middleware plugin allows you to specify a header name and a map of API keys to IP addresses that are allowed to use the API key. If the header is not present or the IP address is not in the list of allowed IP addresses, the request will be **allowed**.

Repeated again, this middleware specifically prevents an API key from being used unless it satisifes the whitelist **otherwise** the request is allowed through as normal. This means that this middleware is not suitable as a catch-all authentication mechanism but merely on top of existing authentication mechanisms in the application or middleware chain. It is recommended to use this middleware in conjunction with other authentication mechanisms to ensure secure access to your API.

## Installation and Configuration

Make sure to pass the sha256sum of the API key to the middleware. This allows storing without any regard for secret management safely.

### Helm Chart Values

```yaml
  experimental:
    plugins:
      redirect-errors:
        moduleName: github.com/assetnote/traefik-conditional-ip
        version: v0.1.0
```

### Middleware
```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: api-conditional-ip-auth
  namespace: traefik
spec:
  traefik-vouch:
    headerName: X-Api-Key
    keyIpMap: 
      "sha256ofyourkey": ["127.0.0.1"]
```
