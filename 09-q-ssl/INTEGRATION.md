# Q-SSL 시스템 통합

Q-SSL (Quantum-resistant SSL) QSIGN 시스템 통합 가이드입니다.

## 목차
- [Q-Gateway 통합](#q-gateway-통합)
- [Keycloak PQC 연동](#keycloak-pqc-연동)
- [Vault HSM 통합](#vault-hsm-통합)
- [Kubernetes 통합](#kubernetes-통합)
- [레거시 시스템 호환성](#레거시-시스템-호환성)

---

## Q-Gateway 통합

### APISIX Q-SSL 설정

```yaml
# apisix-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: apisix-gateway
  namespace: qsign
spec:
  replicas: 3
  selector:
    matchLabels:
      app: apisix-gateway
  template:
    metadata:
      labels:
        app: apisix-gateway
    spec:
      containers:
      - name: apisix
        image: apache/apisix:3.7.0-debian
        ports:
        - containerPort: 9443
          name: https
        volumeMounts:
        - name: apisix-config
          mountPath: /usr/local/apisix/conf/config.yaml
          subPath: config.yaml
        - name: ssl-certs
          mountPath: /etc/apisix/certs
          readOnly: true
        env:
        - name: APISIX_DEPLOYMENT_ETCD_HOST
          value: "etcd.qsign.svc.cluster.local:2379"
      volumes:
      - name: apisix-config
        configMap:
          name: apisix-config
      - name: ssl-certs
        secret:
          secretName: apisix-qssl-certs
```

### SSL Certificate Secret

```yaml
# ssl-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: apisix-qssl-certs
  namespace: qsign
type: kubernetes.io/tls
data:
  tls.crt: |  # Base64 encoded hybrid certificate
    LS0tLS1CRUdJTi...
  tls.key: |  # Base64 encoded hybrid private key
    LS0tLS1CRUdJTi...
  ca.crt: |   # Base64 encoded CA chain
    LS0tLS1CRUdJTi...
```

### Upstream Q-SSL 설정

```bash
#!/bin/bash
# Configure upstream with Q-SSL

curl -X PUT http://127.0.0.1:9180/apisix/admin/upstreams/keycloak \
  -H "X-API-KEY: $APISIX_API_KEY" \
  -d '{
    "type": "roundrobin",
    "scheme": "https",
    "nodes": {
      "keycloak.qsign.svc.cluster.local:8443": 1
    },
    "tls": {
      "client_cert": "/etc/apisix/certs/gateway_client.crt",
      "client_key": "/etc/apisix/certs/gateway_client.key",
      "ca_cert": "/etc/apisix/certs/ca_chain.crt",
      "verify": true,
      "sni": "keycloak.qsign.svc.cluster.local"
    },
    "keepalive_pool": {
      "size": 320,
      "idle_timeout": 60,
      "requests": 1000
    }
  }'
```

---

## Keycloak PQC 연동

### Keycloak Q-SSL 설정

```xml
<!-- standalone.xml -->
<subsystem xmlns="urn:jboss:domain:undertow:12.0">
    <server name="default-server">
        <https-listener name="https"
                       socket-binding="https"
                       security-realm="ApplicationRealm"
                       enable-http2="true"
                       ssl-context="qssl-context"/>
    </server>
</subsystem>

<subsystem xmlns="urn:wildfly:elytron:15.1">
    <!-- Key Store for Hybrid Certificate -->
    <tls>
        <key-stores>
            <key-store name="qssl-keystore">
                <credential-reference clear-text="changeit"/>
                <implementation type="JKS"/>
                <file path="qssl-keystore.jks"
                     relative-to="jboss.server.config.dir"/>
            </key-store>
            <key-store name="qssl-truststore">
                <credential-reference clear-text="changeit"/>
                <implementation type="JKS"/>
                <file path="qssl-truststore.jks"
                     relative-to="jboss.server.config.dir"/>
            </key-store>
        </key-stores>

        <key-managers>
            <key-manager name="qssl-key-manager"
                        key-store="qssl-keystore"
                        alias="qsign-keycloak">
                <credential-reference clear-text="changeit"/>
            </key-manager>
        </key-managers>

        <trust-managers>
            <trust-manager name="qssl-trust-manager"
                          key-store="qssl-truststore"/>
        </trust-managers>

        <server-ssl-contexts>
            <server-ssl-context name="qssl-context"
                               protocols="TLSv1.3"
                               cipher-suite-filter="TLS_AES_256_GCM_SHA384"
                               key-manager="qssl-key-manager"
                               trust-manager="qssl-trust-manager"
                               want-client-auth="true"
                               need-client-auth="false"/>
        </server-ssl-contexts>
    </tls>
</subsystem>
```

### Java 클라이언트 (Keycloak SDK)

```java
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.KeyManagerFactory;
import java.security.KeyStore;

public class QSSLKeycloakClient {
    public static Keycloak createClient() throws Exception {
        // Load keystore (client certificate)
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(
            new FileInputStream("client-keystore.jks"),
            "changeit".toCharArray()
        );

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm()
        );
        kmf.init(keyStore, "changeit".toCharArray());

        // Load truststore (CA certificates)
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(
            new FileInputStream("truststore.jks"),
            "changeit".toCharArray()
        );

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(trustStore);

        // Create SSL context with Q-SSL support
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(
            kmf.getKeyManagers(),
            tmf.getTrustManagers(),
            null
        );

        // Build Keycloak client
        return KeycloakBuilder.builder()
            .serverUrl("https://keycloak.qsign.example.com")
            .realm("qsign")
            .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
            .clientId("qsign-client")
            .clientSecret("client-secret")
            .sslContext(sslContext)
            .build();
    }
}
```

---

## Vault HSM 통합

### Vault Q-SSL Listener

```hcl
# vault-config.hcl
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = false

  # Q-SSL Configuration
  tls_cert_file = "/vault/certs/hybrid_cert.pem"
  tls_key_file = "/vault/certs/hybrid_key.pem"
  tls_client_ca_file = "/vault/certs/ca_chain.pem"

  tls_min_version = "tls13"
  tls_cipher_suites = "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"

  # Client Certificate Authentication
  tls_require_and_verify_client_cert = true
}

# Luna HSM Seal
seal "pkcs11" {
  lib = "/usr/lib/libCryptoki2_64.so"
  slot = "0"
  pin = "vault-pin"
  key_label = "vault-master-key"
  hmac_key_label = "vault-hmac-key"
  generate_key = false
}
```

### Vault Client (Go)

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"

    vault "github.com/hashicorp/vault/api"
)

func newQSSLVaultClient() (*vault.Client, error) {
    // Load client certificate
    cert, err := tls.LoadX509KeyPair(
        "/path/to/client_cert.pem",
        "/path/to/client_key.pem",
    )
    if err != nil {
        return nil, err
    }

    // Load CA certificates
    caCert, err := ioutil.ReadFile("/path/to/ca_chain.pem")
    if err != nil {
        return nil, err
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // Create TLS config
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
        MinVersion:   tls.VersionTLS13,
    }

    // Configure Vault client
    config := vault.DefaultConfig()
    config.Address = "https://vault.qsign.example.com:8200"

    httpClient := config.HttpClient
    httpClient.Transport.(*http.Transport).TLSClientConfig = tlsConfig

    client, err := vault.NewClient(config)
    if err != nil {
        return nil, err
    }

    return client, nil
}
```

---

## Kubernetes 통합

### Ingress with Q-SSL

```yaml
# ingress-qssl.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: qsign-ingress
  namespace: qsign
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ciphers: "TLS_AES_256_GCM_SHA384"
    nginx.ingress.kubernetes.io/auth-tls-secret: "qsign/client-ca"
    nginx.ingress.kubernetes.io/auth-tls-verify-client: "optional"
    nginx.ingress.kubernetes.io/auth-tls-verify-depth: "2"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - qsign.example.com
    secretName: qsign-qssl-cert
  rules:
  - host: qsign.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: apisix-gateway
            port:
              number: 9443
```

### Service Mesh (Istio)

```yaml
# istio-gateway-qssl.yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: qsign-gateway
  namespace: qsign
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: MUTUAL
      credentialName: qsign-qssl-cert
      minProtocolVersion: TLSV1_3
      cipherSuites:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
    hosts:
    - qsign.example.com
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: qsign-backend
  namespace: qsign
spec:
  host: "*.qsign.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
      clientCertificate: /etc/certs/cert-chain.pem
      privateKey: /etc/certs/key.pem
      caCertificates: /etc/certs/root-cert.pem
      sni: "*.qsign.svc.cluster.local"
```

---

## 레거시 시스템 호환성

### SSL/TLS Fallback

```nginx
# nginx-legacy-compat.conf
server {
    listen 443 ssl http2;
    server_name legacy.qsign.example.com;

    # Primary: Q-SSL (TLS 1.3 + PQC)
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    # Q-SSL configuration
    ssl_conf_command Groups kyber1024:x25519:secp384r1;
    ssl_conf_command SignatureAlgorithms dilithium3+ecdsa_secp384r1_sha384:ecdsa_secp384r1_sha384;

    # Hybrid certificate
    ssl_certificate /etc/nginx/certs/hybrid_cert.pem;
    ssl_certificate_key /etc/nginx/certs/hybrid_key.pem;

    # Fallback to classical TLS 1.2 for legacy clients
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;

    location / {
        # Check client capabilities
        if ($ssl_protocol = "TLSv1.2") {
            # Legacy client - use classical crypto only
            add_header X-SSL-Mode "Legacy-TLS1.2" always;
        }

        if ($ssl_protocol = "TLSv1.3") {
            # Modern client - Q-SSL enabled
            add_header X-SSL-Mode "Q-SSL-TLS1.3" always;
        }

        proxy_pass https://backend;
    }
}
```

---

## 마이그레이션 전략

### 단계적 전환

```yaml
Phase 1: Hybrid Deployment (1-3 months):
  - Q-SSL과 기존 TLS 1.2 동시 지원
  - 클라이언트 capabilities 자동 감지
  - Q-SSL 사용률 모니터링

Phase 2: Q-SSL 우선 (3-6 months):
  - Q-SSL을 기본으로 설정
  - TLS 1.2는 fallback으로만 사용
  - 레거시 클라이언트 업그레이드 유도

Phase 3: Q-SSL Only (6-12 months):
  - TLS 1.2 비활성화
  - Q-SSL 전용 운영
  - 최종 레거시 클라이언트 차단
```

---

## 참고 자료

```yaml
문서:
  - APISIX SSL Plugin
  - Keycloak Server Administration Guide
  - HashiCorp Vault Documentation
  - Istio Security
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
