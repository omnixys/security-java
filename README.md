# Omnixys Security Starter

Spring Boot starter for enterprise security infrastructure.

## Features

- JWE encryption/decryption service
- Hash service (bcrypt, scrypt, argon2)
- Hmac service
- Cookie service with secure defaults
- Token cookie service
- Rate limiting with Valkey
- Token revocation with Valkey
- Secure session management
- Security audit logging
- @Public annotation for unauthenticated endpoints
- Custom authentication token and user details
- JWT-to-UserDetails converter
- Spring Security auto-configuration

## Installation

```xml
<dependency>
    <groupId>com.omnixys</groupId>
    <artifactId>security-starter</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Usage

```java
@Autowired
private JweService jweService;

String token = jweService.encrypt(payload);
var decrypted = jweService.decrypt(token, Claims.class);

@Autowired
private RateLimitService rateLimitService;

boolean allowed = rateLimitService.tryConsume("api-key", 10, Duration.ofMinutes(1));
```
