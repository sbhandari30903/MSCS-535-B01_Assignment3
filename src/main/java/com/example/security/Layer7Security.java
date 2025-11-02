package com.example.security;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Example utilities demonstrating how to protect the Application Layer (OSI Layer 7)
 * from common web-application attacks. The code intentionally avoids framework
 * dependencies so the core mitigations can be easily adapted to a variety of
 * environments such as servlets, Spring MVC, or lightweight HTTP servers.
 */
public final class Layer7Security {

    private final RateLimiter rateLimiter;
    private final CsrfTokenManager csrfTokenManager;
    private final InputValidator inputValidator;
    private final SecurityHeaders securityHeaders;

    public Layer7Security() {
        this(new RateLimiter(100, Duration.ofMinutes(1)),
                new CsrfTokenManager(Duration.ofMinutes(30)),
                new InputValidator(),
                new SecurityHeaders());
    }

    public Layer7Security(RateLimiter rateLimiter,
                          CsrfTokenManager csrfTokenManager,
                          InputValidator inputValidator,
                          SecurityHeaders securityHeaders) {
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
        this.csrfTokenManager = Objects.requireNonNull(csrfTokenManager, "csrfTokenManager");
        this.inputValidator = Objects.requireNonNull(inputValidator, "inputValidator");
        this.securityHeaders = Objects.requireNonNull(securityHeaders, "securityHeaders");
    }

    /**
     * Entry point that would be called by the web tier. The method showcases how multiple
     * layer-7 protections work together before the business logic is invoked.
     */
    public HttpResponse secureHandle(HttpRequest request) {
        if (!rateLimiter.tryConsume(request.clientIp())) {
            return HttpResponse.tooManyRequests();
        }

        if (!inputValidator.isPathAllowed(request.path())
                || !inputValidator.areParametersSafe(request.parameters())) {
            return HttpResponse.badRequest("Invalid request");
        }

        if (requiresCsrfProtection(request) && !csrfTokenManager.isValid(request)) {
            return HttpResponse.forbidden("CSRF token missing or invalid");
        }

        HttpResponse response = HttpResponse.ok("Business logic succeeded");
        securityHeaders.apply(response);
        return response;
    }

    private boolean requiresCsrfProtection(HttpRequest request) {
        return Set.of("POST", "PUT", "PATCH", "DELETE").contains(request.method());
    }

    /**
     * Simple token bucket rate limiter for throttling repeated requests from a client.
     */
    public static final class RateLimiter {
        private final int capacity;
        private final Duration refillInterval;
        private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

        public RateLimiter(int capacity, Duration refillInterval) {
            this.capacity = capacity;
            this.refillInterval = refillInterval;
        }

        public boolean tryConsume(String clientIp) {
            Bucket bucket = buckets.computeIfAbsent(clientIp, k -> new Bucket(capacity, refillInterval));
            return bucket.tryConsume();
        }

        private static final class Bucket {
            private final int capacity;
            private final Duration refillInterval;
            private AtomicInteger tokens;
            private Instant lastRefill;

            private Bucket(int capacity, Duration refillInterval) {
                this.capacity = capacity;
                this.refillInterval = refillInterval;
                this.tokens = new AtomicInteger(capacity);
                this.lastRefill = Instant.now();
            }

            private synchronized boolean tryConsume() {
                refillIfNeeded();
                if (tokens.get() <= 0) {
                    return false;
                }
                tokens.decrementAndGet();
                return true;
            }

            private void refillIfNeeded() {
                Instant now = Instant.now();
                if (Duration.between(lastRefill, now).compareTo(refillInterval) >= 0) {
                    tokens.set(capacity);
                    lastRefill = now;
                }
            }
        }
    }

    /**
     * Validates request targets and parameters using a simple allow-list.
     */
    public static final class InputValidator {
        private static final Pattern SAFE_VALUE = Pattern.compile("^[\\w\\-\\.@]{1,128}$");
        private static final Pattern SAFE_PATH = Pattern.compile("^/[a-zA-Z0-9/\\-_]*$");

        public boolean isPathAllowed(String path) {
            return SAFE_PATH.matcher(path).matches();
        }

        public boolean areParametersSafe(Map<String, String> parameters) {
            return parameters.entrySet().stream()
                    .allMatch(entry -> SAFE_VALUE.matcher(entry.getKey()).matches()
                            && SAFE_VALUE.matcher(entry.getValue()).matches());
        }
    }

    /**
     * Manages CSRF tokens bound to session identifiers.
     */
    public static final class CsrfTokenManager {
        private final Duration tokenTtl;
        private final Map<String, TokenRecord> tokens = new ConcurrentHashMap<>();

        public CsrfTokenManager(Duration tokenTtl) {
            this.tokenTtl = tokenTtl;
        }

        public String issueToken(String sessionId) {
            String token = Base64.getUrlEncoder().encodeToString((sessionId + ":" + Instant.now()).getBytes(StandardCharsets.UTF_8));
            tokens.put(sessionId, new TokenRecord(token, Instant.now()));
            return token;
        }

        public boolean isValid(HttpRequest request) {
            String sessionId = request.headers().getOrDefault("X-Session-Id", "");
            String requestToken = Optional.ofNullable(request.headers().get("X-CSRF-Token"))
                    .orElse(request.parameters().get("csrfToken"));
            if (sessionId.isEmpty() || requestToken == null) {
                return false;
            }
            TokenRecord record = tokens.get(sessionId);
            if (record == null || Instant.now().isAfter(record.createdAt().plus(tokenTtl))) {
                tokens.remove(sessionId);
                return false;
            }
            return record.token().equals(requestToken);
        }

        private record TokenRecord(String token, Instant createdAt) { }
    }

    /**
     * Applies defensive response headers that mitigate XSS, clickjacking, and MIME sniffing.
     */
    public static final class SecurityHeaders {
        private final Map<String, String> headers;

        public SecurityHeaders() {
            Map<String, String> defaults = new LinkedHashMap<>();
            defaults.put("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'");
            defaults.put("X-Content-Type-Options", "nosniff");
            defaults.put("X-Frame-Options", "DENY");
            defaults.put("Referrer-Policy", "strict-origin-when-cross-origin");
            defaults.put("Permissions-Policy", "geolocation=(), microphone=()");
            this.headers = Collections.unmodifiableMap(defaults);
        }

        public void apply(HttpResponse response) {
            headers.forEach(response::setHeader);
        }
    }

    /**
     * Minimal HTTP request representation so the example remains framework agnostic.
     */
    public record HttpRequest(String method,
                              String path,
                              Map<String, String> parameters,
                              Map<String, String> headers,
                              String clientIp) {
    }

    /**
     * Minimal HTTP response with helpers for common responses.
     */
    public static final class HttpResponse {
        private final int status;
        private final Map<String, String> headers = new HashMap<>();
        private final String body;

        private HttpResponse(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public static HttpResponse ok(String body) {
            return new HttpResponse(200, body);
        }

        public static HttpResponse badRequest(String body) {
            return new HttpResponse(400, body);
        }

        public static HttpResponse forbidden(String body) {
            return new HttpResponse(403, body);
        }

        public static HttpResponse tooManyRequests() {
            return new HttpResponse(429, "Too Many Requests");
        }

        public int status() {
            return status;
        }

        public Map<String, String> headers() {
            return headers;
        }

        public String body() {
            return body;
        }

        public void setHeader(String name, String value) {
            headers.put(name, value);
        }
    }
}
