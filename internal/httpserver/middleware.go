package httpserver

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type middleware func(http.Handler) http.Handler

func applyMiddleware(handler http.Handler, middlewareChain ...middleware) http.Handler {
	for _, currentMiddleware := range slices.Backward(middlewareChain) {
		handler = currentMiddleware(handler)
	}
	return handler
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		nonce := httpx.CSPNonce(request.Context())
		policyValue := fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self'; img-src 'self' data:; frame-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'; form-action 'self'", nonce)
		responseWriter.Header().Set("Content-Security-Policy", policyValue)
		responseWriter.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		responseWriter.Header().Set("X-Frame-Options", "SAMEORIGIN")

		responseWriter.Header().Set("X-Content-Type-Options", "nosniff")

		responseWriter.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		responseWriter.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		responseWriter.Header().Set("Origin-Agent-Cluster", "?1")
		responseWriter.Header().Set("X-DNS-Prefetch-Control", "off")
		responseWriter.Header().Set("X-Download-Options", "noopen")
		responseWriter.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		responseWriter.Header().Set("X-XSS-Protection", "0")

		next.ServeHTTP(responseWriter, request)
	})
}

// prevents CSRF
func validateSource(appOrigin string, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost {
				next.ServeHTTP(responseWriter, request)
				return
			}

			clientOrigin := request.Header.Get("Origin")
			if clientOrigin == "" {
				refererUrl, err := url.Parse(request.Header.Get("Referer"))
				if err != nil {
					http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
					return
				}
				parsedReferer := &url.URL{
					Scheme: refererUrl.Scheme,
					Host:   refererUrl.Host,
				}

				clientOrigin = parsedReferer.String()
			}

			if clientOrigin != appOrigin {
				if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusForbidden, "Invalid Origin", "the request came from an invalid/missing origin"); err != nil {
					http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				return
			}
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func cspNonce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)
		request = request.WithContext(httpx.WithCSPNonce(request.Context(), nonce))
		next.ServeHTTP(responseWriter, request)
	})
}

func recoverPanics(logger *logging.Logger, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					_ = logger.Event("unhandled_error", map[string]any{
						"method":  request.Method,
						"path":    request.URL.Path,
						"message": fmt.Sprint(recovered),
					})
					if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusInternalServerError, "Unhandled Error", fmt.Sprint(recovered)); err != nil {
						http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					}
				}
			}()
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func LoadShedder(concurrencyCap int, retryAfterSeconds int) func(http.Handler) http.Handler {
	if concurrencyCap < 1 || retryAfterSeconds < 1 {
		panic("non-positive argument in LoadShedder")
	}
	capacityTracker := make(chan struct{}, concurrencyCap)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			responseWriter.Header().Set("X-In-Flight-Limit", strconv.Itoa(concurrencyCap))
			select {
			case capacityTracker <- struct{}{}:
				defer func() { <-capacityTracker }()
				next.ServeHTTP(responseWriter, request)
			default:
				responseWriter.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
				httpx.RespondWithJSON(responseWriter, http.StatusServiceUnavailable, map[string]string{"error": "Service is at capacity"})
			}
		})
	}
}

/* THE FOLLOWING VERSION HAS A RACE CONDITION CALLED check-then-act (TOCTOU "time of check to time of use")

if len(capacityTracker) == cap(capacityTracker) { // 1. check
    ... // RespondWithError + Retry-After
}
capacityTracker <- struct{}{}                     // 2. act
defer func() {
	<-capacityTracker
}()


Under concurrent load each request runs in its own goroutine.
Suppose 49 slots are full and two requests arrive together:

1. Goroutine A checks: 49 < 50, so it continues.
2. Goroutine B checks: 49 < 50, so it continues.
3. A sends and takes the last slot.
4. B sends to a full channel and blocks.

B isn't rejected. It sits there waiting for a slot to open up.
During a flood, many goroutines can pile up like this,
which is the "blocking excess work" the assignment asks to avoid.
The `select` with `default` closes that gap because no other goroutine can get in between the check and the send
since it happens as one atomic step.
*/

func SearchThrottle(renderer *templates.Renderer) func(http.Handler) http.Handler {
	return fixedWindowRateLimiter(rateLimitOptions{
		window:  time.Second,
		maximum: 5,
		key:     func(_ *http.Request) string { return "product-search" }, // constant key so every caller shares one counter
		onLimit: func(responseWriter http.ResponseWriter, _ *http.Request, _ rateLimitState) {
			if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusTooManyRequests, "Search Is Busy", "Try again shortly."); err != nil {
				http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		},
	})
}

type rateLimitCounter struct {
	count   int
	resetAt time.Time
}

type rateLimitOptions struct {
	window  time.Duration
	maximum int
	key     func(*http.Request) string
	onLimit func(http.ResponseWriter, *http.Request, rateLimitState)
	now     func() time.Time
}

type rateLimitState struct {
	limit             int
	remaining         int
	resetAt           time.Time
	retryAfterSeconds int
}

type fixedWindowLimiter struct {
	options       rateLimitOptions
	counters      map[string]rateLimitCounter
	countersMutex sync.Mutex
	nextSweepAt   time.Time
}

func newFixedWindowLimiter(options rateLimitOptions) *fixedWindowLimiter {
	validateRateLimitOptions(options)
	if options.now == nil {
		options.now = time.Now
	}
	if options.key == nil {
		options.key = clientIPKey
	}
	return &fixedWindowLimiter{
		options:     options,
		counters:    make(map[string]rateLimitCounter),
		nextSweepAt: options.now().Add(options.window),
	}
}

func validateRateLimitOptions(options rateLimitOptions) {
	if options.window <= 0 {
		panic("rate-limit window must be positive")
	}
	if options.maximum <= 0 {
		panic("rate-limit maximum must be positive")
	}
}

func (limiter *fixedWindowLimiter) consume(request *http.Request) (rateLimitState, bool) {
	now := limiter.options.now()
	key := limiter.options.key(request)

	limiter.countersMutex.Lock()
	defer limiter.countersMutex.Unlock()
	limiter.sweepExpiredCounters(now)

	counter, exists := limiter.counters[key]
	if !exists || !now.Before(counter.resetAt) {
		counter = rateLimitCounter{resetAt: now.Add(limiter.options.window)}
	}
	retryAfterSeconds := max(1, int(math.Ceil(counter.resetAt.Sub(now).Seconds())))
	if counter.count >= limiter.options.maximum {
		return rateLimitState{
			limit:             limiter.options.maximum,
			remaining:         0,
			resetAt:           counter.resetAt,
			retryAfterSeconds: retryAfterSeconds,
		}, true
	}

	counter.count++
	limiter.counters[key] = counter
	return rateLimitState{
		limit:             limiter.options.maximum,
		remaining:         limiter.options.maximum - counter.count,
		resetAt:           counter.resetAt,
		retryAfterSeconds: retryAfterSeconds,
	}, false
}

func (limiter *fixedWindowLimiter) sweepExpiredCounters(now time.Time) {
	if now.Before(limiter.nextSweepAt) {
		return
	}
	for counterKey, counter := range limiter.counters {
		if !now.Before(counter.resetAt) {
			delete(limiter.counters, counterKey)
		}
	}
	limiter.nextSweepAt = now.Add(limiter.options.window)
}

func (limiter *fixedWindowLimiter) reject(responseWriter http.ResponseWriter, request *http.Request, state rateLimitState) {
	setRateLimitHeaders(responseWriter, state)
	responseWriter.Header().Set("Retry-After", strconv.Itoa(state.retryAfterSeconds))
	if limiter.options.onLimit != nil {
		limiter.options.onLimit(responseWriter, request, state)
		return
	}
	httpx.RespondWithJSON(responseWriter, http.StatusTooManyRequests, map[string]string{"error": "Too many requests"})
}

func fixedWindowRateLimiter(options rateLimitOptions) middleware {
	validateRateLimitOptions(options)
	fixedWindowLimiter := newFixedWindowLimiter(options)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			rateLimitState, limited := fixedWindowLimiter.consume(request)
			if limited {
				fixedWindowLimiter.reject(responseWriter, request, rateLimitState)
				return
			}
			setRateLimitHeaders(responseWriter, rateLimitState)
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func setRateLimitHeaders(responseWriter http.ResponseWriter, state rateLimitState) {
	responseWriter.Header().Set("RateLimit-Limit", strconv.Itoa(state.limit))
	responseWriter.Header().Set("RateLimit-Remaining", strconv.Itoa(state.remaining))
	responseWriter.Header().Set("RateLimit-Reset", strconv.FormatInt(state.resetAt.Unix()+boolToInt64(state.resetAt.Nanosecond() > 0), 10))
}

func clientIPKey(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if request.RemoteAddr != "" {
		return request.RemoteAddr
	}
	return "unknown"
}

func clientIPKeyWithTrustedProxies(trustedProxyHops int) func(*http.Request) string {
	return func(request *http.Request) string {
		if trustedProxyHops > 0 {
			forwardedAddresses := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
			selectedIndex := len(forwardedAddresses) - trustedProxyHops
			if selectedIndex >= 0 && selectedIndex < len(forwardedAddresses) {
				if selectedAddress := strings.TrimSpace(forwardedAddresses[selectedIndex]); selectedAddress != "" {
					return selectedAddress
				}
			}
		}
		return clientIPKey(request)
	}
}

func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
