package pawpal

import (
	"crypto/subtle"
	"fmt"

	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

const maxSafeInteger = 9_007_199_254_740_991

func VerifyWebhook(providedKey, expectedKey string, payload any) WebhookVerification {
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{WebhookUnauthorized, 0}
	}
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{WebhookMalformed, 0}
	}
	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok || math.IsNaN(orderID) || math.IsInf(orderID, 0) || math.Trunc(orderID) != orderID || math.Abs(orderID) > maxSafeInteger {
		return WebhookVerification{WebhookMalformed, 0}
	}
	if payloadRecord["status"] != "approved" { // interface equality comparison ?
		return WebhookVerification{WebhookMalformed, 0}
	}

	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
