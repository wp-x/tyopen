package handler

import "testing"

func TestPublicShareRateLimiterSeparatesKeysAndOperations(t *testing.T) {
	limiter := newPublicShareRateLimiter()
	if !limiter.allow("1.1.1.1", "1.1.1.1|share|view", "view", 2) {
		t.Fatal("第一次请求应放行")
	}
	if !limiter.allow("1.1.1.1", "1.1.1.1|share|view", "view", 2) {
		t.Fatal("第二次请求应放行")
	}
	if limiter.allow("1.1.1.1", "1.1.1.1|share|view", "view", 2) {
		t.Fatal("同一 IP/分享/操作超过上限后应拒绝")
	}
	if !limiter.allow("1.1.1.1", "1.1.1.1|share|content", "content", 1) {
		t.Fatal("不同操作应使用独立 bucket")
	}
	if !limiter.allow("2.2.2.2", "2.2.2.2|share|view", "view", 2) {
		t.Fatal("不同 IP 应使用独立 bucket")
	}
}
