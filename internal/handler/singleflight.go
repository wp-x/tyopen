package handler

import "sync"

type singleCall struct {
	done  chan struct{}
	value interface{}
	err   error
}

type singleGroup struct {
	mu sync.Mutex
	m  map[string]*singleCall
}

func (g *singleGroup) Do(key string, fn func() (interface{}, error)) (interface{}, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*singleCall)
	}
	if call, ok := g.m[key]; ok {
		g.mu.Unlock()
		<-call.done
		return call.value, call.err
	}
	call := &singleCall{done: make(chan struct{})}
	g.m[key] = call
	g.mu.Unlock()

	call.value, call.err = fn()
	close(call.done)

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return call.value, call.err
}
