package flow

import "container/heap"

type activeFlow struct {
	key                   Key
	counters              Counters
	recentIndex, dueIndex int
}

type flowIndex struct {
	entries      []*activeFlow
	deadlines    bool
	active, idle uint64
}

func (h flowIndex) Len() int { return len(h.entries) }
func (h flowIndex) time(f *activeFlow) uint64 {
	if !h.deadlines {
		return f.counters.Last
	}
	return min(f.counters.First+h.active, f.counters.Last+h.idle)
}
func (h flowIndex) Less(i, j int) bool { return h.time(h.entries[i]) < h.time(h.entries[j]) }
func (h flowIndex) set(f *activeFlow, i int) {
	if h.deadlines {
		f.dueIndex = i
	} else {
		f.recentIndex = i
	}
}
func (h flowIndex) Swap(i, j int) {
	h.entries[i], h.entries[j] = h.entries[j], h.entries[i]
	h.set(h.entries[i], i)
	h.set(h.entries[j], j)
}
func (h *flowIndex) Push(value interface{}) {
	f := value.(*activeFlow)
	h.set(f, len(h.entries))
	h.entries = append(h.entries, f)
}
func (h *flowIndex) Pop() interface{} {
	i := len(h.entries) - 1
	f := h.entries[i]
	h.entries[i] = nil
	h.entries = h.entries[:i]
	h.set(f, -1)
	return f
}

type flowTable struct {
	flows       map[Key]*activeFlow
	recent, due flowIndex
}

func newTable(c Config) flowTable {
	return flowTable{flows: make(map[Key]*activeFlow),
		due: flowIndex{deadlines: true, active: uint64(c.active), idle: uint64(c.idle)}}
}

func (t *flowTable) add(p Packet) {
	f := t.flows[p.Key]
	if f == nil {
		f = &activeFlow{key: p.Key}
		f.counters.add(p)
		t.flows[p.Key] = f
		heap.Push(&t.recent, f)
		heap.Push(&t.due, f)
		return
	}
	f.counters.add(p)
	heap.Fix(&t.recent, f.recentIndex)
	heap.Fix(&t.due, f.dueIndex)
}

func (t *flowTable) remove(f *activeFlow) {
	heap.Remove(&t.recent, f.recentIndex)
	heap.Remove(&t.due, f.dueIndex)
	delete(t.flows, f.key)
}
