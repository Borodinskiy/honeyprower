package handlers

import (
	"sort"
	"strconv"
	"strings"

	"honeyprower/internal/catalog"
	"honeyprower/internal/models"
)

// parsePortSpec разбирает "8000-8005,9200" так же, как агент (util::parse_ports):
// неверные части пропускаются, порты вне 1..65535 отбрасываются, повторы схлопываются.
func parsePortSpec(spec string) []int {
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, hi = strings.TrimSpace(a), strings.TrimSpace(b)
		}
		from, err1 := strconv.Atoi(lo)
		to, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil {
			continue
		}
		from, to = max(from, 1), min(to, 65535)
		for p := from; p <= to; p++ {
			seen[p] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// trapProto — транспорт класса ловушки (tcp, если класс неизвестен).
func trapProto(class string) string {
	if c, ok := catalog.ClassByID(class); ok && c.Transport != "" {
		return c.Transport
	}
	return "tcp"
}

// trapSockets — порты, которые ловушка займёт на хосте, вида "2222/tcp".
func trapSockets(t *models.Trap) []string {
	proto := trapProto(t.Class)
	var ports []int
	if c, ok := catalog.ClassByID(t.Class); ok && c.MultiPort {
		ports = parsePortSpec(t.Ports)
	} else if t.Port > 0 {
		ports = []int{t.Port}
	}
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(p) + "/" + proto
	}
	return out
}

// portClash ищет включённую ловушку того же хоста, которая уже занимает порт
// кандидата. Агент открывает порты всех ловушек сразу и при пересечении не
// запустится, поэтому конфликт ловим при сохранении. Пусто — конфликта нет.
func portClash(cand *models.Trap, all []models.Trap) (socket string, other *models.Trap) {
	if cand.HostID == nil || !cand.Enabled {
		return "", nil
	}
	mine := map[string]bool{}
	for _, s := range trapSockets(cand) {
		mine[s] = true
	}
	for i := range all {
		o := &all[i]
		if o.ID == cand.ID || !o.Enabled || o.HostID == nil || *o.HostID != *cand.HostID {
			continue
		}
		for _, s := range trapSockets(o) {
			if mine[s] {
				return s, o
			}
		}
	}
	return "", nil
}
