package storage

import (
	"sort"
	"time"

	"honeyprower/internal/models"
)

// DashboardTop — сколько строк отдаём в топах (IP, ловушки, логины, пароли).
const DashboardTop = 10

// newDashboard заводит пустой дашборд: окно длиной window заканчивается на
// границе ведра, следующей за now, так что последнее ведро — текущее. Границы
// вёдер ровные по местному времени зрителя (смещение utcOffset от UTC).
func newDashboard(now time.Time, window, bucket, utcOffset time.Duration) *models.Dashboard {
	step := int64(bucket / time.Second)
	off := int64(utcOffset / time.Second)
	until := ((now.Unix()+off)/step+1)*step - off
	n := int(window / bucket)
	since := until - int64(n)*step

	d := &models.Dashboard{
		Since:         float64(since),
		Until:         float64(until),
		BucketSeconds: int(step),
		Timeline:      make([]models.TimeBucket, n),
		ByType:        []models.KeyCount{},
		ByTrap:        []models.TrapCount{},
		TopSources:    []models.SourceCount{},
		TopUsernames:  []models.KeyCount{},
		TopPasswords:  []models.KeyCount{},
	}
	for i := range d.Timeline {
		d.Timeline[i].TS = float64(since + int64(i)*step)
	}
	return d
}

// bucketIndex — номер ведра для момента ts или -1, если ts вне окна.
func bucketIndex(d *models.Dashboard, ts float64) int {
	if ts < d.Since || ts >= d.Until {
		return -1
	}
	return int((ts - d.Since) / float64(d.BucketSeconds))
}

// dashboardFromEvents считает дашборд по событиям в памяти; Postgres делает то же в SQL.
func dashboardFromEvents(d *models.Dashboard, events []models.Event) {
	types := map[string]int{}
	traps := map[int64]*models.TrapCount{}
	sources := map[string]*models.SourceCount{}
	sourceTraps := map[string]map[int64]bool{}
	users := map[string]int{}
	passwords := map[string]int{}

	for _, e := range events {
		b := bucketIndex(d, e.TS)
		if b < 0 {
			continue
		}
		warn := 0
		if isWarning(e.Type) {
			warn = 1
		}
		d.Events++
		d.Warnings += warn
		d.Timeline[b].Events++
		d.Timeline[b].Warnings += warn
		types[e.Type]++

		tc := traps[e.TrapID]
		if tc == nil {
			tc = &models.TrapCount{TrapID: e.TrapID, Name: e.TrapName}
			traps[e.TrapID] = tc
		}
		tc.Events++
		tc.Warnings += warn

		if e.Source != "" {
			sc := sources[e.Source]
			if sc == nil {
				sc = &models.SourceCount{IP: e.Source}
				sources[e.Source] = sc
				sourceTraps[e.Source] = map[int64]bool{}
			}
			sc.Events++
			sc.Warnings += warn
			sourceTraps[e.Source][e.TrapID] = true
			sc.Traps = len(sourceTraps[e.Source])
			if e.TS > sc.LastTS {
				sc.LastTS = e.TS
			}
		}
		if e.Username != nil && *e.Username != "" {
			users[*e.Username]++
		}
		if e.Password != nil && *e.Password != "" {
			passwords[*e.Password]++
		}
	}

	d.UniqueSources = len(sources)
	d.ByType = keyCounts(types, 0)
	d.TopUsernames = keyCounts(users, DashboardTop)
	d.TopPasswords = keyCounts(passwords, DashboardTop)

	for _, tc := range traps {
		d.ByTrap = append(d.ByTrap, *tc)
	}
	sort.Slice(d.ByTrap, func(i, j int) bool {
		a, b := d.ByTrap[i], d.ByTrap[j]
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.TrapID < b.TrapID
	})
	if len(d.ByTrap) > DashboardTop {
		d.ByTrap = d.ByTrap[:DashboardTop]
	}

	for _, sc := range sources {
		d.TopSources = append(d.TopSources, *sc)
	}
	sort.Slice(d.TopSources, func(i, j int) bool {
		a, b := d.TopSources[i], d.TopSources[j]
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return a.IP < b.IP
	})
	if len(d.TopSources) > DashboardTop {
		d.TopSources = d.TopSources[:DashboardTop]
	}
}

// keyCounts сортирует счётчики по убыванию (при равенстве — по ключу); limit 0 — без ограничения.
func keyCounts(m map[string]int, limit int) []models.KeyCount {
	out := make([]models.KeyCount, 0, len(m))
	for k, c := range m {
		out = append(out, models.KeyCount{Key: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
