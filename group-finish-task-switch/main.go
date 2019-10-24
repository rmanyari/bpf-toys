package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	bpf "github.com/rmanyari/gobpf/bcc"
)

import "C"

const bpfString = `
#include <linux/sched.h>

struct my_task_struct {
	char comm[TASK_COMM_LEN];
	pid_t pid;
	pid_t tgid;
};

BPF_HASH(switch_table, struct my_task_struct, int);

int trace_finish_task_switch(struct pt_regs *ctx)
{
	struct my_task_struct proc = {};
	struct task_struct *curr_task  = (struct task_struct *)bpf_get_current_task();
	proc.pid = curr_task->pid;
	proc.tgid = curr_task->tgid;
	memcpy(proc.comm, curr_task->comm, TASK_COMM_LEN);
	switch_table.increment(proc, 1);
	return 0;
}
`

type MyTaskMetrics struct {
	Proc  MyTask
	Count uint32
}

func (p *MyTaskMetrics) String() string {
	return fmt.Sprintf("%s has switched %d times", p.Proc.String(), p.Count)
}

type ByMyTaskMetrics []MyTaskMetrics

func (c ByMyTaskMetrics) Len() int           { return len(c) }
func (c ByMyTaskMetrics) Swap(i, j int)      { c[i], c[j] = c[j], c[i] }
func (c ByMyTaskMetrics) Less(i, j int) bool { return c[i].Count < c[j].Count }

type MyTask struct {
	Comm [16]byte
	PID  uint32
	TGID uint32
}

func (p *MyTask) String() string {
	return fmt.Sprintf("Proc %s with PID %d and TGID %d", string(p.Comm[:]), p.PID, p.TGID)
}

func AccMetricsAndClear(t *bpf.Table, acc map[MyTask]uint32) error {
	i := t.Iter()
	for {
		if !i.Next() {
			break
		}
		var proc MyTask
		if err := binary.Read(bytes.NewBuffer(i.Key()), binary.LittleEndian, &proc); err != nil {
			return err
		}
		count := binary.LittleEndian.Uint32(i.Leaf())
		seen, ok := acc[proc]
		if !ok {
			acc[proc] = count
			continue
		}
		acc[proc] = count + seen
	}
	return t.DeleteAll()
}

func main() {
	module := bpf.NewModule(bpfString, []string{})
	defer module.Close()

	scheduleFnName := "finish_task_switch"
	bpfFnName := "trace_finish_task_switch"
	scheduleProbe, err := module.LoadKprobe(bpfFnName)
	if err != nil {
		log.Fatalf("Error loading kprobe for %s: %s", bpfFnName, err)
	}
	if err := module.AttachKprobe(scheduleFnName, scheduleProbe, -1); err != nil {
		log.Fatalf("Failed to attach kprobe to %s: %s", scheduleFnName, err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(1000 * time.Millisecond)
	switchTable := bpf.NewTable(module.TableId("switch_table"), module)

	counters := make(map[MyTask]uint32)

	for {
		select {
		case <-sigs:
			return
		case <-ticker.C:
			if err := AccMetricsAndClear(switchTable, counters); err != nil {
				log.Fatalf("Failed to print and clear values from table %s: %s", switchTable.Name(), err)
			}
			var pcounters []MyTaskMetrics
			for k, v := range counters {
				pcounters = append(pcounters, MyTaskMetrics{Proc: k, Count: v})
			}
			sort.Sort(ByMyTaskMetrics(pcounters))
			for _, c := range pcounters {
				log.Printf("%s", c.String())
			}
		}
	}
}
