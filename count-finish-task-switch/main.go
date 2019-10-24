package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/rmanyari/gobpf/bcc"
)

import "C"

const bpfString = `
#include <linux/sched.h>

BPF_HASH(task_switch, int, int);

int trace_finish_task_switch(struct pt_regs *ctx)
{
	task_switch.increment(1, 1);
	return 0;
}
`

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

	d := 1000 * time.Millisecond
	ticker := time.NewTicker(d)
	switchTable := bpf.NewTable(module.TableId("task_switch"), module)

	var one C.int = C.int(1)
	var oneP unsafe.Pointer = unsafe.Pointer(&one)

	for {
		select {
		case <-sigs:
			return
		case <-ticker.C:
			valueP, err := switchTable.GetP(oneP)
			if err != nil {
				log.Printf("Error while getting value for key %+v: %s", one, err)
			}
			value := *(*int)(valueP)
			log.Printf("Number of finish_task_switch in the last %s: %d", d, value)
			if err := switchTable.DeleteAll(); err != nil {
				log.Printf("Error deleting table values: %s", err)
			}
		}
	}
}
