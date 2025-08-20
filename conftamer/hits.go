package conftamer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
	set "github.com/hashicorp/go-set"
)

/* Handlers for breakpoint/watchpoint hits.
 * Handlers can update state but should not start/stop the target. */

// Data structures used to create the configuration tamer

type Param struct {
	Module string
	File   string
	Param  string
}
type TaintingParam struct {
	Param Param
	Flow  TaintFlow
}

type BehaviorType string

const (
	NetworkMsg BehaviorType = "network message"
	FnArg      BehaviorType = "function argument"
)

type BehaviorValue struct {
	Offset        uint64 // offset in data (e.g. message or argument)
	Send_module   string
	Recv_module   string
	Behavior_type BehaviorType
	Network_msg   NetworkMessage
	Function_arg  FunctionArg
}

type NetworkMessage struct {
	Send_endpoint string // IP:port
	Recv_endpoint string // IP:port
	Transport     string // transport protocol
	// XXX protocol, request vs response
}

type FunctionArg struct {
	Function_name string
	Arg_name      string
}

type TaintingBehavior struct {
	Behavior BehaviorValue
	Flow     TaintFlow
}

type TaintingVals struct {
	Params    set.Set[TaintingParam]
	Behaviors set.Set[TaintingBehavior]
}

type BehaviorMap map[BehaviorValue]TaintingVals

// Info about a breakpoint or watchpoint hit
type Hit struct {
	thread    *api.Thread
	hit_bp    *api.Breakpoint
	hit_instr *api.AsmInstruction
	// Scope to check taint in (first non-runtime frame)
	scope api.EvalScope
	// Length of stack
	stack_len int
}

// A command needed before setting a watchpoint,
// and the criteria for when that command is done
type Command struct {
	cmd string
	// Length of stack when we've reached the destination
	stack_len int
	// Line number when recorded
	lineno int
}

// Exprs/args we will set a wp on, once they're in scope.
// If add any fields, update String()
type PendingWp struct {
	watchexprs set.Set[string]
	// Arg index
	watchargs set.Set[int]
	// TaintingVals for each variable in the memory region that taints these watchexprs/args.
	// Each inner array is indexed by offset in variable.
	// Copy from mem_param_map, so we have them even if the hit wp goes OOS
	// (e.g. hit for return of function local - will set wp after function returns).
	// Empty struct means offset is untainted.
	tainting_vals [][]TaintingVals
	// Whether to apply tainting_vals[0][0] to all bytes rather than applying taint byte-by-byte
	taint_all_bytes bool

	threadID int

	/* Used if need to execute commands to reach in-scope location (vs setting a breakpoint) */

	// The sequence of commands needed
	cmds []Command
	// If executing a command sequence, the index in the sequence
	cmd_idx int
}

type TaintCheck struct {
	config Config
	client *rpc2.RPCClient

	// Watchpoints waiting to be set when we hit a breakpoint
	// Key: Bp addr
	bp_pending_wps map[uint64]PendingWp

	// Watchpoint waiting to be set after a command sequence completes
	cmd_pending_wp *PendingWp
	// If we're in a branch body, the start/end lines
	body_start int
	body_end   int

	// Note for both mem_param_map and behavior_map, each entry is for a single byte
	// (memory address or message offset).
	// Everything in mem_param_map overlaps some watchpoint, but each watchpoint is a contiguous region

	// Memory address => config/behavior values that taint it
	// Don't need PC to disambiguate - if memory is reused,
	// old entry will have gone OOS and been removed
	mem_param_map map[uint64]TaintingVals

	// Behavior value => config/behavior values that taint it
	behavior_map BehaviorMap

	event_log *csv.Writer

	logger *slog.Logger
}

const (
	// Name of buf param in syscall.write
	SyscallRecvBuf = "p"
	// Used as filename for params loaded from config API
	ConfigAPI = "config API"
)

// Handle syscall entry bp hit - server returns it to us if tainted
func (tc *TaintCheck) handleSyscallEntry(hit *Hit) {
	raw_info := hit.hit_bp.UserData
	jsonString, _ := json.Marshal(raw_info)
	info := proc.SyscallBreakpointInfo{}
	json.Unmarshal(jsonString, &info)
	socket := info.Local_endpoint != ""

	if info.SyscallName == "syscall.write" {
		// Send tainted network message => add to behavior map its tainted offsets,
		// i.e. region of send buf that overlaps watched region
		sent_msg := BehaviorValue{
			Offset:        0,
			Send_module:   tc.config.Module,
			Behavior_type: NetworkMsg,
			Network_msg: NetworkMessage{
				Send_endpoint: info.Local_endpoint, Recv_endpoint: info.Remote_endpoint, Transport: info.Transport,
			},
		}
		event := Event{EventType: MessageSend, Address: info.Bufaddr, Size: info.Bufsz, Behavior: &sent_msg}
		WriteEvent(hit.thread, tc.event_log, event)

		for buf_addr := info.Bufaddr; buf_addr < info.Bufaddr+info.Bufsz; buf_addr++ {
			tainting_vals, ok := tc.mem_param_map[buf_addr]
			if !ok {
				continue
			}
			sent_msg.Offset = buf_addr - info.Bufaddr
			tc.behavior_map[sent_msg] = tainting_vals
			event := Event{EventType: BehaviorMapUpdate, Size: 1, Behavior: &sent_msg, TaintingVals: &tainting_vals}
			WriteEvent(hit.thread, tc.event_log, event)
		}
	} else if info.SyscallName == "syscall.read" && socket && info.Local_endpoint != tc.config.Config_API_endpoint {
		// Receive network message (not for config API) => set watchpoint on entire read buffer, tainted by message
		recvd_msg := BehaviorValue{
			Offset:        0,
			Recv_module:   tc.config.Module,
			Behavior_type: NetworkMsg,
			Network_msg: NetworkMessage{
				Send_endpoint: info.Remote_endpoint, Recv_endpoint: info.Local_endpoint, Transport: info.Transport,
			},
		}
		event := Event{EventType: MessageRecv, Address: info.Bufaddr, Size: info.Bufsz, Behavior: &recvd_msg}
		WriteEvent(hit.thread, tc.event_log, event)
		if !tc.config.Ignore_msg_recvs {
			recvd_msg.Offset = info.Bufsz // Used in setWatchpoint
			tainting_msg := TaintingBehavior{
				Behavior: recvd_msg,
				Flow:     DataFlow,
			}
			// frame 3 = syscall.read
			hit.scope.Frame = 3
			// PERF consider delaying this wp set - server will immediately un-mprotect for duration of read)
			tv := MakeTaintingVals(nil, &tainting_msg)
			tc.setWatchpoint(SyscallRecvBuf, [][]TaintingVals{{tv}}, true, true, hit)
		}
	} else if info.SyscallName == "syscall.read" {
		// Load config from file or API => set watchpoint on entire read buffer, tainted by empty param
		// (Will populate param with contents of buffer on first access)
		if info.Local_endpoint == tc.config.Config_API_endpoint && socket {
			info.Filename = ConfigAPI
		}

		tainting_param := TaintingParam{
			Param: Param{
				File:   info.Filename,
				Module: tc.config.Module,
			},
			Flow: DataFlow,
		}
		tv := MakeTaintingVals(&tainting_param, nil)
		event := Event{EventType: ConfigLoad, Address: info.Bufaddr, Size: info.Bufsz, TaintingVals: &tv}
		WriteEvent(hit.thread, tc.event_log, event)
		hit.scope.Frame = 3
		tc.setWatchpoint(SyscallRecvBuf, [][]TaintingVals{{tv}}, true, false, hit)
	} else {
		log.Panicf("Syscall entry breakpoint hit for unexpected syscall %v\n", info.SyscallName)
	}
}

/* If hit was in runtime or internal, either ignore (e.g. newstack), or
 * record first non-runtime/internal frame as line to check taint in.
 * (Assumption is function was called implicitly by target code, so we should go to the first explicit frame.
 * Also, these functions are often optimized or written in asm.)
 * (Can't assume that line will additionally have a non-runtime hit, e.g. some memmoves.)
 * Return false to ignore.
 * TODO are there any runtime functions we want to treat normally (maybe some exported ones?) */
func (tc *TaintCheck) handleRuntimeHit(hit *Hit) (*api.Stackframe, bool) {
	stack := tc.stacktrace()

	hit.stack_len = len(stack)

	skip := runtimeOrInternal(stack[0].File)
	if skip {
		tc.Logf(slog.LevelDebug, hit, "Watchpoint hit in runtime or internal, stack len %v - "+
			"full stack (including first non-runtime frame, whose PC is one after call instr)\n", len(stack))
		tc.printStacktrace()

		for i, frame := range stack {
			fn := frame.Function.Name()

			skip = runtimeOrInternal(frame.File)

			// TODO can go runtime goroutines ever cause hits? (maybe sysmon in early sw wp commit, but may have been due to mprotecting dlv's pages instead)
			// To detect if runtime goroutine: see `goroutines -with user` (https://github.com/go-delve/delve/blob/master/Documentation/cli/README.md#goroutine)
			if fn == "runtime.newstack" {
				return nil, false
			}
			if !skip {
				hit.scope.Frame = i
				return &frame, true
			}
		}
	}

	return nil, true
}

/* Get instruction corresponding to hit */
func (tc *TaintCheck) hittingInstr(non_runtime_frame *api.Stackframe, hit *Hit) {
	pc := hit.thread.PC
	if non_runtime_frame != nil {
		pc = non_runtime_frame.PC
	}
	fct_instr, err := tc.client.DisassemblePC(hit.scope, pc, api.IntelFlavour) // dst, src
	if err != nil {
		log.Panicf("Error disassembling at PC 0x%x: %v\n", pc, err)
	}

	for i, instr := range fct_instr {
		if instr.Loc.PC == pc {
			if non_runtime_frame != nil {
				// For runtime hit, pc is one *after* the call instr that ended up in runtime => get previous instr
				hit.hit_instr = &fct_instr[i-1]
			} else {
				hit.hit_instr = &fct_instr[i]
			}
			return
		}
	}

	log.Panicf("Failed to find instruction at PC 0x%x: %v\n", pc, err)
}

/* Get source line corresponding to hit.
 * Return false to ignore this hit. */
func (tc *TaintCheck) hittingLine(hit *Hit) bool {
	non_runtime_frame, handle := tc.handleRuntimeHit(hit)
	// Ignore prints (may be within print, or when setting up to call print) for convenience
	if tc.hitInPrint() || !handle {
		tc.Logf(slog.LevelDebug, hit, "Ignoring hit")
		return false
	}

	tc.hittingInstr(non_runtime_frame, hit)

	src_line := sourceLine(tc.client, hit.hit_instr.Loc.File, hit.hit_instr.Loc.Line)
	if ignoreSourceLine(src_line) {
		tc.Logf(slog.LevelDebug, hit, "Ignoring hit at: %v", src_line)
		return false
	}

	if src_line == "" {
		log.Panicf("No source line found for PC 0x%x\n", hit.hit_instr.Loc.PC)
	}

	return true
}

/* Populate existing_info with tainting vals from region's m-c entries
 * (they may differ across the region, and some may have none).
 * If no addresses in the region are tainted (watchpoints can include untainted addresses), return false. */
func (tc *TaintCheck) getTaintingVals(existing_info *PendingWp, tainted_region *TaintedRegion, hit *Hit) bool {
	existing_info.threadID = hit.thread.ID
	ifstmt_taint := newTaintingVals()
	found_taint := false
	new_params := map[uint64]string{}
	var total_len, cur_len int
	for _, old_xv := range tainted_region.old_region {
		if old_xv == nil {
			continue // variable failed to eval
		}
		total_len += int(old_xv.Watchsz)
	}

	for i, old_xv := range tainted_region.old_region {
		if old_xv == nil {
			continue // variable failed to eval
		}
		old_start := old_xv.Addr
		old_end := old_start + uint64(old_xv.Watchsz)
		for watchaddr := old_start; watchaddr < old_end; watchaddr++ {
			tainting_vals, ok := tc.mem_param_map[watchaddr]
			if ok {
				found_taint = true
			} else {
				// Untainted address => leave tainting vals empty
			}

			// M-c entry has an empty param => presumably we just accessed
			// (some region of) config read buf for the first time. Populate m-c.
			// (Alternative would be to read from file on syscall entry, based on the offset passed)
			if hasEmptyParam(tainting_vals) {
				if len(new_params) == 0 {
					new_params = tc.readParams(old_start, old_end, hit.scope.Frame)
				}
				// XXX ignore offsets that don't correspond to params (e.g. \n)
				tc.populateParam(watchaddr, new_params[watchaddr-old_start])
				tainting_vals = tc.mem_param_map[watchaddr]
			}

			if tainted_region.body_start == 0 {
				// Case 1a: Regular watchpoint => copy tainted_region vals at each offset
				// (offset may already have existing ones, e.g. hit a watchpoint within a tainted branch body - union with those if so).
				if tainted_region.concat_xvs {
					existing_info.updateTaintingVals(tainting_vals, 0, cur_len)
					cur_len++
				} else {
					existing_info.updateTaintingVals(tainting_vals, i, int(watchaddr-old_start))
				}
			} else {
				// Case 1b: Watchpoint in if condition => gather vals from all bytes of overlapping region,
				// to be copied into each byte of expressions in branch body (don't know their size),
				// and set them to control flow
				tainting_vals.Params.ForEach(func(tp TaintingParam) bool {
					tp.Flow = ControlFlow
					ifstmt_taint.Params.Insert(tp)
					return true
				})
				tainting_vals.Behaviors.ForEach(func(tb TaintingBehavior) bool {
					tb.Flow = ControlFlow
					ifstmt_taint.Behaviors.Insert(tb)
					return true
				})
			}
		}
	}

	if tainted_region.body_start != 0 {
		existing_info.updateTaintingVals(ifstmt_taint, 0, 0) // put them all at offset 0 - setWatchpoint will pick them out
		existing_info.taint_all_bytes = true
	}

	return found_taint
}

func (tc *TaintCheck) onPendingWpBpHitDone(hit *Hit) {
	bp_addr := hit.hit_bp.Addrs[0]
	if _, err := tc.client.ClearBreakpoint(hit.hit_bp.ID); err != nil {
		log.Panicf("Failed to clear bp at 0x%x: %v\n", bp_addr, err)
	}
	delete(tc.bp_pending_wps, bp_addr)
}

// Warn or panic if needed
func (tc *TaintCheck) logWatchErr(msg string, err error, hit *Hit) {
	if err == nil {
		return
	}
	errstr := fmt.Sprintf("%v: %v", msg, err.Error())
	if strings.Contains(err.Error(), "type not supported") || strings.Contains(err.Error(), "nil slice") ||
		strings.Contains(err.Error(), "fake address") ||
		strings.Contains(err.Error(), "insane") ||
		strings.Contains(err.Error(), "unreadable") {
		// TODO fake address is likely fixable by setting bp at 2nd instr in function body instead of 1st
		// (unsure if has potential to cause missed access of arg in 1st instr)
		// TODO insane and unreadable are from setting wp on whole struct for multiline lit with slice fields (see unmarshal test) -
		// could improve (see gdoc) by only setting on field (may help PERF too)
		tc.Logf(slog.LevelWarn, hit, errstr)
	} else {
		log.Panicln(errstr)
	}
}

func (tc *TaintCheck) logWatchpoint(watchexpr string, wp *api.Breakpoint, hit *Hit) {
	if wp == nil {
		return
	}
	tc.Logf(slog.LevelDebug, hit, "Set watchpoint on %v", wp.WatchExpr)
	if watchSize(wp) == 0 {
		log.Panicf("Debugger returned sz 0 watchpoint %+v for %v\n", *wp, watchexpr)
	}
	event := Event{EventType: WatchpointSet, Address: wp.Addr, Size: watchSize(wp), Expression: wp.WatchExpr}
	WriteEvent(hit.thread, tc.event_log, event)
}

// Set any watchpoint(s) corresponding to watchexpr
// Update m-c map
func (tc *TaintCheck) setWatchpoint(watchexpr string, tainting_vals [][]TaintingVals, taint_all_bytes bool, msg_recv bool, hit *Hit) {
	// 1. Set watchpoint on full new expr
	// We really want a read-only wp, but not supported
	watchpoints, errs := tc.client.CreateWatchpoint(hit.scope, watchexpr, api.WatchRead|api.WatchWrite, api.WatchSoftware, tc.config.Move_wps)
	for _, err := range errs {
		tc.logWatchErr(fmt.Sprintf("Failed to set watchpoint for %v", watchexpr), err, hit)
	}
	if len(watchpoints) != len(errs) {
		log.Panicf("Debugger returned watchpoints and errs with mismatched lengths: %v vs %v", watchpoints, errs)
	}

	// 2. Update m-c map only for tainted part of new expr
	// Eval expr for new addrs rather than using returned watch region - new region may overlap existing watch region
	// Add pre-move addresses to m-c - will update after next Continue()

	new_xvs, errs := tc.client.EvalWatchexpr(hit.scope, watchexpr, true)
	if len(new_xvs) != len(errs) {
		log.Panicf("Debugger returned vars and errs with mismatched lengths: %v vs %v", new_xvs, errs)
	}

	// TODO test for adding new taint to existing addr

	// If !taint_all_bytes, add tainting_vals to newly tainted region(s), byte by byte
	// Else, we're tainting the recv buf of a network message or config file/API read buf (or initial_watchexpr) =>
	// Network message: record each byte of buf as tainted by corresponding offset of message
	// (tainting_vals[0][0] is recvd msg)
	// Config file/API: record each byte of buf as tainted by corresponding param
	// (tainting_vals[0][0] is param).
	var allbytes_taint TaintingVals
	if taint_all_bytes {
		allbytes_taint = tainting_vals[0][0]
	}

	// Update m-c map
	for i, xv := range new_xvs {
		if i < len(watchpoints) && watchpoints[i] != nil {
			// For testing convenience, interleave watchpoint and m-c map logging
			tc.logWatchpoint(watchexpr, watchpoints[i], hit)
		}
		if errs[i] != nil {
			continue // variable failed to eval
		}

		xv_tainting_vals := []TaintingVals{}
		if len(tainting_vals) > i {
			xv_tainting_vals = tainting_vals[i]
		}
		new_end := xv.Addr + uint64(xv.Watchsz)
		for new_addr := xv.Addr; new_addr < new_end; new_addr++ {
			offset := new_addr - xv.Addr
			new_taint := allbytes_taint

			if !taint_all_bytes {
				// Apply any taint from corresponding byte
				if uint64(len(xv_tainting_vals)) > offset {
					new_taint = union(new_taint, xv_tainting_vals[offset])
				} else {
					// New region is shorter than old (e.g. copy())
					break
				}
			} else if msg_recv {
				// Receive network msg => taint by corresponding msg offset
				tainting_msg := tainting_vals[0][0].Behaviors.Slice()[0]
				tainting_msg.Behavior.Offset = offset
				new_taint = MakeTaintingVals(nil, &tainting_msg)
			}
			tc.updateTaintingVals(new_addr, new_taint, hit.thread)
		}
	}
	// Fewer xvs than wps (unsure if possible) - log any remaining wps
	for i := len(new_xvs); i < len(watchpoints); i++ {
		tc.logWatchpoint(watchexpr, watchpoints[i], hit)
	}
}

/* Record a pending watchpoint for the newly tainted region.
 * Create or update from breakpoint- or command-pending watchpoints,
 * depending on set location. */
func (tc *TaintCheck) pendingWatchpoint(tainted_region *TaintedRegion, hit *Hit) {
	set_at_bp := tainted_region.set_location != nil
	// Get existing pending watchpoint for location (if any)
	pending_watchpoint := PendingWp{}
	if set_at_bp {
		// Breakpoint
		pending_watchpoint = tc.bp_pending_wps[tainted_region.set_location.PC]
	} else if tc.cmd_pending_wp != nil {
		// Existing cmd sequence, if any
		pending_watchpoint = *tc.cmd_pending_wp
		// Currently only supporting single cmd_pending_wp
		if pending_watchpoint.cmds != nil && !reflect.DeepEqual(tainted_region.cmds, pending_watchpoint.cmds) {
			// When advancing through branch body, this is ok (we keep updating the same one throughout branch body)
			tc.Logf(slog.LevelDebug, hit, "Existing cmd_pending_wp %+v has different command sequence than current %+v",
				pending_watchpoint.cmds, tainted_region.cmds)
		}
	}
	// Update commands and branch body info (can change, e.g. if handling a return inside tainted if)
	pending_watchpoint.cmds = tainted_region.cmds
	pending_watchpoint.cmd_idx = 0

	// Populate tainting values
	if hit.hit_bp != nil {
		// Watchpoint hit => copy from region overlapping with hit
		found_taint := tc.getTaintingVals(&pending_watchpoint, tainted_region, hit)
		if !found_taint {
			// Hit for entirely untainted region of watchpoint
			return
		}
	} else {
		// Fake "hit" from finishing next in branch body => tainting vals are already in cmd_pending_wp
		// (created for hit in condition).
		// If new watchpoint is also in cmd_pending, will use those - else, copy them to bp_pending
		if set_at_bp {
			pending_watchpoint.updateTaintingVals(tc.cmd_pending_wp.tainting_vals[0][0], 0, 0) // all at offset 0
		}
	}

	// Insert argno/expr
	if tainted_region.new_argno != nil {
		insert(&pending_watchpoint.watchargs, *tainted_region.new_argno)
	} else if tainted_region.new_expr != nil {
		insert(&pending_watchpoint.watchexprs, *tainted_region.new_expr)
	}
	tc.Logf(slog.LevelDebug, hit, "pendingWatchpoint about to record - watchexprs: %+v, watchargs: %+v, cmds: %+v",
		pending_watchpoint.watchexprs, pending_watchpoint.watchargs, pending_watchpoint.cmds)

	// Record pending watchpoint (or set now, if possible)
	if tainted_region.set_now && len(tainted_region.cmds) == 0 {
		// non-runtime hit, can set now
		tc.Logf(slog.LevelDebug, hit, "Set pending watchpoint now")
		tc.setPendingWatchpoints(&pending_watchpoint, hit)
		// Cleanup if there was already a pending watchpoint at this location
		if set_at_bp {
			delete(tc.bp_pending_wps, tainted_region.set_location.PC)
		} else {
			// cmd-pending - cleaned up in Run()
		}
	} else {
		if set_at_bp {
			tc.setBp(tainted_region.set_location.PC)
			tc.Logf(slog.LevelDebug, hit, "pendingWatchpoint set bp at %v:%v",
				tainted_region.set_location.File, tainted_region.set_location.Line)
			tc.bp_pending_wps[tainted_region.set_location.PC] = pending_watchpoint
		} else {
			tc.cmd_pending_wp = &pending_watchpoint
		}
	}
}

// Watchpoint hit => record any new pending watchpoints.
func (tc *TaintCheck) onWatchpointHit(hit *Hit) {
	if !tc.hittingLine(hit) {
		tc.Logf(slog.LevelDebug, hit, "Not propagating taint for watchpoint hit at %#x", hit.thread.PC)
		return
	}
	event := Event{EventType: WatchpointHit, Address: hit.hit_bp.Addr, Size: watchSize(hit.hit_bp), Expression: hit.hit_bp.WatchExpr}
	WriteEvent(hit.thread, tc.event_log, event)
	tc.Logf(slog.LevelDebug, hit, "Hit watchpoint on %v at %v:%v", hit.hit_bp.WatchExpr, hit.hit_instr.Loc.File, hit.hit_instr.Loc.Line)
	tainted_regions := tc.propagateTaint(hit)
	for _, tainted_region := range tainted_regions {
		tc.pendingWatchpoint(&tainted_region, hit)
	}
	tc.Logf(slog.LevelDebug, hit, "Propagated taint for watchpoint hit on %v", hit.hit_bp.WatchExpr)
}

// Set all watchpoints corresponding to pendingWp, remove them from pendingWp
func (tc *TaintCheck) setPendingWatchpoints(pendingWp *PendingWp, hit *Hit) {
	if pendingWp.watchexprs.Empty() && pendingWp.watchargs.Empty() {
		log.Panicf("No pending watches found\n")
	}
	pendingWp.watchexprs.ForEach(func(watchexpr string) bool {
		tc.setWatchpoint(watchexpr, pendingWp.tainting_vals, pendingWp.taint_all_bytes, false, hit)
		return true
	})
	pendingWp.watchargs.ForEach(func(watcharg int) bool {
		// if method, args include receiver as arg 0 (as we did when recording argno)
		args, err := tc.client.ListFunctionArgs(hit.scope, api.LoadConfig{})
		if err != nil {
			log.Panicf("Failed to list function args for pending wp %+v: %v\n", pendingWp, err)
		}
		watchexpr := args[watcharg].Name
		tc.setWatchpoint(watchexpr, pendingWp.tainting_vals, pendingWp.taint_all_bytes, false, hit)
		return true
	})
	pendingWp.watchexprs = *set.New[string](0)
	pendingWp.watchargs = *set.New[int](0)
}

func (tc *TaintCheck) onPendingWpBpHit(hit *Hit) {
	if len(hit.hit_bp.Addrs) != 1 {
		log.Panicf("Wrong number of addrs at pending wp; bp %+v\n", hit.hit_bp)
	}

	bp_addr := hit.hit_bp.Addrs[0]
	info := tc.bp_pending_wps[bp_addr]
	tc.Logf(slog.LevelDebug, hit, "Hit pending wp breakpoint - watchexprs: %+v, watchargs: %+v, cmds: %+v",
		info.watchexprs, info.watchargs, info.cmds)
	defer func() {
		tc.onPendingWpBpHitDone(hit)
	}()

	tc.setPendingWatchpoints(&info, hit)
}

// Update mem-param map for any watchpoints that moved since last Continue
// (either due to stack adjust or allocator move)
func (tc *TaintCheck) updateMovedWps() {
	// TODO: add a test for stack adjust (happens in xenon, but not deterministically) - and log these m-c updates
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Panicf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps {
		new_addr := bp.Addr
		for _, prev_addrs := range bp.PreviousAddrs {
			for _, prev_addr := range prev_addrs {
				if prev_addr > 0 {
					if tainting_vals, ok := tc.mem_param_map[prev_addr]; ok {
						delete(tc.mem_param_map, prev_addr)
						tc.mem_param_map[new_addr] = tainting_vals
					}
				}
				new_addr++
			}
		}
	}
}

func New(config *Config) (*TaintCheck, error) {
	client := rpc2.NewClient(config.Server_endpoint)

	event_log_file, err := os.Create(config.Event_log_filename)
	if err != nil {
		return nil, err
	}

	// TODO (minor) rename TaintCheck to e.g. ConfTamerModule
	tc := TaintCheck{
		config:         *config,
		client:         client,
		bp_pending_wps: make(map[uint64]PendingWp),
		mem_param_map:  make(map[uint64]TaintingVals),
		behavior_map:   make(BehaviorMap),
		event_log:      csv.NewWriter(event_log_file),
	}

	// TODO (minor) make log level configurable
	tc.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{AddSource: true, Level: config.LoggerLevel,
		// Shorten paths for client filenames
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				source, _ := a.Value.Any().(*slog.Source)
				if source != nil {
					source.File = filepath.Base(source.File)
				}
			}
			return a
		}}))

	tc.event_log.Write([]string{"Type", "Memory Address", "Memory Size", "Expression", "Behavior", "Tainting Values",
		"Timestamp", "Breakpoint/Watchpoint Hit Location (File Line PC)", "Thread"})

	if config.Initial_watchexpr != "" {
		// For testing: pass in an expr to set a watchpoint on
		tainting_param := TaintingParam{Param: Param{Module: tc.config.Module, Param: config.Initial_watchexpr}, Flow: DataFlow}
		tainting_vals := [][]TaintingVals{{MakeTaintingVals(&tainting_param, nil)}}
		if config.Initial_bp_file != "" {
			// Config specifies initial location => set bp there
			init_loc := tc.lineWithStmt(config.Initial_bp_file, config.Initial_bp_line, 0)
			tc.bp_pending_wps[init_loc.PC] = PendingWp{
				watchexprs: *set.From([]string{config.Initial_watchexpr}),
				// Will be copied into each byte of config variable (don't know its size)
				tainting_vals:   tainting_vals,
				taint_all_bytes: true,
			}
			tc.setBp(init_loc.PC)
		} else {
			// No initial location => set it now (assumes server is already attached to the target - for self-CTscan)
			tc.setWatchpoint(config.Initial_watchexpr, tainting_vals, true, false, &Hit{
				scope: api.EvalScope{GoroutineID: config.Initial_goroutine, Frame: config.Initial_frame},
			})
		}
	}

	return &tc, nil
}
