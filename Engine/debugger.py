"""Serialized JSON worker around the real LLDB SB API, with asynchronous execution."""
import importlib
import os
import shlex
import subprocess
import sys
import time
import tempfile
import faulthandler

class Debugger:
    def __init__(self):
        self.trace_file=tempfile.NamedTemporaryFile(mode='w',prefix='asteria-debug-',suffix='.log',delete=False) if os.environ.get('ASTERIA_DEBUG_TRACE')=='1' else None
        module_path=subprocess.check_output(['/usr/bin/xcrun','lldb','-P'],text=True,timeout=15).strip()
        sys.path.insert(0,module_path)
        self.lldb=importlib.import_module('lldb')
        l=self.lldb
        l.SBDebugger.Initialize()
        self.debugger=l.SBDebugger.Create(False)
        self.debugger.SetAsync(True)
        self.target=l.SBTarget(); self.process=l.SBProcess(); self.owned=False
        self.output=''; self.note=''; self.path=''; self.frame_index=0; self.detached=False
        self.command('settings set target.load-script-from-symbol-file false')
        self.command('settings set target.load-cwd-lldbinit false')
        self.command('settings set target.max-children-count 128')
        self.command('settings set target.process.thread.max-backtrace-depth 128')
    def trace(self,stage):
        if self.trace_file is None: return
        if self.trace_file.tell()>1024*1024:
            self.trace_file.seek(0); self.trace_file.truncate()
        self.trace_file.write('%.3f %s\n'%(time.monotonic(),stage)); self.trace_file.flush()

    def command(self,text):
        result=self.lldb.SBCommandReturnObject()
        if self.process.IsValid() and self.process.GetState() in (self.lldb.eStateStopped,self.lldb.eStateCrashed):
            frame=self.process.GetSelectedThread().GetFrameAtIndex(self.frame_index)
            self.debugger.GetCommandInterpreter().HandleCommand(text,self.lldb.SBExecutionContext(frame),result)
        else:
            self.debugger.GetCommandInterpreter().HandleCommand(text,result)
        self.target=self.debugger.GetSelectedTarget()
        if self.target.IsValid():
            self.process=self.target.GetProcess()
            self.path=str(self.target.GetExecutable())
        output=(result.GetOutput() or '')+(result.GetError() or '')
        if not result.Succeeded(): raise ValueError(output.strip() or 'LLDB command failed')
        return output
    def check(self,error):
        if error.Fail(): raise ValueError(error.GetCString() or 'LLDB operation failed')
    def active(self):
        l=self.lldb
        return self.process.IsValid() and self.process.GetState() not in (l.eStateInvalid,l.eStateExited,l.eStateDetached,l.eStateUnloaded)
    def stopped(self):
        if self.process.GetState() not in (self.lldb.eStateStopped,self.lldb.eStateCrashed,self.lldb.eStateSuspended):
            raise ValueError('Pause the process before inspecting or stepping')
    def drain_events(self):
        # LLDB publishes process state when events are removed from its listener.
        # Without draining, GetState can stay "stopped" while the target runs.
        event=self.lldb.SBEvent()
        listener=self.debugger.GetListener()
        for _ in range(1024):
            if not listener.GetNextEvent(event): break
            if self.lldb.SBProcess.EventIsProcessEvent(event):
                self.lldb.SBProcess.GetStateFromEvent(event)

    def handle(self,q):
        self.trace('handle '+q.get('action','snapshot'))
        self.drain_events()
        action=q.get('action','snapshot'); l=self.lldb; result=''
        if action in ('target','launch','continue','thread','stepInto','stepOver','instructionInto','instructionOver'): self.frame_index=0
        if action in ('target','launch','attach','remote','core'): self.detached=False
        if action=='target':
            if self.active(): raise ValueError('Detach or terminate the current process first')
            path=os.path.realpath(q['path'])
            if not os.path.isfile(path): raise ValueError('Target file does not exist')
            err=l.SBError()
            platform=q.get('platform','host')
            self.target=self.debugger.CreateTarget(path,q.get('triple') or None,platform,True,err)
            self.check(err)
            if not self.target.IsValid(): raise ValueError('LLDB cannot create a target for this format')
            self.path=path; self.process=l.SBProcess(); self.owned=False
            self.debugger.SetSelectedTarget(self.target)
            self.note='Target ready; execution has not started.'
        elif action=='launch':
            if not self.target.IsValid(): raise ValueError('Prepare a target first')
            if self.active(): raise ValueError('A process is already active')
            if self.target.GetPlatform().GetName()!='host': raise ValueError('Prepare a Local macOS target before local launch')
            with open(self.path,'rb') as f: magic=f.read(4)
            if magic not in (b'\xcf\xfa\xed\xfe',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xfe\xed\xfa\xce',b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf'):
                raise ValueError('Local launch supports macOS Mach-O executables. Use a remote target for PE/ELF.')
            args=shlex.split(q.get('arguments',''))
            info=l.SBLaunchInfo(args)
            info.SetWorkingDirectory(q.get('cwd') or os.path.dirname(self.path))
            flags=info.GetLaunchFlags()
            flags &= ~l.eLaunchFlagDisableASLR
            if q.get('stopAtEntry',True): flags |= l.eLaunchFlagStopAtEntry
            info.SetLaunchFlags(flags)
            environment=q.get('environment','').splitlines()
            if any('=' not in e for e in environment if e.strip()): raise ValueError('Environment entries must be NAME=value, one per line')
            if environment: info.SetEnvironmentEntries([e for e in environment if e.strip()],True)
            err=l.SBError(); self.process=self.target.Launch(info,err); self.check(err)
            self.owned=True; self.note='Launched local process.'
            if self.process.GetState()==l.eStateExited and self.process.GetExitStatus()==-1:
                raise ValueError('Debug launch failed: '+(self.process.GetExitDescription() or 'process unavailable')+'. Check macOS debugger authorization and the executable signature.')
        elif action=='attach':
            if self.active(): raise ValueError('A process is already active')
            if not self.target.IsValid(): self.target=self.debugger.CreateTarget('')
            if self.target.GetPlatform().GetName()!='host': raise ValueError('Prepare a Local macOS target before PID attach')
            err=l.SBError(); self.process=self.target.AttachToProcessWithID(self.debugger.GetListener(),int(q['pid']),err); self.check(err)
            self.owned=False; self.note='Attached to process.'
        elif action=='remote':
            if not self.target.IsValid(): raise ValueError('Prepare the local symbol file and matching remote platform first')
            if self.active(): raise ValueError('A process is already active')
            endpoint=q['endpoint'].strip()
            if not endpoint or '\n' in endpoint or any(c.isspace() for c in endpoint): raise ValueError('Use host:port for a gdb-remote stub')
            url=endpoint if endpoint.startswith('connect://') else 'connect://'+endpoint
            err=l.SBError(); self.process=self.target.ConnectRemote(self.debugger.GetListener(),url,'gdb-remote',err); self.check(err)
            self.owned=False; self.note='Connected to remote debugger.'
        elif action=='core':
            if self.active(): raise ValueError('Detach or terminate the process before loading a core')
            if not self.target.IsValid(): self.target=self.debugger.CreateTarget('')
            err=l.SBError(); self.process=self.target.LoadCore(q['path'],err); self.check(err)
            self.owned=False; self.note='Core loaded for inspection.'
        elif action=='breakpoint':
            if not self.target.IsValid(): raise ValueError('Prepare a target first')
            spec=q['spec'].strip()
            if not spec: raise ValueError('Enter a symbol or address')
            if spec.startswith('0x'):
                address=int(spec,16)
                bp=self.target.BreakpointCreateBySBAddress(self.target.ResolveFileAddress(address))
            else: bp=self.target.BreakpointCreateByName(spec)
            if not bp.IsValid(): raise ValueError('Breakpoint could not be created')
            if q.get('condition'): bp.SetCondition(q['condition'])
            self.note='Breakpoint %d: %d resolved location(s)'%(bp.GetID(),bp.GetNumLocations())
        elif action=='deleteBreakpoint':
            if not self.target.BreakpointDelete(int(q['id'])): raise ValueError('Breakpoint does not exist')
        elif action=='toggleBreakpoint':
            bp=self.target.FindBreakpointByID(int(q['id']))
            if not bp.IsValid(): raise ValueError('Breakpoint does not exist')
            bp.SetEnabled(not bp.IsEnabled())
        elif action=='continue': self.stopped(); self.check(self.process.Continue())
        elif action=='pause': self.check(self.process.Stop())
        elif action in ('stepInto','stepOver','stepOut','instructionInto','instructionOver'):
            self.stopped(); thread=self.process.GetSelectedThread()
            if not thread.IsValid(): raise ValueError('No selected thread')
            if action=='stepInto': thread.StepInto()
            elif action=='stepOver': thread.StepOver()
            elif action=='stepOut':
                thread.StepOutOfFrame(thread.GetFrameAtIndex(self.frame_index)); self.frame_index=0
            else: thread.StepInstruction(action=='instructionOver')
        elif action=='thread':
            self.stopped()
            if not self.process.SetSelectedThreadByID(int(q['id'])): raise ValueError('Thread not found')
        elif action=='frame':
            self.stopped()
            index=int(q['id'])
            if not 0<=index<128 or not self.process.GetSelectedThread().GetFrameAtIndex(index).IsValid(): raise ValueError('Frame not found')
            self.frame_index=index
        elif action=='memory':
            self.stopped(); address=int(q['address'],0); count=max(1,min(int(q.get('count',256)),65536))
            err=l.SBError(); data=self.process.ReadMemory(address,count,err); self.check(err)
            result='\n'.join('%016x  %-47s  |%s|'%(address+i,data[i:i+16].hex(' '),''.join(chr(c) if 32<=c<127 else '.' for c in data[i:i+16])) for i in range(0,len(data),16))
        elif action=='expression':
            self.stopped()
            opts=l.SBExpressionOptions(); opts.SetTimeoutInMicroSeconds(2000000); opts.SetTryAllThreads(False)
            value=self.process.GetSelectedThread().GetFrameAtIndex(self.frame_index).EvaluateExpression(q['expression'],opts)
            self.check(value.GetError()); result=str(value)
        elif action=='command': result=self.command(q['command'])
        elif action=='stdin':
            if not self.active(): raise ValueError('No active process')
            count=self.process.PutSTDIN(q['text']); result='Sent %d bytes'%count
        elif action=='detach': self.check(self.process.Detach()); self.owned=False; self.detached=True
        elif action=='kill': self.check(self.process.Kill()); self.owned=False
        elif action=='shutdown':
            if self.active():
                if self.owned: self.process.Kill()
                else: self.process.Detach()
            l.SBDebugger.Destroy(self.debugger)
            if self.trace_file: self.trace_file.close()
            return dict(shutdown=True)
        elif action!='snapshot': raise ValueError('Unknown debugger action: '+action)
        state=self.snapshot(); state['result']=result
        return state
    def snapshot(self):
        if self.trace_file: faulthandler.dump_traceback_later(8,file=self.trace_file)
        self.trace('snapshot events')
        self.drain_events()
        self.trace('snapshot state')
        l=self.lldb; p=self.process; t=self.target
        # Commands can replace the current target/process.
        state=l.SBDebugger.StateAsCString(p.GetState()) if p.IsValid() else 'ready' if t.IsValid() else 'idle'
        if self.detached: state='detached'
        d=dict(state=state or 'unknown',pid=p.GetProcessID() if p.IsValid() else 0,description=self.note,
               triple=t.GetTriple() or '' if t.IsValid() else '',targetPath=str(t.GetExecutable()) if t.IsValid() else '',platform=t.GetPlatform().GetName() or 'host' if t.IsValid() else 'host',breakpoints=[],threads=[],frames=[],registers=[],variables=[],modules=[],output='',pc='',assembly='',result='')
        self.trace('snapshot modules')
        if t.IsValid():
            for i in range(min(t.GetNumBreakpoints(),2000)):
                bp=t.GetBreakpointAtIndex(i); stream=l.SBStream(); bp.GetDescription(stream)
                d['breakpoints'].append(dict(id=bp.GetID(),enabled=bp.IsEnabled(),locations=bp.GetNumLocations(),hits=bp.GetHitCount(),condition=bp.GetCondition() or '',description=stream.GetData() or ''))
            for i in range(min(t.GetNumModules(),512)):
                m=t.GetModuleAtIndex(i); addr=m.GetObjectFileHeaderAddress().GetLoadAddress(t)
                d['modules'].append(dict(name=str(m.GetFileSpec()),address='0x%x'%addr if addr!=l.LLDB_INVALID_ADDRESS else '',uuid=m.GetUUIDString() or ''))
        self.trace('snapshot output')
        if p.IsValid():
            d['output']=(p.GetSTDOUT(65536) or '')+(p.GetSTDERR(65536) or '')
            if p.GetState()==l.eStateExited: d['description']='Exited with status %d%s'%(p.GetExitStatus(), (': '+p.GetExitDescription()) if p.GetExitDescription() else '')
        self.trace('snapshot threads')
        if p.GetState() in (l.eStateStopped,l.eStateCrashed,l.eStateSuspended):
            self.trace('get selected thread')
            selected=p.GetSelectedThread()
            self.trace('get thread count')
            # Prefer the thread that actually stopped at a breakpoint/signal after Continue.
            if not selected.IsValid() and p.GetNumThreads(): selected=p.GetThreadAtIndex(0); p.SetSelectedThread(selected)
            for i in range(min(p.GetNumThreads(),256)):
                self.trace('get thread '+str(i))
                th=p.GetThreadAtIndex(i)
                self.trace('describe thread '+str(i))
                d['threads'].append(dict(id=th.GetThreadID(),index=th.GetIndexID(),name=th.GetName() or '',reason=th.GetStopDescription(512) or '',selected=th.GetThreadID()==selected.GetThreadID()))
            if selected.IsValid():
                d['description']='Stopped: '+(selected.GetStopDescription(512) or 'paused')
                self.trace('get selected frame')
                # Keep frame selection in the workbench: Xcode's native selection callbacks can stall a standalone worker.
                frame=selected.GetFrameAtIndex(self.frame_index)
                self.trace('get frame count')
                for i in range(min(selected.GetNumFrames(),128)):
                    self.trace('get frame '+str(i))
                    f=selected.GetFrameAtIndex(i); le=f.GetLineEntry()
                    self.trace('describe frame '+str(i))
                    d['frames'].append(dict(id=i,address='0x%x'%f.GetPC(),name=f.GetFunctionName() or '??',location=('%s:%d'%(le.GetFileSpec().GetFilename(),le.GetLine())) if le.IsValid() else '',selected=i==frame.GetFrameID()))
                if frame.IsValid():
                    d['pc']='0x%x'%frame.GetPC()
                    self.trace('snapshot registers')
                    for group in frame.GetRegisters():
                        for value in group:
                            if len(d['registers'])>=256: break
                            d['registers'].append(dict(name=value.GetName() or '',value=value.GetValue() or '',group=group.GetName() or ''))
                    self.trace('snapshot variables')
                    for value in frame.GetVariables(True,True,False,True):
                        if len(d['variables'])>=256: break
                        d['variables'].append(dict(name=value.GetName() or '',value=value.GetValue() or value.GetSummary() or '',type=value.GetTypeName() or ''))
                    self.trace('snapshot instructions')
                    ins=t.ReadInstructions(frame.GetPCAddress(),24)
                    d['assembly']='\n'.join('%016x  %-9s %s%s'%(i.GetAddress().GetLoadAddress(t),i.GetMnemonic(t) or '',i.GetOperands(t) or '',('  ; '+i.GetComment(t)) if i.GetComment(t) else '') for i in ins)
        if self.detached: d['description']='Detached; process is no longer monitored.'
        self.trace('snapshot done')
        if self.trace_file: faulthandler.cancel_dump_traceback_later()
        return d
