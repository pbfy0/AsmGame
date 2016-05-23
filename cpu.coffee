Function::property = (prop, desc) ->
	Object.defineProperty @prototype, prop, desc

TYPE_CONSTANT = 0
TYPE_REGISTER = 1
TYPE_MEMORY = 6

MTYPE_NONE = 0
MTYPE_8 = 1
MTYPE_16 = 2
MTYPE_32 = 3
ra = [null, 'read8', 'read16', 'read32']
wa = [null, 'write8', 'write16', 'write32']
nn = [null, 'BYTE', 'WORD', 'DWORD']

types = ['c', 'r', 'mB', 'pB', 'mH', 'pH', 'mW', 'pW']

R_SP = 30
R_PC = 31

regs = {'sp': 30, 'pc': 31}
for i in [0..31]
	regs['r' + i] = i
rregs = {}
do ->
	for k, v of regs
		rregs[v] = k
	null
Object.assign(rregs, {30: 'sp', 31: 'pc'})
pad = (s, size, padding='0') ->
	s = s.toString();
	while s.length < size
		s = padding + s
	return s

class Operand
	constructor: (@cpu, @type, val) ->
		@raw = val & 0xffff
	@fromstr: (cpu, str) ->
		if str == '<null>' then return new @(cpu, TYPE_REGISTER, 0)
		m = str.match(/\[(.*?)\](?:\.(\d+))?/)
		ptr = 0
		if m
			ptr = {"32": 3, "16": 2, "8": 1, undefined: 3}[m[2]]
			str = m[1]
		if str in ["sp", "pc"] or /r\d+/.test(str)
			rn = regs[str]
			raw = 0xc0 | rn
			type = TYPE_REGISTER
		else if str.startsWith('#')
			raw = parseInt(str.substr(1)) & 0xffff
			type = TYPE_CONSTANT
		type |= ptr << 1
		return new @(cpu, type, raw)
	npsv: ->
		if @type & TYPE_REGISTER and @raw == 0 then return '<null>'
		return if @type & TYPE_REGISTER then rregs[@raw & 0x1f] else '#0x' + @raw.toString(16)
	tn: ->
		types[@type]
	bitfmt: (n) ->
		if @cc
			return place([[2, 'cc='+cca[@cc]], [9, n + '=' + @npsv()]])
		else
			return n + '=' + @npsv()
	toString: ->
		v = @npsv()
		if @type >> 1
			v = '[' + v + '].' + (4 << (@type >> 1))
		return v
	@property 'val', 
		get: ->
			if (@type >> 1) == 0 then return @ptrval
			return @cpu.mem[ra[@type>>1]](@ptrval & 0xffff)

		set: (val) ->
			switch @type
				when TYPE_CONSTANT then return
				when TYPE_REGISTER then @regval = val
				else @cpu.mem[wa[@type>>1]](@ptrval, val)
			return
	memread: (ptr) ->
		if not (@type & TYPE_MEMORY) then throw 'problem'
		@cpu.mem[ra[@type>>1]](ptr)
	memwrite: (ptr, val) ->
		if not (@type & TYPE_MEMORY) then throw 'problem'
		@cpu.mem[wa[@type>>1]](ptr, val)
	@property 'regval',
		get: ->
			if not (@type & TYPE_REGISTER) then throw 'problem'
			v = @cpu.regs[@raw & 0x1f]
			if (@raw & 0xc000) == 0xc000 then v |= @cpu.regs[(@raw >> 8) & 0x1f]
			return v
		set: (val) ->
			if not (@type & TYPE_REGISTER) then throw 'problem'
			@cpu.regs[@raw & 0x1f] = val & 0xffff
			if (@raw & 0xc000) == 0xc000 then @cpu.regs[(@raw >> 8) & 0x1f]
	@property 'ptrval',
		get: ->
			#if not (@type & TYPE_MEMORY) then throw 'problem'
			if @type & TYPE_REGISTER then @regval else @raw
	@property 'readable',
		get: ->
			return (@type & TYPE_REGISTER) == 0 or (@raw & 0xc0) == 0xc0
	@property 'writeable',
		get: ->
			return @type != TYPE_CONSTANT
	@property 'cc',
		get: ->
			if not (@type & TYPE_REGISTER) then return null
			if (@raw & 0xf000) != 0x3000 then return null
			return (@raw & 0x0f00) >> 8
		set: (val) ->
			@raw &= 0x00ff
			@raw |= (0x30 | val) << 8
class Mem
	constructor: ->
		@buf = new ArrayBuffer(0x10000)
		@view = new DataView(@buf)
		@bytes = new Uint8Array(@buf)
	read8: (ptr) ->
		@view.getUint8(ptr, false)
	read16: (ptr) ->
		@view.getUint16(ptr, false)
	read32: (ptr) ->
		@view.getUint32(ptr, false)
	write8: (ptr, val) ->
		@view.setUint8(ptr, val, false)
	write16: (ptr, val) ->
		@view.setUint16(ptr, val, false)
	write32: (ptr, val) ->
		@view.setUint32(ptr, val, false)

F_EQ = 0 
F_NE = 1 
F_CS = 2 
F_HS = 2 
F_CC = 3 
F_LO = 3 
F_MI = 4 
F_PL = 5 
F_VS = 6 
F_VC = 7 
F_HI = 8 
F_LS = 9 
F_GE = 10
F_LT = 11
F_GT = 12
F_LE = 13
F_AL = 14
cca = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', '', '??']
ccs = {}
do ->
	for v, i in cca
		ccs[v] = i
ccs[null] = 0x0e

nf = (n, fn) ->
	fn._name = n
	return fn
	#return new Proxy fn,
	#	get: (val) ->
	#		if val == 'name' then return n
	#		return fn[val]
split = (str, lens) ->
	idx = 0
	for l in lens
		v = str.substr(idx, l)
		idx += l
		v
sm = (s, n) ->
	y = ""
	for i in [0...n]
		y += s
	return y
place = (locs) ->
	s = ""
	idx = 0
	for [loc, val] in locs
		v = val.toString()
		s += sm(" ", loc - idx) + v
		idx = loc + v.length
	return s
class Op
	constructor: (@cpu, pc) ->
		if pc? then @frommem(pc)
		#if buf?
		#	@insn = insn = new Uint8Array(buf).subarray(pc, pc+8)
		#	t = new DataView(buf)
		#	shi = t.getUint32(pc, false)
		#	slo = t.getUint32(pc+4, false)
		#	
	frommem: (pc) ->
		insn = @cpu.mem.bytes.subarray(pc, pc+8)
		@s = pad(@cpu.mem.read32(pc).toString(2), 32) + pad(@cpu.mem.read32(pc + 4).toString(2), 32)
		
		@opcode = insn[0] & 0x3f
		@flags = Boolean(insn[0] & 0x80)
		
		op1t = (insn[0] & 0x40) >> 6 | (insn[1] >> 5) & 0b110
		op1c = insn[2] << 8 | insn[3]
		@op1 = new Operand(@cpu, op1t, op1c)
		
		op2t = (insn[1] >> 3) & 7
		op2c = insn[4] << 8 | insn[5]
		@op2 = new Operand(@cpu, op2t, op2c)
		
		op3t = insn[1] & 7
		op3c = insn[6] << 8 | insn[7]
		@op3 = new Operand(@cpu, op3t, op3c)
		
		@cc = @op1.cc ? @op2.cc ? @op3.cc ? F_AL
	tomem: (insn = new Uint8Array(8), o=0) ->
		insn[o+0] = (@flags << 7) | ((@op1.type & 1) << 6) | (@opcode & 0x3f)
		insn[o+1] = ((@op1.type >> 1) << 6) | (@op2.type << 3) | @op3.type
		insn[o+2] = @op1.raw >> 8
		insn[o+3] = @op1.raw & 0xff
		insn[o+4] = @op2.raw >> 8
		insn[o+5] = @op2.raw & 0xff
		insn[o+6] = @op3.raw >> 8
		insn[o+7] = @op3.raw & 0xff
		return insn
	fromstr: (insn) ->
		[_, op, flags, arg] = insn.match(/\s+([a-z]+?)(s)?(?:\s+(.*?)\s*)?(?:;.*)?$/)
		for k, v of ccs
			if op.endsWith(k) and k != "" and (tmp = op.substr(0, op.length - 2)) of @cpu.rop
				op = tmp
				@cc = v
		if not @cc? then @cc = F_AL
		@opcode = @cpu.rop[op]
		@flags = flags == "s"
		args = if arg? then arg.split(/,\s*/) else []
		#if args.length < @opcode.length then throw new Error "Not enough arguments"
		@op1 = if args[0] then Operand.fromstr(@cpu, args[0]) else new Operand(0, 0)
		@op2 = if args[1] then Operand.fromstr(@cpu, args[1]) else new Operand(0, 0)
		@op3 = if args[2] then Operand.fromstr(@cpu, args[2]) else new Operand(0, 0)
		if @cc != F_AL
			if @op1.type & TYPE_REGISTER then @op1.cc = @cc
			else if @op2.type & TYPE_REGISTER then @op2.cc = @cc
			else if @op3.type & TYPE_REGISTER then @op3.cc = @cc
			else
				console.log('couldn\'t set condition code')
				@cc = F_AL
	@fromstr: (cpu, insn) ->
		v = new @(cpu)
		v.fromstr(insn)
		return v
	@assemble: (cpu, str) ->
		a = str.split('\n')
		b = new Uint8Array(8 * a.length)
		for v, i in a
			Op.fromstr(cpu, v).tomem(b, 8 * i)
		return b
	@frombin: (bin) ->
		x = bin.match(/[01]+/g).join('')
		if x.length != 64 then return
		a = new Uint8Array(8)
		for i in [0...8]
			a[i] = parseInt(x.substr(i*8, 8), 2)
		return a
	exec: ->
		if @cpu.checkcc(@cc)
			v = @cpu.opcodes[@opcode].call(@cpu, @op1, @op2, @op3)
			if @flags then @cpu.updateflags(v)
			return v
	
	disas: ->
		o = @cpu.opcodes[@opcode]
		o._name + (if @flags then 's' else '') + cca[@cc] + ' ' + (if o.length > 0 then @op1 else '') + (if o.length > 1 then ', ' + @op2 else '') + (if o.length > 2 then ', ' + @op3 else '')
	toString: @::disas
	tobin: ->
		a = split(@s, [1, 1, 6, 2, 3, 3, 8, 8, 8, 8, 8, 8])
		v = [[0, if @flags then 'S' else ''], [4, 'O=' + @opcode.toString(16)], [11, 'x='+@op1.tn()], [16, 'y='+@op2.tn()], [21, 'z='+@op3.tn()], [26, @op1.bitfmt('X')], [44, @op2.bitfmt('Y')], [62, @op3.bitfmt('Z')]]
		
		console.log(place(v))
		return "#{a[0]} #{a[1]} #{a[2]} _#{a[3]}  #{a[4]}  #{a[5]}  #{a[6]}:#{a[7]} #{a[8]}:#{a[9]} #{a[10]}:#{a[11]}"
class CPU
	constructor: ->
		@mem = new Mem()
		@regs = new Uint32Array(32)
		@regs[R_SP] = 0x7DFC #0x7E00
		@mem.write32(@regs[R_SP], 0xffff)
		@mode = 1
		@syscall_returns = [0x8000]
		@user_stack = 0 # wraps around, I think
		@flags = {n: false, z: false, c: false, v: false}
	exec: ->
		pc = @regs[R_PC]
		
		@regs[R_PC] += 8
		
		op = new Op(@, pc)
		console.log(op.toString())
		console.log(op.tobin())
		op.exec()

	updateflags: (res) ->
		@flags.n = Boolean(res & 0x80000000)
		@flags.z = res == 0
		@flags.c = res > 0xffffffff
		@flags.v = res > 0x7fffffff
	checkcc: (cc) ->
		f = @flags
		switch cc
			when F_EQ then f.z
			when F_NE then not f.z
			when F_CS then f.c
			when F_CC then not f.c
			when F_MI then f.n
			when F_PL then not f.n
			when F_VS then f.v
			when F_VC then not f.c
			when F_HI then f.c and (not f.z)
			when F_LS then (not f.c) and f.z
			when F_GE then f.n == f.v
			when F_LT then f.n != f.v
			when F_GT then (not f.z) and f.n == f.v
			when F_LE then f.z or f.n != f.v
			when F_AL then true
		#true # :/
	push: (val) ->
		@mem.write32(@regs[R_SP] -= 4, val)
		return
	pop: ->
		v = @mem.read32(@regs[R_SP])
		@regs[R_SP] += 4
		return v
	opcodes:
		0x00: nf 'lsl', (op1, op2, op3) -> # lsl
			op1.val = op2.val << op3.val
		0x01: nf 'rsc', (op1, op2, op3) -> # rsc
			op1.val = ((op2.val & 0xffff) << 16) | (op3.val & 0xffff)
		0x02: nf 'mmv', (op1, op2, op3) -> # mmv
			#if not (op2.type & TYPE_MEMORY) then throw 'problem'
			v = if op2.type & TYPE_MEMORY then @op2.memread(op2.ptrval + op3.val) else op2.val
			if op1.type & TYPE_MEMORY
				@op1.memwrite(op1.ptrval + op3.val, v)
			else
				op1.val = v
		0x03: nf 'lsr', (op1, op2, op3) -> # lsr
			op1.val = op2.val >>> op3.val
		0x04: nf 'asr', (op1, op2, op3) -> # asr
			op1.val = op2.val >> op3.val
		0x05: nf 'add', (op1, op2, op3) -> # add
			op1.val = op2.val + op3.val
		0x06: nf 'sub', (op1, op2, op3) -> # sub
			op1.val = op2.val - op3.val
		0x07: nf 'push', (op1, op2, op3) -> # push
			if op1.readable then @push(op1.val)
			if op2.readable then @push(op2.val)
			if op3.readable then @push(op3.val)
			return
		0x08: nf 'pop', (op1, op2, op3) -> # pop
			if op1.writeable then op1.val = @pop()
			if op2.writeable then op2.val = @pop()
			if op3.writeable then op3.val = @pop()
			return
		0x09: nf 'and', (op1, op2, op3) -> # and
			op1.val = op2.val & op3.val
		0x0a: nf 'or', (op1, op2, op3) -> # or
			op1.val = op2.val | op3.val
		0x0b: nf 'xor', (op1, op2, op3) -> # xor
			op1.val = op2.val ^ op3.val
		0x0c: nf 'mul', (op1, op2, op3) ->
			op1.val = Math.imul(op2.val, op3.val)
		# control flow
		0x10: nf 'call', (op1) -> #, op2, op3) -> # call
			@push(@regs[R_PC])
			@regs[R_PC] = op1.val
			return
		0x11: nf 'rcall', (op1) -> #, op2, op3) ->
			@push(@regs[R_PC])
			@regs[R_PC] += op1.val
		0x1e: nf 'syscall', (op1) -> #, op2, op3) -> # syscall
			if @mode == 0
				@user_stack = @regs[R_SP]
				@regs[R_SP] = @system_stack
			@push(0xffff)
			@syscall_returns.push(@regs[R_PC])
			@mode++
			@regs[R_PC] = @mem.read16(0x7E00 | (op1.val << 1))
			return
		0x1f: nf 'ret', () -> #op1, op2, op3) -> # ret
			ra = @pop()
			if ra == 0xffff
				@mode--
				@regs[R_PC] = @syscall_returns.pop()
				if @mode == 0
					@system_stack = @regs[R_SP]
					@regs[R_SP] = @user_stack
				return
			@regs[R_PC] = @pop()
		0x3f: nf 'rst', () ->#op1, op2, op3) -> # reset
			throw 'something bad happened'
	rop: {}
	for k, v of @::opcodes
		k = Number(k)
		@::rop[v._name] = k
		v.opcode = k
	@::rop.mov = @::rop.add
	@::rop.ldr = @::rop.add