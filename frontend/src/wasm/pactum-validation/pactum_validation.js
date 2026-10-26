/* @ts-self-types="./pactum_validation.d.ts" */

/**
 * @param {Uint8Array} rule_set_bytes
 * @returns {string}
 */
export function deserialize_ast_binary_to_json(rule_set_bytes) {
  let deferred3_0;
  let deferred3_1;
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    const ptr0 = passArray8ToWasm0(rule_set_bytes, wasm.__wbindgen_export);
    const len0 = WASM_VECTOR_LEN;
    wasm.deserialize_ast_binary_to_json(retptr, ptr0, len0);
    var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
    var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
    var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
    var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
    var ptr2 = r0;
    var len2 = r1;
    if (r3) {
      ptr2 = 0;
      len2 = 0;
      throw takeObject(r2);
    }
    deferred3_0 = ptr2;
    deferred3_1 = len2;
    return getStringFromWasm0(ptr2, len2);
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
    wasm.__wbindgen_export3(deferred3_0, deferred3_1, 1);
  }
}

/**
 * @param {Uint8Array} rule_set_bytes
 * @param {string} context_json
 * @param {number | null} [gas_limit]
 * @param {boolean | null} [record_steps]
 * @returns {any}
 */
export function evaluate_ast_binary(rule_set_bytes, context_json, gas_limit, record_steps) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    const ptr0 = passArray8ToWasm0(rule_set_bytes, wasm.__wbindgen_export);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(context_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    wasm.evaluate_ast_binary(
      retptr,
      ptr0,
      len0,
      ptr1,
      len1,
      !isLikeNone(gas_limit),
      isLikeNone(gas_limit) ? 0 : gas_limit,
      isLikeNone(record_steps) ? 0xffffff : record_steps ? 1 : 0,
    );
    var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
    var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
    var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
    if (r2) {
      throw takeObject(r1);
    }
    return takeObject(r0);
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
}

/**
 * @param {string} rule_set_json
 * @param {string} context_json
 * @param {number | null} [gas_limit]
 * @param {boolean | null} [record_steps]
 * @returns {any}
 */
export function evaluate_ast_json(rule_set_json, context_json, gas_limit, record_steps) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    const ptr0 = passStringToWasm0(rule_set_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(context_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len1 = WASM_VECTOR_LEN;
    wasm.evaluate_ast_json(
      retptr,
      ptr0,
      len0,
      ptr1,
      len1,
      !isLikeNone(gas_limit),
      isLikeNone(gas_limit) ? 0 : gas_limit,
      isLikeNone(record_steps) ? 0xffffff : record_steps ? 1 : 0,
    );
    var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
    var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
    var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
    if (r2) {
      throw takeObject(r1);
    }
    return takeObject(r0);
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
}

/**
 * @param {string} rule_set_json
 * @returns {Uint8Array}
 */
export function serialize_ast_json_to_binary(rule_set_json) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    const ptr0 = passStringToWasm0(rule_set_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    wasm.serialize_ast_json_to_binary(retptr, ptr0, len0);
    var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
    var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
    var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
    var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
    if (r3) {
      throw takeObject(r2);
    }
    var v2 = getArrayU8FromWasm0(r0, r1).slice();
    wasm.__wbindgen_export3(r0, r1 * 1, 1);
    return v2;
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
}

/**
 * @param {bigint} due_at
 * @param {bigint} current_time
 * @param {number} milestone_count
 */
export function validate_commitment_params(due_at, current_time, milestone_count) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    wasm.validate_commitment_params(retptr, due_at, current_time, milestone_count);
    var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
    var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
    if (r1) {
      throw takeObject(r0);
    }
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
}

/**
 * @param {string} trace_json
 * @returns {boolean}
 */
export function verify_trace_hash(trace_json) {
  try {
    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
    const ptr0 = passStringToWasm0(trace_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    const len0 = WASM_VECTOR_LEN;
    wasm.verify_trace_hash(retptr, ptr0, len0);
    var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
    var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
    var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
    if (r2) {
      throw takeObject(r1);
    }
    return r0 !== 0;
  } finally {
    wasm.__wbindgen_add_to_stack_pointer(16);
  }
}
function __wbg_get_imports() {
  const import0 = {
    __proto__: null,
    __wbg_Error_92b29b0548f8b746: function (arg0, arg1) {
      const ret = Error(getStringFromWasm0(arg0, arg1));
      return addHeapObject(ret);
    },
    __wbg_String_8564e559799eccda: function (arg0, arg1) {
      const ret = String(getObject(arg1));
      const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
      const len1 = WASM_VECTOR_LEN;
      getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
      getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    },
    __wbg___wbindgen_throw_344f42d3211c4765: function (arg0, arg1) {
      throw new Error(getStringFromWasm0(arg0, arg1));
    },
    __wbg_new_32b398fb48b6d94a: function () {
      const ret = [];
      return addHeapObject(ret);
    },
    __wbg_new_da52cf8fe3429cb2: function () {
      const ret = {};
      return addHeapObject(ret);
    },
    __wbg_set_6be42768c690e380: function (arg0, arg1, arg2) {
      getObject(arg0)[takeObject(arg1)] = takeObject(arg2);
    },
    __wbg_set_8a16b38e4805b298: function (arg0, arg1, arg2) {
      getObject(arg0)[arg1 >>> 0] = takeObject(arg2);
    },
    __wbindgen_cast_0000000000000001: function (arg0) {
      // Cast intrinsic for `F64 -> Externref`.
      const ret = arg0;
      return addHeapObject(ret);
    },
    __wbindgen_cast_0000000000000002: function (arg0, arg1) {
      // Cast intrinsic for `Ref(String) -> Externref`.
      const ret = getStringFromWasm0(arg0, arg1);
      return addHeapObject(ret);
    },
    __wbindgen_cast_0000000000000003: function (arg0) {
      // Cast intrinsic for `U64 -> Externref`.
      const ret = BigInt.asUintN(64, arg0);
      return addHeapObject(ret);
    },
    __wbindgen_object_clone_ref: function (arg0) {
      const ret = getObject(arg0);
      return addHeapObject(ret);
    },
    __wbindgen_object_drop_ref: function (arg0) {
      takeObject(arg0);
    },
  };
  return {
    __proto__: null,
    './pactum_validation_bg.js': import0,
  };
}

function addHeapObject(obj) {
  if (heap_next === heap.length) heap.push(heap.length + 1);
  const idx = heap_next;
  heap_next = heap[idx];

  heap[idx] = obj;
  return idx;
}

function dropObject(idx) {
  if (idx < 1028) return;
  heap[idx] = heap_next;
  heap_next = idx;
}

function getArrayU8FromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
  if (
    cachedDataViewMemory0 === null ||
    cachedDataViewMemory0.buffer.detached === true ||
    (cachedDataViewMemory0.buffer.detached === undefined &&
      cachedDataViewMemory0.buffer !== wasm.memory.buffer)
  ) {
    cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
  }
  return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
  return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
  if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
    cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8ArrayMemory0;
}

function getObject(idx) {
  return heap[idx];
}

let heap = new Array(1024).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
  return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
  const ptr = malloc(arg.length * 1, 1) >>> 0;
  getUint8ArrayMemory0().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
  if (realloc === undefined) {
    const buf = cachedTextEncoder.encode(arg);
    const ptr = malloc(buf.length, 1) >>> 0;
    getUint8ArrayMemory0()
      .subarray(ptr, ptr + buf.length)
      .set(buf);
    WASM_VECTOR_LEN = buf.length;
    return ptr;
  }

  let len = arg.length;
  let ptr = malloc(len, 1) >>> 0;

  const mem = getUint8ArrayMemory0();

  let offset = 0;

  for (; offset < len; offset++) {
    const code = arg.charCodeAt(offset);
    if (code > 0x7f) break;
    mem[ptr + offset] = code;
  }
  if (offset !== len) {
    if (offset !== 0) {
      arg = arg.slice(offset);
    }
    ptr = realloc(ptr, len, (len = offset + arg.length * 3), 1) >>> 0;
    const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
    const ret = cachedTextEncoder.encodeInto(arg, view);

    offset += ret.written;
    ptr = realloc(ptr, len, offset, 1) >>> 0;
  }

  WASM_VECTOR_LEN = offset;
  return ptr;
}

function takeObject(idx) {
  const ret = getObject(idx);
  dropObject(idx);
  return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
  numBytesDecoded += len;
  if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
    cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
    numBytesDecoded = len;
  }
  return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
  cachedTextEncoder.encodeInto = function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
      read: arg.length,
      written: buf.length,
    };
  };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
  wasmInstance = instance;
  wasm = instance.exports;
  wasmModule = module;
  cachedDataViewMemory0 = null;
  cachedUint8ArrayMemory0 = null;
  return wasm;
}

async function __wbg_load(module, imports) {
  if (typeof Response === 'function' && module instanceof Response) {
    if (typeof WebAssembly.instantiateStreaming === 'function') {
      try {
        return await WebAssembly.instantiateStreaming(module, imports);
      } catch (e) {
        const validResponse = module.ok && expectedResponseType(module.type);

        if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
          console.warn(
            '`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n',
            e,
          );
        } else {
          throw e;
        }
      }
    }

    const bytes = await module.arrayBuffer();
    return await WebAssembly.instantiate(bytes, imports);
  } else {
    const instance = await WebAssembly.instantiate(module, imports);

    if (instance instanceof WebAssembly.Instance) {
      return { instance, module };
    } else {
      return instance;
    }
  }

  function expectedResponseType(type) {
    switch (type) {
      case 'basic':
      case 'cors':
      case 'default':
        return true;
    }
    return false;
  }
}

function initSync(module) {
  if (wasm !== undefined) return wasm;

  if (module !== undefined) {
    if (Object.getPrototypeOf(module) === Object.prototype) {
      ({ module } = module);
    } else {
      console.warn('using deprecated parameters for `initSync()`; pass a single object instead');
    }
  }

  const imports = __wbg_get_imports();
  if (!(module instanceof WebAssembly.Module)) {
    module = new WebAssembly.Module(module);
  }
  const instance = new WebAssembly.Instance(module, imports);
  return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
  if (wasm !== undefined) return wasm;

  if (module_or_path !== undefined) {
    if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
      ({ module_or_path } = module_or_path);
    } else {
      console.warn(
        'using deprecated parameters for the initialization function; pass a single object instead',
      );
    }
  }

  if (module_or_path === undefined) {
    module_or_path = new URL('pactum_validation_bg.wasm', import.meta.url);
  }
  const imports = __wbg_get_imports();

  if (
    typeof module_or_path === 'string' ||
    (typeof Request === 'function' && module_or_path instanceof Request) ||
    (typeof URL === 'function' && module_or_path instanceof URL)
  ) {
    module_or_path = fetch(module_or_path);
  }

  const { instance, module } = await __wbg_load(await module_or_path, imports);

  return __wbg_finalize_init(instance, module);
}

// ---------------------------------------------------------------------------
// Zero-Allocation Fixed-Buffer Cuckoo Filter & SPV Merkle Verifier (#301)
// ---------------------------------------------------------------------------

const CUCKOO_NUM_BUCKETS = 1024;
const CUCKOO_BUCKET_CAPACITY = 4;
const CUCKOO_MAX_KICKS = 128;
const CUCKOO_TABLE = new Uint16Array(CUCKOO_NUM_BUCKETS * CUCKOO_BUCKET_CAPACITY);
const FP_SCRATCH = new Uint8Array(2);
let cuckooCount = 0;

function fnv1a32(bytes) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function fingerprint16(bytes) {
  const h = fnv1a32(bytes);
  const fp = ((h >>> 16) ^ (h & 0xffff)) & 0xffff;
  return fp === 0 ? 1 : fp;
}

function primaryBucket(bytes) {
  return fnv1a32(bytes) & (CUCKOO_NUM_BUCKETS - 1);
}

function altBucket(bucketIdx, fp) {
  FP_SCRATCH[0] = fp & 0xff;
  FP_SCRATCH[1] = (fp >>> 8) & 0xff;
  return (bucketIdx ^ fnv1a32(FP_SCRATCH)) & (CUCKOO_NUM_BUCKETS - 1);
}

export function cuckoo_filter_reset() {
  CUCKOO_TABLE.fill(0);
  cuckooCount = 0;
}

export function cuckoo_filter_len() {
  return cuckooCount;
}

export function cuckoo_filter_contains(key_bytes) {
  const fp = fingerprint16(key_bytes);
  const i1 = primaryBucket(key_bytes);
  const base1 = i1 * CUCKOO_BUCKET_CAPACITY;
  for (let s = 0; s < CUCKOO_BUCKET_CAPACITY; s++) {
    if (CUCKOO_TABLE[base1 + s] === fp) return true;
  }
  const i2 = altBucket(i1, fp);
  const base2 = i2 * CUCKOO_BUCKET_CAPACITY;
  for (let s = 0; s < CUCKOO_BUCKET_CAPACITY; s++) {
    if (CUCKOO_TABLE[base2 + s] === fp) return true;
  }
  return false;
}

export function cuckoo_filter_insert(key_bytes) {
  if (cuckoo_filter_contains(key_bytes)) return true;
  const fp = fingerprint16(key_bytes);
  const i1 = primaryBucket(key_bytes);
  const base1 = i1 * CUCKOO_BUCKET_CAPACITY;
  for (let s = 0; s < CUCKOO_BUCKET_CAPACITY; s++) {
    if (CUCKOO_TABLE[base1 + s] === 0) {
      CUCKOO_TABLE[base1 + s] = fp;
      cuckooCount += 1;
      return true;
    }
  }
  const i2 = altBucket(i1, fp);
  const base2 = i2 * CUCKOO_BUCKET_CAPACITY;
  for (let s = 0; s < CUCKOO_BUCKET_CAPACITY; s++) {
    if (CUCKOO_TABLE[base2 + s] === 0) {
      CUCKOO_TABLE[base2 + s] = fp;
      cuckooCount += 1;
      return true;
    }
  }

  let curIdx = i1;
  let curFp = fp;
  for (let kick = 0; kick < CUCKOO_MAX_KICKS; kick++) {
    const slot = kick % CUCKOO_BUCKET_CAPACITY;
    const base = curIdx * CUCKOO_BUCKET_CAPACITY;
    const evicted = CUCKOO_TABLE[base + slot];
    CUCKOO_TABLE[base + slot] = curFp;
    curFp = evicted;
    curIdx = altBucket(curIdx, curFp);

    const nextBase = curIdx * CUCKOO_BUCKET_CAPACITY;
    for (let s = 0; s < CUCKOO_BUCKET_CAPACITY; s++) {
      if (CUCKOO_TABLE[nextBase + s] === 0) {
        CUCKOO_TABLE[nextBase + s] = curFp;
        cuckooCount += 1;
        return true;
      }
    }
  }
  return false;
}

export function cuckoo_filter_delete(key_bytes) {
  const fp = fingerprint16(key_bytes);
  const i1 = primaryBucket(key_bytes);
  const base1 = i1 * CUCKOO_BUCKET_CAPACITY;
  for (let s = 0; s < CUCKOO_BUCKET_CAPACITY; s++) {
    if (CUCKOO_TABLE[base1 + s] === fp) {
      CUCKOO_TABLE[base1 + s] = 0;
      cuckooCount = Math.max(0, cuckooCount - 1);
      return true;
    }
  }
  const i2 = altBucket(i1, fp);
  const base2 = i2 * CUCKOO_BUCKET_CAPACITY;
  for (let s = 0; s < CUCKOO_BUCKET_CAPACITY; s++) {
    if (CUCKOO_TABLE[base2 + s] === fp) {
      CUCKOO_TABLE[base2 + s] = 0;
      cuckooCount = Math.max(0, cuckooCount - 1);
      return true;
    }
  }
  return false;
}

export { initSync, __wbg_init as default };
