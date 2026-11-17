'use strict';
/**
 * 对象工具库 —— 修复原型污染后的安全版本
 *
 * 修复要点:
 *  1. 遍历时用 Object.keys 只取自有键,并拒绝 __proto__ / constructor / prototype;
 *  2. 递归合并前确认双方都是"普通对象"(原型为 Object.prototype 或 null),
 *     绝不递归进函数或内建对象;
 *  3. 路径解析后对每一段做黑名单校验,命中直接抛错;
 *  4. 需要新建对象承接拷贝时,键名经过同样校验,杜绝 __proto__ 赋值触发 setter。
 */

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function isSafeKey(key) {
  return typeof key === 'string' && !FORBIDDEN_KEYS.has(key);
}

function isObject(v) {
  return v !== null && (typeof v === 'object' || typeof v === 'function');
}

function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function assertSafeKey(key, fnName) {
  if (!isSafeKey(key)) {
    throw new TypeError(`${fnName}: 拒绝不安全的键名/路径段 "${key}"`);
  }
}

function parsePath(path) {
  if (Array.isArray(path)) return path.map(String);
  return String(path)
    .replace(/\[([^\]]+)\]/g, '.$1')
    .split('.')
    .filter((s) => s.length > 0);
}

/** 浅合并 */
function merge(target, ...sources) {
  for (const src of sources) {
    if (!isObject(src)) continue;
    for (const key of Object.keys(src)) {
      if (!isSafeKey(key)) continue;
      target[key] = src[key];
    }
  }
  return target;
}

/** 深合并 */
function deepMerge(target, source) {
  if (!isObject(source)) return target;
  for (const key of Object.keys(source)) {
    if (!isSafeKey(key)) continue;
    const sv = source[key];
    const tv = target[key];
    if (isPlainObject(sv) && isPlainObject(tv)) {
      deepMerge(tv, sv);
    } else if (Array.isArray(sv)) {
      target[key] = sv.slice();
    } else if (isPlainObject(sv)) {
      target[key] = deepMerge({}, sv);
    } else {
      target[key] = sv;
    }
  }
  return target;
}

/** 深拷贝(自有 __proto__ 键会被跳过,见文件头说明) */
function deepClone(obj) {
  if (!isObject(obj)) return obj;
  if (obj instanceof Date) return new Date(obj);
  if (obj instanceof RegExp) return new RegExp(obj);
  const out = Array.isArray(obj) ? [] : {};
  for (const key of Object.keys(obj)) {
    if (!isSafeKey(key)) continue;
    out[key] = deepClone(obj[key]);
  }
  return out;
}

/** 按路径赋值,非法路径段直接抛 TypeError */
function setPath(obj, path, value) {
  const segs = parsePath(path);
  if (segs.length === 0) return obj;
  let cur = obj;
  for (let i = 0; i < segs.length - 1; i++) {
    const k = segs[i];
    assertSafeKey(k, 'setPath');
    if (!isPlainObject(cur[k]) && !Array.isArray(cur[k])) {
      cur[k] = /^\d+$/.test(segs[i + 1]) ? [] : {};
    }
    cur = cur[k];
  }
  const last = segs[segs.length - 1];
  assertSafeKey(last, 'setPath');
  cur[last] = value;
  return obj;
}

/** 按路径读取(只读) */
function getPath(obj, path) {
  const segs = parsePath(path);
  let cur = obj;
  for (const k of segs) {
    if (cur == null) return undefined;
    cur = cur[k];
  }
  return cur;
}

/** 深层默认值填充 */
function defaultsDeep(target, ...sources) {
  for (const src of sources) {
    if (!isObject(src)) continue;
    for (const key of Object.keys(src)) {
      if (!isSafeKey(key)) continue;
      const sv = src[key];
      if (isPlainObject(sv) && isPlainObject(target[key])) {
        defaultsDeep(target[key], sv);
      } else if (target[key] === undefined) {
        target[key] = sv;
      }
    }
  }
  return target;
}

module.exports = {
  merge,
  deepMerge,
  deepClone,
  setPath,
  getPath,
  defaultsDeep,
  isObject,
  isPlainObject,
};
