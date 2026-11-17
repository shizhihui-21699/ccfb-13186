'use strict';
/**
 * 对象工具库 —— 存在原型污染漏洞的版本
 * 仅用于检测器的演示与验证,请勿在生产环境使用。
 */

function isObject(v) {
  return v !== null && (typeof v === 'object' || typeof v === 'function');
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function parsePath(path) {
  if (Array.isArray(path)) return path.map(String);
  return String(path)
    .replace(/\[([^\]]+)\]/g, '.$1')
    .split('.')
    .filter((s) => s.length > 0);
}

/** 浅合并:把 sources 的键逐一拷到 target */
function merge(target, ...sources) {
  for (const src of sources) {
    if (!isObject(src)) continue;
    // 漏洞点 1: for...in 会枚举到 JSON.parse 产生的自有 __proto__ 键,
    //           target['__proto__'] = x 触发原型 setter,改写了返回对象的原型
    for (const key in src) {
      target[key] = src[key];
    }
  }
  return target;
}

/** 深合并 */
function deepMerge(target, source) {
  if (!isObject(source)) return target;
  for (const key in source) {
    const sv = source[key];
    const tv = target[key];
    // 漏洞点 2: key 为 __proto__ 时 tv 即 Object.prototype,递归直接污染全局原型;
    //           key 为 constructor 时 tv 是构造函数(被 isObject 判定通过),
    //           再下一层 prototype 即 Object.prototype —— constructor.prototype 链污染
    if (isObject(sv) && isObject(tv)) {
      deepMerge(tv, sv);
    } else if (isObject(sv)) {
      target[key] = deepMerge(Array.isArray(sv) ? [] : {}, sv);
    } else {
      target[key] = sv;
    }
  }
  return target;
}

/** 深拷贝 */
function deepClone(obj) {
  if (!isObject(obj)) return obj;
  if (obj instanceof Date) return new Date(obj);
  if (obj instanceof RegExp) return new RegExp(obj);
  const out = Array.isArray(obj) ? [] : {};
  // 漏洞点 3: out['__proto__'] = ... 把克隆结果的原型替换成攻击者控制的对象
  for (const key in obj) {
    out[key] = deepClone(obj[key]);
  }
  return out;
}

/** 按路径赋值,路径支持 a.b.c 与 a[0].b 形式 */
function setPath(obj, path, value) {
  const segs = parsePath(path);
  let cur = obj;
  for (let i = 0; i < segs.length - 1; i++) {
    const k = segs[i];
    // 漏洞点 4: 路径段未校验,__proto__ / constructor.prototype 可一路走进 Object.prototype
    if (!isObject(cur[k])) cur[k] = {};
    cur = cur[k];
  }
  cur[segs[segs.length - 1]] = value;
  return obj;
}

/** 按路径读取(只读,安全) */
function getPath(obj, path) {
  const segs = parsePath(path);
  let cur = obj;
  for (const k of segs) {
    if (cur == null) return undefined;
    cur = cur[k];
  }
  return cur;
}

/** 深层默认值填充:target 缺少的键用 sources 补齐 */
function defaultsDeep(target, ...sources) {
  for (const src of sources) {
    if (!isObject(src)) continue;
    for (const key in src) {
      const sv = src[key];
      // 漏洞点 5: 与 deepMerge 相同,__proto__ 会递归进 Object.prototype
      if (isObject(sv) && isObject(target[key])) {
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
  // 内部辅助也导出,检测器应把它们一并枚举出来
  isObject,
  isPlainObject,
};
