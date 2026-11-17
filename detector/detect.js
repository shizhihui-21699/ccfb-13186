#!/usr/bin/env node
'use strict';
/**
 * 原型污染检测器
 *
 * 原理:
 *  1. 在独立的 vm 上下文中加载被测工具库,自动枚举其导出的函数;
 *  2. 根据函数签名(参数名含 path/key/prop 等 → 路径类,其余 → 对象类)选择攻击策略;
 *  3. 每个测试用例都在一个全新的 vm realm 中执行 —— 该 realm 有自己的
 *     Object.prototype,污染不会外溢到宿主进程,也不会在用例间串扰;
 *  4. 调用后检查两件事:
 *     a. 全局原型污染: 该 realm 的 Object.prototype / Function.prototype 上是否出现标记键;
 *     b. 返回对象原型注入: 返回值的原型是否被替换成带标记键的对象;
 *  5. 对命中的载荷做贪心最小化(删键 / 取子树),给出最小复现输入;
 *  6. 按污染向量生成修复建议,结果写入 report/results.js 供 Lit 结果页渲染。
 *
 * 用法:
 *   node detector/detect.js vulnerable=lib/object-utils.vulnerable.js \
 *                           safe=lib/object-utils.safe.js \
 *                           [-o report/results.js]
 *
 * 退出码: 任一被测库存在"全局原型污染"发现时为 1,否则为 0(可直接接 CI)。
 */

const vm = require('vm');
const fs = require('fs');
const path = require('path');

const MARKER = 'ppMarker7f3a'; // 标记键:出现在原型上即判定污染
const MARKER_JSON = JSON.stringify(MARKER);

// ---------- 攻击载荷 ----------

// 对象类载荷(JSON 字符串;必须用 JSON.parse 构造才能得到自有的 __proto__ 键)
const OBJECT_PAYLOADS = [
  `{"__proto__":{"${MARKER}":1}}`,
  `{"constructor":{"prototype":{"${MARKER}":1}}}`,
  `{"a":{"__proto__":{"${MARKER}":1}}}`,
  `{"__proto__":{"a":{"${MARKER}":1}}}`,
  `{"a":{"b":{"constructor":{"prototype":{"${MARKER}":1}}}}}`,
  `[{"__proto__":{"${MARKER}":1}}]`,
];

// 路径类载荷(按长度升序,首个命中即天然最小)
const PATH_PAYLOADS = [
  `__proto__.${MARKER}`,
  `constructor.prototype.${MARKER}`,
  `a.__proto__.${MARKER}`,
  `a.b.constructor.prototype.${MARKER}`,
];

// 参数模板: P=载荷对象 E={} PATH=路径字符串 PATHARR=路径数组 V=写入值
const OBJECT_ARG_TEMPLATES = [['P'], ['E', 'P'], ['P', 'E'], ['E', 'E', 'P']];
const PATH_ARG_TEMPLATES = [['E', 'PATH', 'V'], ['E', 'PATHARR', 'V']];

// ---------- 沙箱加载 ----------

function loadLib(ctx, code) {
  const factory = vm.runInContext(
    `(function (module, exports, require) {\n${code}\n})`,
    ctx,
    { filename: 'target-lib.js', timeout: 2000 }
  );
  const module = { exports: {} };
  factory(module, module.exports, () => {
    throw new Error('require() 在沙箱中被禁用');
  });
  return module.exports;
}

// ---------- 单次用例执行 ----------

/**
 * 在全新 vm realm 中执行一次调用。
 * tokens: 参数模板; payload: 对象载荷 JSON 字符串或路径字符串。
 */
function runCase(libCode, fnName, tokens, payload) {
  const ctx = vm.createContext(Object.create(null));
  let exports;
  try {
    exports = loadLib(ctx, libCode);
  } catch (e) {
    return { error: String(e) };
  }
  const fn = exports[fnName];
  if (typeof fn !== 'function') return null;

  // 参数在沙箱内构造,保证对象属于被测 realm(尤其是 JSON.parse 出的 __proto__ 自有键)
  const argExprs = tokens
    .map((t) => {
      switch (t) {
        case 'P': return `JSON.parse(${JSON.stringify(payload)})`;
        case 'E': return '({})';
        case 'PATH': return JSON.stringify(payload);
        case 'PATHARR': return `JSON.parse(${JSON.stringify(JSON.stringify(payload.split('.')))})`;
        case 'V': return '1';
        default: return 'undefined';
      }
    })
    .join(',');
  const args = vm.runInContext(`[${argExprs}]`, ctx, { timeout: 2000 });

  let result;
  let threw = null;
  try {
    result = fn.apply(null, args);
  } catch (e) {
    threw = (e && e.message) || String(e);
  }

  // a. 全局原型污染检查(在该 realm 内)
  const globalPolluted = vm.runInContext(
    `typeof Object.prototype[${MARKER_JSON}] !== 'undefined' || ` +
    `typeof Function.prototype[${MARKER_JSON}] !== 'undefined'`,
    ctx
  );

  // b. 返回对象原型注入检查(宿主侧,跨 realm 读取是安全的)
  let protoInjected = false;
  if (!globalPolluted && result && (typeof result === 'object' || typeof result === 'function')) {
    try {
      const proto = Object.getPrototypeOf(result);
      protoInjected =
        !Object.prototype.hasOwnProperty.call(result, MARKER) &&
        result[MARKER] !== undefined &&
        proto !== null &&
        Object.prototype.hasOwnProperty.call(proto, MARKER);
    } catch { /* 忽略代理等异常 */ }
  }

  return { globalPolluted, protoInjected, threw };
}

// ---------- 载荷最小化 ----------

// 用 defineProperty 保证 __proto__ 被定义为自有数据属性而非触发 setter
function setOwn(obj, k, v) {
  Object.defineProperty(obj, k, { value: v, enumerable: true, configurable: true, writable: true });
  return obj;
}

// 生成一个载荷的所有"更小"变体: 子树 / 删键 / 子位置的更小变体
function* payloadVariants(node) {
  if (!node || typeof node !== 'object') return;
  for (const k of Object.keys(node)) {
    yield node[k]; // 子树
    if (Array.isArray(node)) {
      const c = node.slice();
      c.splice(Number(k), 1);
      yield c;
    } else {
      const c = {};
      for (const k2 of Object.keys(node)) if (k2 !== k) setOwn(c, k2, node[k2]);
      yield c;
    }
    for (const sub of payloadVariants(node[k])) {
      if (Array.isArray(node)) {
        const c = node.slice();
        c[Number(k)] = sub;
        yield c;
      } else {
        const c = {};
        for (const k2 of Object.keys(node)) setOwn(c, k2, k2 === k ? sub : node[k2]);
        yield c;
      }
    }
  }
}

/** 贪心收缩:反复尝试更小的变体,直到任何变体都不再触发污染 */
function shrinkPayload(libCode, fnName, tokens, payloadStr) {
  let best = payloadStr;
  const seen = new Set([payloadStr]);
  let frontier = [JSON.parse(payloadStr)];
  let improved = true;
  while (improved) {
    improved = false;
    const cands = [];
    for (const node of frontier) {
      for (const v of payloadVariants(node)) {
        const s = JSON.stringify(v);
        if (s && s.length < best.length && !seen.has(s)) {
          seen.add(s);
          cands.push(s);
        }
      }
    }
    cands.sort((a, b) => a.length - b.length);
    for (const s of cands) {
      const r = runCase(libCode, fnName, tokens, s);
      if (r && (r.globalPolluted || r.protoInjected)) {
        best = s;
        frontier = [JSON.parse(s)];
        improved = true;
        break;
      }
    }
  }
  return best;
}

// ---------- 函数签名分析 ----------

function paramNames(fn) {
  const src = Function.prototype.toString.call(fn).replace(/\/\*[\s\S]*?\*\//g, '').trim();
  let m = src.match(/^[^(]*\(([^)]*)\)/);
  let list;
  if (m) {
    list = m[1];
  } else {
    m = src.match(/^(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>/);
    list = m ? m[1] : '';
  }
  return list
    .split(',')
    .map((s) => s.replace(/=.*$/, '').trim().replace(/^\.\.\./, ''))
    .filter(Boolean);
}

// ---------- 复现与修复建议 ----------

function buildRepro(fnName, tokens, payload) {
  const args = tokens
    .map((t) => {
      switch (t) {
        case 'P': return `JSON.parse('${payload}')`;
        case 'E': return '{}';
        case 'PATH': return JSON.stringify(payload);
        case 'PATHARR': return `${JSON.stringify(payload)}.split('.')`;
        case 'V': return "'polluted'";
        default: return 'undefined';
      }
    })
    .join(', ');
  return `${fnName}(${args})`;
}

function classifyVector(payload) {
  if (payload.includes('__proto__')) return '__proto__';
  if (payload.includes('constructor')) return 'constructor.prototype';
  return 'other';
}

function fixesFor(finding) {
  const fixes = [];
  if (finding.vector === '__proto__') {
    fixes.push('遍历来源对象时改用 Object.keys 只取自有键,并显式跳过 __proto__;或对赋值改用 Object.defineProperty,避免触发原型 setter。');
  }
  if (finding.vector === 'constructor.prototype') {
    fixes.push('把 constructor / prototype 列入键名黑名单;递归合并前确认目标是普通对象(Object.getPrototypeOf 为 Object.prototype 或 null),不要递归进函数。');
  }
  if (finding.strategy === 'path') {
    fixes.push('对路径解析出的每一段做黑名单校验(__proto__、constructor、prototype 直接抛 TypeError),可参考 lodash >= 4.17.12 中 _.set 的修复方式。');
  }
  if (finding.pollutionType === 'returned-object-proto') {
    fixes.push('创建承接拷贝的对象时使用 Object.create(null),或为 __proto__ 键使用 Object.defineProperty 定义普通数据属性,避免调用方拿到原型被篡改的对象。');
  }
  fixes.push('可直接替换为检测通过的安全版本 lib/object-utils.safe.js。');
  return fixes;
}

// ---------- 主检测流程 ----------

function detectLib(label, file) {
  const libCode = fs.readFileSync(file, 'utf8');

  // 自动发现:枚举模块导出的全部函数
  const ctx = vm.createContext(Object.create(null));
  const exports = loadLib(ctx, libCode);
  const fnNames = Object.keys(exports).filter((k) => typeof exports[k] === 'function');

  const functions = fnNames.map((name) => {
    const fn = exports[name];
    const params = paramNames(fn);
    const strategies = ['object'];
    if (params.some((p) => /path|key|prop|attr|field/i.test(p))) strategies.push('path');

    const findings = [];
    let tested = 0;

    for (const strategy of strategies) {
      const templates = strategy === 'object' ? OBJECT_ARG_TEMPLATES : PATH_ARG_TEMPLATES;
      const payloads = strategy === 'object' ? OBJECT_PAYLOADS : PATH_PAYLOADS;
      const seenMinimal = new Set();

      for (const tokens of templates) {
        for (const payload of payloads) {
          tested++;
          const r = runCase(libCode, name, tokens, payload);
          if (!r || (!r.globalPolluted && !r.protoInjected)) continue;

          const minimal = strategy === 'object' ? shrinkPayload(libCode, name, tokens, payload) : payload;
          if (seenMinimal.has(minimal)) continue;
          seenMinimal.add(minimal);

          const pollutionType = r.globalPolluted ? 'global-prototype' : 'returned-object-proto';
          const finding = {
            strategy,
            vector: classifyVector(minimal),
            pollutionType,
            severity: r.globalPolluted ? 'high' : 'medium',
            payload: minimal,
            repro: buildRepro(name, tokens, minimal),
          };
          finding.fixes = fixesFor(finding);
          findings.push(finding);
        }
      }
    }

    return { name, params, arity: fn.length, tested, findings };
  });

  return { label, file: path.relative(process.cwd(), file), functions };
}

// ---------- CLI ----------

function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes('--help')) {
    console.log('用法: node detector/detect.js <label>=<lib路径> [...] [-o report/results.js]');
    process.exit(argv.length === 0 ? 1 : 0);
  }

  let out = 'report/results.js';
  const targets = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '-o') out = argv[++i];
    else {
      const eq = argv[i].indexOf('=');
      if (eq <= 0) {
        console.error(`无法解析参数: ${argv[i]}(应为 label=path)`);
        process.exit(1);
      }
      targets.push({ label: argv[i].slice(0, eq), file: path.resolve(argv[i].slice(eq + 1)) });
    }
  }

  const report = {
    tool: 'prototype-pollution-detector',
    generatedAt: new Date().toISOString(),
    node: process.version,
    marker: MARKER,
    libs: [],
  };

  let anyHigh = false;
  for (const t of targets) {
    const result = detectLib(t.label, t.file);
    report.libs.push(result);

    const totalFindings = result.functions.reduce((n, f) => n + f.findings.length, 0);
    const high = result.functions.reduce(
      (n, f) => n + f.findings.filter((x) => x.severity === 'high').length, 0
    );
    if (high > 0) anyHigh = true;
    console.log(
      `[${result.label}] ${result.file}: 发现 ${result.functions.length} 个导出函数, ` +
      `${totalFindings} 项发现(高危 ${high})`
    );
    for (const f of result.functions) {
      for (const x of f.findings) {
        console.log(`  - ${f.name}: ${x.pollutionType} via ${x.vector}  repro: ${x.repro}`);
      }
    }
  }

  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `window.__PP_RESULTS__ = ${JSON.stringify(report, null, 2)};\n`);
  console.log(`报告已写入 ${out}`);

  process.exitCode = anyHigh ? 1 : 0;
}

main();
